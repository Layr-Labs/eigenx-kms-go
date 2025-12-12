package badger

import (
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	badgerdb "github.com/dgraph-io/badger/v3"
	"go.uber.org/zap"
)

// Key prefixes for namespacing
const (
	keyPrefixKeyShare      = "keyshare:"
	keyPrefixActiveVersion = "active:version"
	keyPrefixNodeState     = "nodestate:main"
	keyPrefixSession       = "session:"
	keySchemaVersion       = "metadata:schema_version"
	currentSchemaVersion   = "v1"
)

// BadgerPersistence is a production-ready persistence implementation using Badger.
// Provides durable, disk-based storage with ACID guarantees.
type BadgerPersistence struct {
	db       *badgerdb.DB
	logger   *zap.Logger
	gcCancel context.CancelFunc
	gcWg     sync.WaitGroup
	mu       sync.RWMutex
	closed   bool
}

// NewBadgerPersistence creates a new Badger-backed persistence layer.
// The database is opened at the specified path with SyncWrites enabled for durability.
// A background goroutine is started for garbage collection.
func NewBadgerPersistence(dataPath string, logger *zap.Logger) (*BadgerPersistence, error) {
	// Convert to absolute path
	absPath, err := filepath.Abs(dataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	// Configure Badger for production use
	opts := badgerdb.DefaultOptions(absPath)
	opts.Logger = &badgerLoggerAdapter{logger: logger}
	opts.SyncWrites = true // Ensure durability (fsync on every write)
	opts.CompactL0OnClose = true
	opts.NumVersionsToKeep = 1 // We don't need versioning within Badger

	// Open database
	db, err := badgerdb.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open badger database at %s: %w", absPath, err)
	}

	bp := &BadgerPersistence{
		db:     db,
		logger: logger,
	}

	// Initialize schema version
	if err := bp.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Start background GC
	ctx, cancel := context.WithCancel(context.Background())
	bp.gcCancel = cancel
	bp.gcWg.Add(1)
	go bp.runGC(ctx)

	logger.Sugar().Infow("Badger persistence initialized", "path", absPath)

	return bp, nil
}

// initSchema initializes or validates the schema version
func (b *BadgerPersistence) initSchema() error {
	return b.db.Update(func(txn *badgerdb.Txn) error {
		item, err := txn.Get([]byte(keySchemaVersion))
		if err == badgerdb.ErrKeyNotFound {
			// First time setup - set schema version
			return txn.Set([]byte(keySchemaVersion), []byte(currentSchemaVersion))
		}
		if err != nil {
			return fmt.Errorf("failed to read schema version: %w", err)
		}

		// Validate existing schema version
		var existingVersion string
		err = item.Value(func(val []byte) error {
			existingVersion = string(val)
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to read schema version value: %w", err)
		}

		if existingVersion != currentSchemaVersion {
			return fmt.Errorf("unsupported schema version: %s (expected: %s)", existingVersion, currentSchemaVersion)
		}

		return nil
	})
}

// runGC runs periodic garbage collection in the background
func (b *BadgerPersistence) runGC(ctx context.Context) {
	defer b.gcWg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Run value log GC with 0.5 discard ratio
			err := b.db.RunValueLogGC(0.5)
			if err != nil && err != badgerdb.ErrNoRewrite {
				b.logger.Sugar().Warnw("Badger GC error", "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// SaveKeyShareVersion persists a key share version
func (b *BadgerPersistence) SaveKeyShareVersion(version *types.KeyShareVersion) error {
	if version == nil {
		return fmt.Errorf("cannot save nil KeyShareVersion")
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	// Serialize to JSON
	data, err := persistence.MarshalKeyShareVersion(version)
	if err != nil {
		return fmt.Errorf("failed to marshal KeyShareVersion: %w", err)
	}

	// Store in Badger
	key := fmt.Sprintf("%s%d", keyPrefixKeyShare, version.Version)
	return b.db.Update(func(txn *badgerdb.Txn) error {
		return txn.Set([]byte(key), data)
	})
}

// LoadKeyShareVersion retrieves a key share version
func (b *BadgerPersistence) LoadKeyShareVersion(epoch int64) (*types.KeyShareVersion, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	key := fmt.Sprintf("%s%d", keyPrefixKeyShare, epoch)

	var data []byte
	err := b.db.View(func(txn *badgerdb.Txn) error {
		item, err := txn.Get([]byte(key))
		if err == badgerdb.ErrKeyNotFound {
			return nil // Not found is not an error
		}
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			data = append([]byte{}, val...) // Copy value
			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("failed to load KeyShareVersion: %w", err)
	}

	if data == nil {
		return nil, nil // Not found
	}

	// Deserialize from JSON
	version, err := persistence.UnmarshalKeyShareVersion(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal KeyShareVersion: %w", err)
	}

	return version, nil
}

// ListKeyShareVersions returns all key share versions sorted by epoch
func (b *BadgerPersistence) ListKeyShareVersions() ([]*types.KeyShareVersion, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	var versions []*types.KeyShareVersion

	err := b.db.View(func(txn *badgerdb.Txn) error {
		opts := badgerdb.DefaultIteratorOptions
		opts.Prefix = []byte(keyPrefixKeyShare)

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()

			var data []byte
			err := item.Value(func(val []byte) error {
				data = append([]byte{}, val...) // Copy value
				return nil
			})
			if err != nil {
				return fmt.Errorf("failed to read value: %w", err)
			}

			version, err := persistence.UnmarshalKeyShareVersion(data)
			if err != nil {
				b.logger.Sugar().Warnw("Failed to unmarshal KeyShareVersion, skipping",
					"key", string(item.Key()), "error", err)
				continue
			}

			versions = append(versions, version)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list KeyShareVersions: %w", err)
	}

	// Sort by epoch (ascending)
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version < versions[j].Version
	})

	return versions, nil
}

// DeleteKeyShareVersion removes a key share version
func (b *BadgerPersistence) DeleteKeyShareVersion(epoch int64) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	key := fmt.Sprintf("%s%d", keyPrefixKeyShare, epoch)

	return b.db.Update(func(txn *badgerdb.Txn) error {
		return txn.Delete([]byte(key))
	})
}

// SetActiveVersionEpoch stores the active version epoch
func (b *BadgerPersistence) SetActiveVersionEpoch(epoch int64) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	// Convert int64 to bytes
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(epoch))

	return b.db.Update(func(txn *badgerdb.Txn) error {
		return txn.Set([]byte(keyPrefixActiveVersion), buf)
	})
}

// GetActiveVersionEpoch retrieves the active version epoch
func (b *BadgerPersistence) GetActiveVersionEpoch() (int64, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return 0, fmt.Errorf("persistence layer is closed")
	}

	var epoch int64

	err := b.db.View(func(txn *badgerdb.Txn) error {
		item, err := txn.Get([]byte(keyPrefixActiveVersion))
		if err == badgerdb.ErrKeyNotFound {
			return nil // No active version set yet
		}
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			if len(val) != 8 {
				return fmt.Errorf("invalid active version data length: %d", len(val))
			}
			epoch = int64(binary.BigEndian.Uint64(val))
			return nil
		})
	})

	if err != nil {
		return 0, fmt.Errorf("failed to get active version epoch: %w", err)
	}

	return epoch, nil
}

// SaveNodeState persists node operational state
func (b *BadgerPersistence) SaveNodeState(state *persistence.NodeState) error {
	if state == nil {
		return fmt.Errorf("cannot save nil NodeState")
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	// Serialize to JSON
	data, err := persistence.MarshalNodeState(state)
	if err != nil {
		return fmt.Errorf("failed to marshal NodeState: %w", err)
	}

	return b.db.Update(func(txn *badgerdb.Txn) error {
		return txn.Set([]byte(keyPrefixNodeState), data)
	})
}

// LoadNodeState retrieves node operational state
func (b *BadgerPersistence) LoadNodeState() (*persistence.NodeState, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	var data []byte

	err := b.db.View(func(txn *badgerdb.Txn) error {
		item, err := txn.Get([]byte(keyPrefixNodeState))
		if err == badgerdb.ErrKeyNotFound {
			return nil // Not found is not an error
		}
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			data = append([]byte{}, val...) // Copy value
			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("failed to load NodeState: %w", err)
	}

	if data == nil {
		return nil, nil // Not found
	}

	// Deserialize from JSON
	state, err := persistence.UnmarshalNodeState(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal NodeState: %w", err)
	}

	return state, nil
}

// SaveProtocolSession persists protocol session state
func (b *BadgerPersistence) SaveProtocolSession(session *persistence.ProtocolSessionState) error {
	if session == nil {
		return fmt.Errorf("cannot save nil ProtocolSessionState")
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	// Serialize to JSON
	data, err := persistence.MarshalProtocolSessionState(session)
	if err != nil {
		return fmt.Errorf("failed to marshal ProtocolSessionState: %w", err)
	}

	key := fmt.Sprintf("%s%d", keyPrefixSession, session.SessionTimestamp)

	return b.db.Update(func(txn *badgerdb.Txn) error {
		return txn.Set([]byte(key), data)
	})
}

// LoadProtocolSession retrieves protocol session state
func (b *BadgerPersistence) LoadProtocolSession(sessionTimestamp int64) (*persistence.ProtocolSessionState, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	key := fmt.Sprintf("%s%d", keyPrefixSession, sessionTimestamp)

	var data []byte

	err := b.db.View(func(txn *badgerdb.Txn) error {
		item, err := txn.Get([]byte(key))
		if err == badgerdb.ErrKeyNotFound {
			return nil // Not found is not an error
		}
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			data = append([]byte{}, val...) // Copy value
			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("failed to load ProtocolSessionState: %w", err)
	}

	if data == nil {
		return nil, nil // Not found
	}

	// Deserialize from JSON
	session, err := persistence.UnmarshalProtocolSessionState(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ProtocolSessionState: %w", err)
	}

	return session, nil
}

// DeleteProtocolSession removes protocol session state
func (b *BadgerPersistence) DeleteProtocolSession(sessionTimestamp int64) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	key := fmt.Sprintf("%s%d", keyPrefixSession, sessionTimestamp)

	return b.db.Update(func(txn *badgerdb.Txn) error {
		return txn.Delete([]byte(key))
	})
}

// ListProtocolSessions returns all protocol sessions
func (b *BadgerPersistence) ListProtocolSessions() ([]*persistence.ProtocolSessionState, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	var sessions []*persistence.ProtocolSessionState

	err := b.db.View(func(txn *badgerdb.Txn) error {
		opts := badgerdb.DefaultIteratorOptions
		opts.Prefix = []byte(keyPrefixSession)

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()

			var data []byte
			err := item.Value(func(val []byte) error {
				data = append([]byte{}, val...) // Copy value
				return nil
			})
			if err != nil {
				return fmt.Errorf("failed to read value: %w", err)
			}

			session, err := persistence.UnmarshalProtocolSessionState(data)
			if err != nil {
				b.logger.Sugar().Warnw("Failed to unmarshal ProtocolSessionState, skipping",
					"key", string(item.Key()), "error", err)
				continue
			}

			sessions = append(sessions, session)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list ProtocolSessionStates: %w", err)
	}

	return sessions, nil
}

// Close shuts down the persistence layer
func (b *BadgerPersistence) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil // Already closed, idempotent
	}
	b.closed = true
	b.mu.Unlock()

	// Stop GC goroutine
	if b.gcCancel != nil {
		b.gcCancel()
	}
	b.gcWg.Wait()

	// Close database
	if err := b.db.Close(); err != nil {
		return fmt.Errorf("failed to close badger database: %w", err)
	}

	b.logger.Sugar().Info("Badger persistence closed")
	return nil
}

// HealthCheck verifies the persistence layer is operational
func (b *BadgerPersistence) HealthCheck() error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	// Try a simple read operation to verify database is accessible
	return b.db.View(func(txn *badgerdb.Txn) error {
		_, err := txn.Get([]byte(keySchemaVersion))
		if err == badgerdb.ErrKeyNotFound {
			return fmt.Errorf("schema version not found - database may be corrupted")
		}
		return err
	})
}
