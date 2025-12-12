package redis

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Key prefixes for namespacing in Redis
const (
	keyPrefixKeyShare      = "kms:keyshare:"
	keyPrefixActiveVersion = "kms:active:version"
	keyPrefixNodeState     = "kms:nodestate:main"
	keyPrefixSession       = "kms:session:"
	keySchemaVersion       = "kms:metadata:schema_version"
	currentSchemaVersion   = "v1"

	// Key set for listing operations (Redis doesn't support prefix iteration natively)
	keySetKeyShares = "kms:keyshares:index"
	keySetSessions  = "kms:sessions:index"
)

// RedisPersistence is a production-ready persistence implementation using Redis.
// Provides durable, distributed storage suitable for cloud-native deployments.
type RedisPersistence struct {
	client    *redis.Client
	logger    *zap.Logger
	keyPrefix string // Custom prefix for all keys
	mu        sync.RWMutex
	closed    bool
}

// RedisConfig holds the configuration for connecting to Redis
type RedisConfig struct {
	// Address is the Redis server address (host:port)
	Address string
	// Password is the optional Redis password
	Password string
	// DB is the Redis database number (0-15)
	DB int
	// KeyPrefix is an optional custom prefix for all keys (for multi-tenant setups).
	// If set, this prefix is prepended to all keys, e.g., "myapp:" would result in
	// keys like "myapp:kms:keyshare:123". If empty, keys use the default "kms:" prefix.
	KeyPrefix string
}

// NewRedisPersistence creates a new Redis-backed persistence layer.
func NewRedisPersistence(cfg *RedisConfig, logger *zap.Logger) (*RedisPersistence, error) {
	if cfg == nil {
		return nil, fmt.Errorf("redis config cannot be nil")
	}

	if cfg.Address == "" {
		return nil, fmt.Errorf("redis address cannot be empty")
	}

	// Create Redis client options
	opts := &redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	}

	// Create Redis client
	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis at %s: %w", cfg.Address, err)
	}

	rp := &RedisPersistence{
		client:    client,
		logger:    logger,
		keyPrefix: cfg.KeyPrefix,
	}

	// Initialize schema version
	if err := rp.initSchema(ctx); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	if cfg.KeyPrefix != "" {
		logger.Sugar().Infow("Redis persistence initialized", "address", cfg.Address, "db", cfg.DB, "key_prefix", cfg.KeyPrefix)
	} else {
		logger.Sugar().Infow("Redis persistence initialized", "address", cfg.Address, "db", cfg.DB)
	}

	return rp, nil
}

// prefixKey adds the custom key prefix (if configured) to a key
func (r *RedisPersistence) prefixKey(key string) string {
	if r.keyPrefix == "" {
		return key
	}
	return r.keyPrefix + key
}

// initSchema initializes or validates the schema version
func (r *RedisPersistence) initSchema(ctx context.Context) error {
	schemaKey := r.prefixKey(keySchemaVersion)

	// Check if schema version exists
	existingVersion, err := r.client.Get(ctx, schemaKey).Result()
	if err == redis.Nil {
		// First time setup - set schema version
		return r.client.Set(ctx, schemaKey, currentSchemaVersion, 0).Err()
	}
	if err != nil {
		return fmt.Errorf("failed to read schema version: %w", err)
	}

	// Validate existing schema version
	if existingVersion != currentSchemaVersion {
		return fmt.Errorf("unsupported schema version: %s (expected: %s)", existingVersion, currentSchemaVersion)
	}

	return nil
}

// SaveKeyShareVersion persists a key share version
func (r *RedisPersistence) SaveKeyShareVersion(version *types.KeyShareVersion) error {
	if version == nil {
		return fmt.Errorf("cannot save nil KeyShareVersion")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	ctx := context.Background()

	// Serialize to JSON
	data, err := persistence.MarshalKeyShareVersion(version)
	if err != nil {
		return fmt.Errorf("failed to marshal KeyShareVersion: %w", err)
	}

	// Store in Redis using a pipeline for atomicity
	key := r.prefixKey(fmt.Sprintf("%s%d", keyPrefixKeyShare, version.Version))
	indexKey := r.prefixKey(keySetKeyShares)
	pipe := r.client.Pipeline()
	pipe.Set(ctx, key, data, 0)
	pipe.SAdd(ctx, indexKey, version.Version) // Add to index set

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to save KeyShareVersion: %w", err)
	}

	return nil
}

// LoadKeyShareVersion retrieves a key share version
func (r *RedisPersistence) LoadKeyShareVersion(epoch int64) (*types.KeyShareVersion, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	ctx := context.Background()
	key := r.prefixKey(fmt.Sprintf("%s%d", keyPrefixKeyShare, epoch))

	data, err := r.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil // Not found is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load KeyShareVersion: %w", err)
	}

	// Deserialize from JSON
	version, err := persistence.UnmarshalKeyShareVersion(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal KeyShareVersion: %w", err)
	}

	return version, nil
}

// ListKeyShareVersions returns all key share versions sorted by epoch
func (r *RedisPersistence) ListKeyShareVersions() ([]*types.KeyShareVersion, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	ctx := context.Background()
	indexKey := r.prefixKey(keySetKeyShares)

	// Get all epochs from the index set
	epochs, err := r.client.SMembers(ctx, indexKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list KeyShareVersion epochs: %w", err)
	}

	if len(epochs) == 0 {
		return []*types.KeyShareVersion{}, nil
	}

	// Build keys for all versions
	keys := make([]string, len(epochs))
	for i, epoch := range epochs {
		keys[i] = r.prefixKey(fmt.Sprintf("%s%s", keyPrefixKeyShare, epoch))
	}

	// Fetch all values using MGET
	values, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch KeyShareVersions: %w", err)
	}

	// Parse all versions
	var versions []*types.KeyShareVersion
	for i, val := range values {
		if val == nil {
			// Key was in index but doesn't exist - clean up index
			r.client.SRem(ctx, indexKey, epochs[i])
			continue
		}

		data, ok := val.(string)
		if !ok {
			r.logger.Sugar().Warnw("Unexpected value type for KeyShareVersion", "key", keys[i])
			continue
		}

		version, err := persistence.UnmarshalKeyShareVersion([]byte(data))
		if err != nil {
			r.logger.Sugar().Warnw("Failed to unmarshal KeyShareVersion, skipping",
				"key", keys[i], "error", err)
			continue
		}

		versions = append(versions, version)
	}

	// Sort by epoch (ascending)
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version < versions[j].Version
	})

	return versions, nil
}

// DeleteKeyShareVersion removes a key share version
func (r *RedisPersistence) DeleteKeyShareVersion(epoch int64) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	ctx := context.Background()
	key := r.prefixKey(fmt.Sprintf("%s%d", keyPrefixKeyShare, epoch))
	indexKey := r.prefixKey(keySetKeyShares)

	// Delete using pipeline
	pipe := r.client.Pipeline()
	pipe.Del(ctx, key)
	pipe.SRem(ctx, indexKey, epoch) // Remove from index set

	_, err := pipe.Exec(ctx)
	return err
}

// SetActiveVersionEpoch stores the active version epoch
func (r *RedisPersistence) SetActiveVersionEpoch(epoch int64) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	ctx := context.Background()
	key := r.prefixKey(keyPrefixActiveVersion)

	// Convert int64 to bytes
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(epoch))

	return r.client.Set(ctx, key, buf, 0).Err()
}

// GetActiveVersionEpoch retrieves the active version epoch
func (r *RedisPersistence) GetActiveVersionEpoch() (int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return 0, fmt.Errorf("persistence layer is closed")
	}

	ctx := context.Background()
	key := r.prefixKey(keyPrefixActiveVersion)

	data, err := r.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return 0, nil // No active version set yet
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get active version epoch: %w", err)
	}

	if len(data) != 8 {
		return 0, fmt.Errorf("invalid active version data length: %d", len(data))
	}

	epoch := int64(binary.BigEndian.Uint64(data))
	return epoch, nil
}

// SaveNodeState persists node operational state
func (r *RedisPersistence) SaveNodeState(state *persistence.NodeState) error {
	if state == nil {
		return fmt.Errorf("cannot save nil NodeState")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	ctx := context.Background()
	key := r.prefixKey(keyPrefixNodeState)

	// Serialize to JSON
	data, err := persistence.MarshalNodeState(state)
	if err != nil {
		return fmt.Errorf("failed to marshal NodeState: %w", err)
	}

	return r.client.Set(ctx, key, data, 0).Err()
}

// LoadNodeState retrieves node operational state
func (r *RedisPersistence) LoadNodeState() (*persistence.NodeState, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	ctx := context.Background()
	key := r.prefixKey(keyPrefixNodeState)

	data, err := r.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil // Not found is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load NodeState: %w", err)
	}

	// Deserialize from JSON
	state, err := persistence.UnmarshalNodeState(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal NodeState: %w", err)
	}

	return state, nil
}

// SaveProtocolSession persists protocol session state
func (r *RedisPersistence) SaveProtocolSession(session *persistence.ProtocolSessionState) error {
	if session == nil {
		return fmt.Errorf("cannot save nil ProtocolSessionState")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	ctx := context.Background()

	// Serialize to JSON
	data, err := persistence.MarshalProtocolSessionState(session)
	if err != nil {
		return fmt.Errorf("failed to marshal ProtocolSessionState: %w", err)
	}

	key := r.prefixKey(fmt.Sprintf("%s%d", keyPrefixSession, session.SessionTimestamp))
	indexKey := r.prefixKey(keySetSessions)

	// Store using pipeline
	pipe := r.client.Pipeline()
	pipe.Set(ctx, key, data, 0)
	pipe.SAdd(ctx, indexKey, session.SessionTimestamp) // Add to index set

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to save ProtocolSessionState: %w", err)
	}

	return nil
}

// LoadProtocolSession retrieves protocol session state
func (r *RedisPersistence) LoadProtocolSession(sessionTimestamp int64) (*persistence.ProtocolSessionState, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	ctx := context.Background()
	key := r.prefixKey(fmt.Sprintf("%s%d", keyPrefixSession, sessionTimestamp))

	data, err := r.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil // Not found is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load ProtocolSessionState: %w", err)
	}

	// Deserialize from JSON
	session, err := persistence.UnmarshalProtocolSessionState(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ProtocolSessionState: %w", err)
	}

	return session, nil
}

// DeleteProtocolSession removes protocol session state
func (r *RedisPersistence) DeleteProtocolSession(sessionTimestamp int64) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	ctx := context.Background()
	key := r.prefixKey(fmt.Sprintf("%s%d", keyPrefixSession, sessionTimestamp))
	indexKey := r.prefixKey(keySetSessions)

	// Delete using pipeline
	pipe := r.client.Pipeline()
	pipe.Del(ctx, key)
	pipe.SRem(ctx, indexKey, sessionTimestamp) // Remove from index set

	_, err := pipe.Exec(ctx)
	return err
}

// ListProtocolSessions returns all protocol sessions
func (r *RedisPersistence) ListProtocolSessions() ([]*persistence.ProtocolSessionState, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	ctx := context.Background()
	indexKey := r.prefixKey(keySetSessions)

	// Get all session timestamps from the index set
	timestamps, err := r.client.SMembers(ctx, indexKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list ProtocolSession timestamps: %w", err)
	}

	if len(timestamps) == 0 {
		return []*persistence.ProtocolSessionState{}, nil
	}

	// Build keys for all sessions
	keys := make([]string, len(timestamps))
	for i, ts := range timestamps {
		keys[i] = r.prefixKey(fmt.Sprintf("%s%s", keyPrefixSession, ts))
	}

	// Fetch all values using MGET
	values, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ProtocolSessionStates: %w", err)
	}

	// Parse all sessions
	var sessions []*persistence.ProtocolSessionState
	for i, val := range values {
		if val == nil {
			// Key was in index but doesn't exist - clean up index
			r.client.SRem(ctx, indexKey, timestamps[i])
			continue
		}

		data, ok := val.(string)
		if !ok {
			r.logger.Sugar().Warnw("Unexpected value type for ProtocolSessionState", "key", keys[i])
			continue
		}

		session, err := persistence.UnmarshalProtocolSessionState([]byte(data))
		if err != nil {
			r.logger.Sugar().Warnw("Failed to unmarshal ProtocolSessionState, skipping",
				"key", keys[i], "error", err)
			continue
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

// Close shuts down the persistence layer
func (r *RedisPersistence) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil // Already closed, idempotent
	}
	r.closed = true
	r.mu.Unlock()

	// Close Redis client
	if err := r.client.Close(); err != nil {
		return fmt.Errorf("failed to close Redis client: %w", err)
	}

	r.logger.Sugar().Info("Redis persistence closed")
	return nil
}

// HealthCheck verifies the persistence layer is operational
func (r *RedisPersistence) HealthCheck() error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ping Redis to check connectivity
	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis health check failed: %w", err)
	}

	// Verify schema version exists
	schemaKey := r.prefixKey(keySchemaVersion)
	_, err := r.client.Get(ctx, schemaKey).Result()
	if err == redis.Nil {
		return fmt.Errorf("schema version not found - database may not be properly initialized")
	}
	if err != nil {
		return fmt.Errorf("failed to verify schema version: %w", err)
	}

	return nil
}
