package persistence

import "github.com/Layr-Labs/eigenx-kms-go/pkg/types"

// INodePersistence defines the interface for persisting node state across restarts.
// All implementations must be thread-safe as Node operations are concurrent.
//
// The interface supports:
// - Key share version management (save, load, list, delete)
// - Active version tracking (which key version is currently in use)
// - Node operational state (lastProcessedBoundary, etc.)
// - Protocol session management (in-progress DKG/reshare state)
// - Lifecycle management (close, health check)
type INodePersistence interface {
	// Key Share Management

	// SaveKeyShareVersion persists a key share version indexed by block timestamp.
	// The version is stored using the block timestamp as the key.
	// Returns error only on storage failure, not if version already exists (idempotent).
	SaveKeyShareVersion(version *types.KeyShareVersion) error

	// LoadKeyShareVersion retrieves a key share version by block timestamp.
	// Returns nil if version doesn't exist, error only on storage failure.
	LoadKeyShareVersion(timestamp int64) (*types.KeyShareVersion, error)

	// ListKeyShareVersions returns all persisted key share versions sorted by block timestamp (ascending).
	// Returns empty slice if no versions exist, error only on storage failure.
	ListKeyShareVersions() ([]*types.KeyShareVersion, error)

	// DeleteKeyShareVersion removes a key share version by block timestamp.
	// Idempotent - returns nil if version doesn't exist.
	// Returns error only on storage failure.
	DeleteKeyShareVersion(timestamp int64) error

	// AddPoisonedVersion records a key-share version as poisoned (its shares are
	// cross-node-inconsistent and must never be dealt from, activated, or served).
	// Idempotent. Returns error only on storage failure.
	//
	// The poisoned set is intentionally append-only: a version that was once
	// cross-node-inconsistent must never be re-activated, so there is deliberately
	// no removal API. Demotions are rare, non-steady-state events, so unbounded
	// growth is a non-issue in practice; recovery from the floor case is via
	// wipe-and-rejoin, not in-place cleanup of this set.
	AddPoisonedVersion(version int64) error

	// ListPoisonedVersions returns all recorded poisoned versions (unordered).
	// Returns empty slice if none. Returns error only on storage failure.
	ListPoisonedVersions() ([]int64, error)

	// Active Version Tracking

	// SetActiveVersionTimestamp stores which key version is currently active.
	// This is a pointer to the block timestamp of the active KeyShareVersion.
	// Setting timestamp=0 indicates no active version.
	SetActiveVersionTimestamp(timestamp int64) error

	// GetActiveVersionTimestamp returns the block timestamp of the active version.
	// Returns 0 if no active version is set (first run).
	// Returns error only on storage failure.
	GetActiveVersionTimestamp() (int64, error)

	// Node Operational State

	// SaveNodeState persists operational state (lastProcessedBoundary, etc.).
	// Overwrites any existing state.
	SaveNodeState(state *NodeState) error

	// LoadNodeState retrieves operational state.
	// Returns nil state if none exists (first run), error only on storage failure.
	LoadNodeState() (*NodeState, error)

	// Protocol Session Management

	// SaveProtocolSession persists ephemeral protocol state for crash recovery.
	// Sessions are indexed by sessionTimestamp.
	// Overwrites any existing session with the same timestamp.
	SaveProtocolSession(session *ProtocolSessionState) error

	// LoadProtocolSession retrieves protocol session state by timestamp.
	// Returns nil if session doesn't exist, error only on storage failure.
	LoadProtocolSession(sessionTimestamp int64) (*ProtocolSessionState, error)

	// DeleteProtocolSession removes completed/failed session data.
	// Idempotent - returns nil if session doesn't exist.
	// Returns error only on storage failure.
	DeleteProtocolSession(sessionTimestamp int64) error

	// ListProtocolSessions returns all active protocol sessions.
	// Returns empty slice if no sessions exist, error only on storage failure.
	// Used during startup to detect and clean up incomplete sessions.
	ListProtocolSessions() ([]*ProtocolSessionState, error)

	// Chain Poller Block Cursor

	// SaveBlockRecord upserts a block record keyed by (chainId, number) and
	// unconditionally advances the "last processed" pointer for that chain to
	// this block. The poller invokes this in-order per block, so the most
	// recently saved block is always the highest processed one (this matches
	// the chain-indexer in-memory implementation's semantics).
	// Returns error only on storage failure.
	SaveBlockRecord(record *BlockRecord) error

	// GetLastProcessedBlockRecord returns the highest-processed block record for
	// the given chain, i.e. the block most recently passed to SaveBlockRecord.
	// Returns (nil, nil) if no block has been processed for the chain yet.
	// Returns error only on storage failure.
	GetLastProcessedBlockRecord(chainId uint64) (*BlockRecord, error)

	// GetBlockRecord returns a specific block record by (chainId, number).
	// Returns (nil, nil) if the block does not exist.
	// Returns error only on storage failure.
	GetBlockRecord(chainId uint64, blockNumber uint64) (*BlockRecord, error)

	// DeleteBlockRecord removes a block record by (chainId, number).
	// Idempotent - returns nil if the block does not exist (used for reorg
	// handling). Does not modify the last-processed pointer.
	// Returns error only on storage failure.
	DeleteBlockRecord(chainId uint64, blockNumber uint64) error

	// Lifecycle Management

	// Close cleanly shuts down the persistence layer.
	// Idempotent - safe to call multiple times.
	// After Close(), all other operations should return errors.
	Close() error

	// HealthCheck verifies the persistence layer is operational.
	// Returns nil if healthy, error describing the problem if not.
	// Should be called during node startup to fail fast.
	HealthCheck() error
}
