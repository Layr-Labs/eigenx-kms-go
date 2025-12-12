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

	// SaveKeyShareVersion persists a key share version indexed by epoch timestamp.
	// The version is stored using the epoch as the key.
	// Returns error only on storage failure, not if version already exists (idempotent).
	SaveKeyShareVersion(version *types.KeyShareVersion) error

	// LoadKeyShareVersion retrieves a key share version by epoch timestamp.
	// Returns nil if version doesn't exist, error only on storage failure.
	LoadKeyShareVersion(epoch int64) (*types.KeyShareVersion, error)

	// ListKeyShareVersions returns all persisted key share versions sorted by epoch (ascending).
	// Returns empty slice if no versions exist, error only on storage failure.
	ListKeyShareVersions() ([]*types.KeyShareVersion, error)

	// DeleteKeyShareVersion removes a key share version by epoch timestamp.
	// Idempotent - returns nil if version doesn't exist.
	// Returns error only on storage failure.
	DeleteKeyShareVersion(epoch int64) error

	// Active Version Tracking

	// SetActiveVersionEpoch stores which key version is currently active.
	// This is a pointer to the epoch of the active KeyShareVersion.
	// Setting epoch=0 indicates no active version.
	SetActiveVersionEpoch(epoch int64) error

	// GetActiveVersionEpoch returns the epoch of the active version.
	// Returns 0 if no active version is set (first run).
	// Returns error only on storage failure.
	GetActiveVersionEpoch() (int64, error)

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
