package persistence

import (
	"encoding/json"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// NodeState represents operational state that must persist across restarts.
// This state is required for the node to resume operations correctly after a restart.
type NodeState struct {
	// LastProcessedBoundary is the last block number at which DKG/reshare was triggered.
	// Used to avoid re-triggering protocols on the same block after restart.
	LastProcessedBoundary int64 `json:"lastProcessedBoundary"`

	// NodeStartTime is the Unix timestamp when the node last started.
	// Used for operational monitoring and debugging.
	NodeStartTime int64 `json:"nodeStartTime"`

	// OperatorAddress is the Ethereum address of this operator.
	// Stored for verification that persistence data matches the operator.
	OperatorAddress string `json:"operatorAddress"`

	// TrackedSourceVersion is the active source version the MPK-abort counter is
	// currently counting against. The counter is only trusted after restart when
	// this equals the current active source version.
	TrackedSourceVersion int64 `json:"trackedSourceVersion"`

	// ConsecutiveMPKAborts counts consecutive Layer-1 MPK-validation aborts on
	// TrackedSourceVersion. Reaching the demotion threshold marks that version poisoned.
	ConsecutiveMPKAborts int `json:"consecutiveMpkAborts"`

	// LastKnownGoodSourceVersion is the agreed majority source version (srcVersion)
	// of the most recent reshare round that passed MPK validation and persisted.
	// 0 means none recorded yet. Used as the preferred auto-heal rollback target.
	LastKnownGoodSourceVersion int64 `json:"lastKnownGoodSourceVersion"`
}

// MarshalJSON implements json.Marshaler. The Alias type strips the method
// set so default encoding is used, avoiding infinite recursion.
func (ns *NodeState) MarshalJSON() ([]byte, error) {
	type Alias NodeState
	return json.Marshal((*Alias)(ns))
}

// UnmarshalJSON implements json.Unmarshaler. The Alias type strips the method
// set so default decoding is used, avoiding infinite recursion.
func (ns *NodeState) UnmarshalJSON(data []byte) error {
	type Alias NodeState
	return json.Unmarshal(data, (*Alias)(ns))
}

// BlockRecord is a node-local representation of a chain-poller block cursor
// entry. It intentionally mirrors the shape of the chain-indexer
// chainPoller.BlockRecord but uses only primitive fields (in particular a
// plain uint64 ChainId) so that the persistence package remains free of any
// chain-indexer dependency. Translation to/from the chain-indexer type is
// performed exclusively by the chainpolleradapter package.
type BlockRecord struct {
	Number     uint64 `json:"number"`
	Hash       string `json:"hash"`
	ParentHash string `json:"parentHash"`
	Timestamp  uint64 `json:"timestamp"`
	ChainId    uint64 `json:"chainId"`
}

// ProtocolSessionState captures ephemeral state of a DKG or reshare session.
// This enables crash recovery - if a node restarts mid-protocol, it can
// detect incomplete sessions and clean them up appropriately.
type ProtocolSessionState struct {
	// SessionTimestamp is the block timestamp for this session.
	// This serves as the primary key for session storage.
	SessionTimestamp int64 `json:"sessionTimestamp"`

	// Type indicates the protocol type: "dkg" or "reshare"
	Type string `json:"type"`

	// Phase indicates the current phase of the protocol (1-4)
	// Phase 1: Share distribution
	// Phase 2: Verification and acknowledgement
	// Phase 3: Finalization
	// Phase 4: Merkle tree building (future)
	Phase int `json:"phase"`

	// StartTime is the Unix timestamp when this session began
	StartTime int64 `json:"startTime"`

	// OperatorAddresses is the list of operator addresses participating in this session.
	// Stored as hex strings for JSON serialization.
	OperatorAddresses []string `json:"operatorAddresses"`

	// Shares maps operator address (hex) to serialized share (SerializeFr string format).
	// This captures shares received during the protocol.
	Shares map[string]string `json:"shares"`

	// Commitments maps operator address (hex) to their broadcast commitments.
	// G2Points are JSON-serializable via CompressedBytes.
	Commitments map[string][]types.G2Point `json:"commitments"`

	// Acknowledgements maps dealer address (hex) -> receiver address (hex) -> acknowledgement.
	// This tracks which operators have acknowledged which shares.
	Acknowledgements map[string]map[string]*types.Acknowledgement `json:"acknowledgements"`
}

// MarshalJSON implements json.Marshaler. The Alias type strips the method
// set so default encoding is used, avoiding infinite recursion.
func (pss *ProtocolSessionState) MarshalJSON() ([]byte, error) {
	type Alias ProtocolSessionState
	return json.Marshal((*Alias)(pss))
}

// UnmarshalJSON implements json.Unmarshaler. The Alias type strips the method
// set so default decoding is used, avoiding infinite recursion.
func (pss *ProtocolSessionState) UnmarshalJSON(data []byte) error {
	type Alias ProtocolSessionState
	return json.Unmarshal(data, (*Alias)(pss))
}

// IsExpired checks if a protocol session has exceeded its timeout duration.
// Sessions are considered expired if they've been running longer than the timeout.
func (pss *ProtocolSessionState) IsExpired(timeoutSeconds int64) bool {
	if pss == nil {
		return true
	}
	currentTime := time.Now().Unix()
	elapsed := currentTime - pss.StartTime
	return elapsed > timeoutSeconds
}
