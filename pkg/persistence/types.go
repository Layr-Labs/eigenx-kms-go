package persistence

import (
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
}

// ProtocolSessionState captures ephemeral state of a DKG or reshare session.
// This enables crash recovery - if a node restarts mid-protocol, it can
// detect incomplete sessions and clean them up appropriately.
type ProtocolSessionState struct {
	// SessionTimestamp is the block number or epoch timestamp for this session.
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

	// Shares maps dealer node ID to serialized share (SerializeFr string format).
	// This captures shares received during the protocol.
	Shares map[int]string `json:"shares"`

	// Commitments maps dealer node ID to their broadcast commitments.
	// G2Points are JSON-serializable via CompressedBytes.
	Commitments map[int][]types.G2Point `json:"commitments"`

	// Acknowledgements maps dealer ID -> receiver ID -> acknowledgement.
	// This tracks which operators have acknowledged which shares.
	// Nested map structure: dealerID -> map[receiverID]Acknowledgement
	Acknowledgements map[int]map[int]*types.Acknowledgement `json:"acknowledgements"`
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
