package memory

import (
	"fmt"
	"sort"
	"sync"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// MemoryPersistence is an in-memory implementation of INodePersistence.
// This implementation is intended for TESTING ONLY.
//
// All data is stored in memory and will be lost when the process exits.
// Thread-safe using sync.RWMutex for concurrent access.
// Deep copies data to prevent external mutation.
type MemoryPersistence struct {
	mu sync.RWMutex

	// Key share storage: epoch -> KeyShareVersion
	keyShares map[int64]*types.KeyShareVersion

	// Active version tracking
	activeVersionEpoch int64

	// Node state
	nodeState *persistence.NodeState

	// Protocol sessions: sessionTimestamp -> ProtocolSessionState
	sessions map[int64]*persistence.ProtocolSessionState

	// Closed flag
	closed bool
}

// NewMemoryPersistence creates a new in-memory persistence layer.
// Prints a loud warning since this should only be used for testing.
func NewMemoryPersistence() *MemoryPersistence {
	fmt.Println("⚠️  WARNING: Using in-memory persistence - ALL DATA WILL BE LOST ON RESTART")
	fmt.Println("⚠️  This should ONLY be used for testing. Set KMS_PERSISTENCE_TYPE=badger for production")

	return &MemoryPersistence{
		keyShares: make(map[int64]*types.KeyShareVersion),
		sessions:  make(map[int64]*persistence.ProtocolSessionState),
		nodeState: &persistence.NodeState{},
	}
}

// SaveKeyShareVersion persists a key share version.
func (m *MemoryPersistence) SaveKeyShareVersion(version *types.KeyShareVersion) error {
	if version == nil {
		return fmt.Errorf("cannot save nil KeyShareVersion")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	// Deep copy to prevent external mutation
	m.keyShares[version.Version] = deepCopyKeyShareVersion(version)

	return nil
}

// LoadKeyShareVersion retrieves a key share version by epoch.
func (m *MemoryPersistence) LoadKeyShareVersion(epoch int64) (*types.KeyShareVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	version, exists := m.keyShares[epoch]
	if !exists {
		return nil, nil // Not found is not an error
	}

	// Deep copy to prevent external mutation
	return deepCopyKeyShareVersion(version), nil
}

// ListKeyShareVersions returns all key share versions sorted by epoch.
func (m *MemoryPersistence) ListKeyShareVersions() ([]*types.KeyShareVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	// Collect epochs and sort
	epochs := make([]int64, 0, len(m.keyShares))
	for epoch := range m.keyShares {
		epochs = append(epochs, epoch)
	}
	sort.Slice(epochs, func(i, j int) bool {
		return epochs[i] < epochs[j]
	})

	// Build sorted list with deep copies
	result := make([]*types.KeyShareVersion, 0, len(epochs))
	for _, epoch := range epochs {
		result = append(result, deepCopyKeyShareVersion(m.keyShares[epoch]))
	}

	return result, nil
}

// DeleteKeyShareVersion removes a key share version.
func (m *MemoryPersistence) DeleteKeyShareVersion(epoch int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	delete(m.keyShares, epoch)
	return nil
}

// SetActiveVersionEpoch stores the active version epoch.
func (m *MemoryPersistence) SetActiveVersionEpoch(epoch int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	m.activeVersionEpoch = epoch
	return nil
}

// GetActiveVersionEpoch retrieves the active version epoch.
func (m *MemoryPersistence) GetActiveVersionEpoch() (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return 0, fmt.Errorf("persistence layer is closed")
	}

	return m.activeVersionEpoch, nil
}

// SaveNodeState persists node operational state.
func (m *MemoryPersistence) SaveNodeState(state *persistence.NodeState) error {
	if state == nil {
		return fmt.Errorf("cannot save nil NodeState")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	// Deep copy
	m.nodeState = &persistence.NodeState{
		LastProcessedBoundary: state.LastProcessedBoundary,
		NodeStartTime:         state.NodeStartTime,
		OperatorAddress:       state.OperatorAddress,
	}

	return nil
}

// LoadNodeState retrieves node operational state.
func (m *MemoryPersistence) LoadNodeState() (*persistence.NodeState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	// Return nil if no state has been saved yet (first run)
	if m.nodeState.OperatorAddress == "" && m.nodeState.LastProcessedBoundary == 0 {
		return nil, nil
	}

	// Deep copy
	return &persistence.NodeState{
		LastProcessedBoundary: m.nodeState.LastProcessedBoundary,
		NodeStartTime:         m.nodeState.NodeStartTime,
		OperatorAddress:       m.nodeState.OperatorAddress,
	}, nil
}

// SaveProtocolSession persists protocol session state.
func (m *MemoryPersistence) SaveProtocolSession(session *persistence.ProtocolSessionState) error {
	if session == nil {
		return fmt.Errorf("cannot save nil ProtocolSessionState")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	// Deep copy
	m.sessions[session.SessionTimestamp] = deepCopyProtocolSessionState(session)

	return nil
}

// LoadProtocolSession retrieves protocol session state.
func (m *MemoryPersistence) LoadProtocolSession(sessionTimestamp int64) (*persistence.ProtocolSessionState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	session, exists := m.sessions[sessionTimestamp]
	if !exists {
		return nil, nil // Not found is not an error
	}

	// Deep copy
	return deepCopyProtocolSessionState(session), nil
}

// DeleteProtocolSession removes protocol session state.
func (m *MemoryPersistence) DeleteProtocolSession(sessionTimestamp int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	delete(m.sessions, sessionTimestamp)
	return nil
}

// ListProtocolSessions returns all protocol sessions.
func (m *MemoryPersistence) ListProtocolSessions() ([]*persistence.ProtocolSessionState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	// Build list with deep copies
	result := make([]*persistence.ProtocolSessionState, 0, len(m.sessions))
	for _, session := range m.sessions {
		result = append(result, deepCopyProtocolSessionState(session))
	}

	return result, nil
}

// Close shuts down the persistence layer.
func (m *MemoryPersistence) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	return nil
}

// HealthCheck verifies the persistence layer is operational.
func (m *MemoryPersistence) HealthCheck() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	return nil
}

// Deep copy helpers

func deepCopyKeyShareVersion(v *types.KeyShareVersion) *types.KeyShareVersion {
	if v == nil {
		return nil
	}

	// Copy private share (fr.Element)
	var privateShareCopy *fr.Element
	if v.PrivateShare != nil {
		ps := new(fr.Element).Set(v.PrivateShare)
		privateShareCopy = ps
	}

	// Copy commitments
	commitments := make([]types.G2Point, len(v.Commitments))
	for i, c := range v.Commitments {
		compressedCopy := make([]byte, len(c.CompressedBytes))
		copy(compressedCopy, c.CompressedBytes)
		commitments[i] = types.G2Point{CompressedBytes: compressedCopy}
	}

	// Copy participant IDs
	participantIDs := make([]int64, len(v.ParticipantIDs))
	copy(participantIDs, v.ParticipantIDs)

	return &types.KeyShareVersion{
		Version:        v.Version,
		PrivateShare:   privateShareCopy,
		Commitments:    commitments,
		IsActive:       v.IsActive,
		ParticipantIDs: participantIDs,
	}
}

func deepCopyProtocolSessionState(s *persistence.ProtocolSessionState) *persistence.ProtocolSessionState {
	if s == nil {
		return nil
	}

	// Copy operator addresses
	operatorAddresses := make([]string, len(s.OperatorAddresses))
	copy(operatorAddresses, s.OperatorAddresses)

	// Copy shares map
	shares := make(map[int64]string)
	for k, v := range s.Shares {
		shares[k] = v
	}

	// Copy commitments map
	commitments := make(map[int64][]types.G2Point)
	for k, v := range s.Commitments {
		commitmentsCopy := make([]types.G2Point, len(v))
		for i, c := range v {
			compressedCopy := make([]byte, len(c.CompressedBytes))
			copy(compressedCopy, c.CompressedBytes)
			commitmentsCopy[i] = types.G2Point{CompressedBytes: compressedCopy}
		}
		commitments[k] = commitmentsCopy
	}

	// Copy acknowledgements map
	acknowledgements := make(map[int64]map[int64]*types.Acknowledgement)
	for dealerID, ackMap := range s.Acknowledgements {
		ackMapCopy := make(map[int64]*types.Acknowledgement)
		for receiverID, ack := range ackMap {
			ackCopy := &types.Acknowledgement{
				PlayerID:       ack.PlayerID,
				DealerID:       ack.DealerID,
				Epoch:          ack.Epoch,
				ShareHash:      ack.ShareHash,      // [32]byte is copied by value
				CommitmentHash: ack.CommitmentHash, // [32]byte is copied by value
			}
			if len(ack.Signature) > 0 {
				signatureCopy := make([]byte, len(ack.Signature))
				copy(signatureCopy, ack.Signature)
				ackCopy.Signature = signatureCopy
			}
			ackMapCopy[receiverID] = ackCopy
		}
		acknowledgements[dealerID] = ackMapCopy
	}

	return &persistence.ProtocolSessionState{
		SessionTimestamp:  s.SessionTimestamp,
		Type:              s.Type,
		Phase:             s.Phase,
		StartTime:         s.StartTime,
		OperatorAddresses: operatorAddresses,
		Shares:            shares,
		Commitments:       commitments,
		Acknowledgements:  acknowledgements,
	}
}
