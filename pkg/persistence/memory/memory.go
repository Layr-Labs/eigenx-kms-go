package memory

import (
	"fmt"
	"sort"
	"sync"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
)

// MemoryPersistence is an in-memory implementation of INodePersistence.
// This implementation is intended for TESTING ONLY.
//
// All data is stored in memory and will be lost when the process exits.
// Thread-safe using sync.RWMutex for concurrent access.
// Deep copies data to prevent external mutation.
type MemoryPersistence struct {
	mu sync.RWMutex

	// Key share storage: timestamp -> KeyShareVersion
	keyShares map[int64]*types.KeyShareVersion

	// Active version tracking
	activeVersionTimestamp int64

	// Node state
	nodeState *persistence.NodeState

	// Protocol sessions: sessionTimestamp -> ProtocolSessionState
	sessions map[int64]*persistence.ProtocolSessionState

	// Chain poller block records: (chainId, number) -> BlockRecord
	blockRecords map[blockRecordKey]*persistence.BlockRecord

	// Chain poller last processed block: chainId -> block number
	lastProcessedBlocks map[uint64]uint64

	// Closed flag
	closed bool
}

// blockRecordKey is the composite map key for block record storage.
type blockRecordKey struct {
	chainId uint64
	number  uint64
}

// NewMemoryPersistence creates a new in-memory persistence layer.
// Prints a loud warning since this should only be used for testing.
func NewMemoryPersistence() *MemoryPersistence {
	fmt.Println("WARNING: Using in-memory persistence - ALL DATA WILL BE LOST ON RESTART")
	fmt.Println("WARNING: This should ONLY be used for testing. Set KMS_PERSISTENCE_TYPE=badger for production")

	return &MemoryPersistence{
		keyShares:           make(map[int64]*types.KeyShareVersion),
		sessions:            make(map[int64]*persistence.ProtocolSessionState),
		blockRecords:        make(map[blockRecordKey]*persistence.BlockRecord),
		lastProcessedBlocks: make(map[uint64]uint64),
		nodeState:           &persistence.NodeState{},
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

// LoadKeyShareVersion retrieves a key share version by block timestamp.
func (m *MemoryPersistence) LoadKeyShareVersion(timestamp int64) (*types.KeyShareVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	version, exists := m.keyShares[timestamp]
	if !exists {
		return nil, nil // Not found is not an error
	}

	// Deep copy to prevent external mutation
	return deepCopyKeyShareVersion(version), nil
}

// ListKeyShareVersions returns all key share versions sorted by block timestamp.
func (m *MemoryPersistence) ListKeyShareVersions() ([]*types.KeyShareVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	// Collect timestamps and sort
	timestamps := make([]int64, 0, len(m.keyShares))
	for ts := range m.keyShares {
		timestamps = append(timestamps, ts)
	}
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})

	// Build sorted list with deep copies
	result := make([]*types.KeyShareVersion, 0, len(timestamps))
	for _, ts := range timestamps {
		result = append(result, deepCopyKeyShareVersion(m.keyShares[ts]))
	}

	return result, nil
}

// DeleteKeyShareVersion removes a key share version by block timestamp.
func (m *MemoryPersistence) DeleteKeyShareVersion(timestamp int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	delete(m.keyShares, timestamp)
	return nil
}

// SetActiveVersionTimestamp stores the active version block timestamp.
func (m *MemoryPersistence) SetActiveVersionTimestamp(timestamp int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	m.activeVersionTimestamp = timestamp
	return nil
}

// GetActiveVersionTimestamp retrieves the active version block timestamp.
func (m *MemoryPersistence) GetActiveVersionTimestamp() (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return 0, fmt.Errorf("persistence layer is closed")
	}

	return m.activeVersionTimestamp, nil
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
		LastProcessedBoundary:      state.LastProcessedBoundary,
		NodeStartTime:              state.NodeStartTime,
		OperatorAddress:            state.OperatorAddress,
		TrackedSourceVersion:       state.TrackedSourceVersion,
		ConsecutiveMPKAborts:       state.ConsecutiveMPKAborts,
		LastKnownGoodSourceVersion: state.LastKnownGoodSourceVersion,
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

	// Return nil if no state has been saved yet (first run).
	// NOTE: this guard also implicitly protects the auto-heal fields
	// (TrackedSourceVersion, ConsecutiveMPKAborts, LastKnownGoodSourceVersion),
	// which are load-bearing. The auto-heal writers always set OperatorAddress
	// when persisting those fields, so a real persisted state is never mistaken
	// for "first run" here. If this condition is ever revisited, take care not
	// to drop a state that carries only auto-heal fields.
	if m.nodeState.OperatorAddress == "" && m.nodeState.LastProcessedBoundary == 0 {
		return nil, nil
	}

	// Deep copy
	return &persistence.NodeState{
		LastProcessedBoundary:      m.nodeState.LastProcessedBoundary,
		NodeStartTime:              m.nodeState.NodeStartTime,
		OperatorAddress:            m.nodeState.OperatorAddress,
		TrackedSourceVersion:       m.nodeState.TrackedSourceVersion,
		ConsecutiveMPKAborts:       m.nodeState.ConsecutiveMPKAborts,
		LastKnownGoodSourceVersion: m.nodeState.LastKnownGoodSourceVersion,
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

// SaveBlockRecord upserts a block record and advances the last-processed
// pointer for the chain to the saved block.
func (m *MemoryPersistence) SaveBlockRecord(record *persistence.BlockRecord) error {
	if record == nil {
		return fmt.Errorf("cannot save nil BlockRecord")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	// Deep copy to prevent external mutation
	key := blockRecordKey{chainId: record.ChainId, number: record.Number}
	m.blockRecords[key] = deepCopyBlockRecord(record)
	m.lastProcessedBlocks[record.ChainId] = record.Number

	return nil
}

// GetLastProcessedBlockRecord returns the highest-processed block for the chain,
// or (nil, nil) if none has been processed yet.
func (m *MemoryPersistence) GetLastProcessedBlockRecord(chainId uint64) (*persistence.BlockRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	blockNum, exists := m.lastProcessedBlocks[chainId]
	if !exists {
		return nil, nil // Not found is not an error
	}

	record, exists := m.blockRecords[blockRecordKey{chainId: chainId, number: blockNum}]
	if !exists {
		return nil, nil // Not found is not an error
	}

	// Deep copy to prevent external mutation
	return deepCopyBlockRecord(record), nil
}

// GetBlockRecord returns a specific block record, or (nil, nil) if it does not exist.
func (m *MemoryPersistence) GetBlockRecord(chainId uint64, blockNumber uint64) (*persistence.BlockRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}

	record, exists := m.blockRecords[blockRecordKey{chainId: chainId, number: blockNumber}]
	if !exists {
		return nil, nil // Not found is not an error
	}

	// Deep copy to prevent external mutation
	return deepCopyBlockRecord(record), nil
}

// DeleteBlockRecord removes a block record. Idempotent.
func (m *MemoryPersistence) DeleteBlockRecord(chainId uint64, blockNumber uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("persistence layer is closed")
	}

	delete(m.blockRecords, blockRecordKey{chainId: chainId, number: blockNumber})
	return nil
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

	// Copy master public key
	var masterPublicKeyCopy *types.G2Point
	if v.MasterPublicKey != nil {
		compressedCopy := make([]byte, len(v.MasterPublicKey.CompressedBytes))
		copy(compressedCopy, v.MasterPublicKey.CompressedBytes)
		masterPublicKeyCopy = &types.G2Point{CompressedBytes: compressedCopy}
	}

	// Copy participant IDs
	participantIDs := make([]common.Address, len(v.ParticipantIDs))
	copy(participantIDs, v.ParticipantIDs)

	return &types.KeyShareVersion{
		Version:         v.Version,
		PrivateShare:    privateShareCopy,
		Commitments:     commitments,
		MasterPublicKey: masterPublicKeyCopy,
		IsActive:        v.IsActive,
		ParticipantIDs:  participantIDs,
	}
}

func deepCopyBlockRecord(r *persistence.BlockRecord) *persistence.BlockRecord {
	if r == nil {
		return nil
	}
	// BlockRecord contains only value-type fields, so a struct copy suffices.
	cp := *r
	return &cp
}

func deepCopyProtocolSessionState(s *persistence.ProtocolSessionState) *persistence.ProtocolSessionState {
	if s == nil {
		return nil
	}

	// Copy operator addresses
	operatorAddresses := make([]string, len(s.OperatorAddresses))
	copy(operatorAddresses, s.OperatorAddresses)

	// Copy shares map
	shares := make(map[string]string)
	for k, v := range s.Shares {
		shares[k] = v
	}

	// Copy commitments map
	commitments := make(map[string][]types.G2Point)
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
	acknowledgements := make(map[string]map[string]*types.Acknowledgement)
	for dealerAddr, ackMap := range s.Acknowledgements {
		ackMapCopy := make(map[string]*types.Acknowledgement)
		for receiverAddr, ack := range ackMap {
			ackCopy := &types.Acknowledgement{
				PlayerAddress:    ack.PlayerAddress,
				DealerAddress:    ack.DealerAddress,
				SessionTimestamp: ack.SessionTimestamp,
				ShareHash:        ack.ShareHash,      // [32]byte is copied by value
				CommitmentHash:   ack.CommitmentHash, // [32]byte is copied by value
			}
			if len(ack.Signature) > 0 {
				signatureCopy := make([]byte, len(ack.Signature))
				copy(signatureCopy, ack.Signature)
				ackCopy.Signature = signatureCopy
			}
			ackMapCopy[receiverAddr] = ackCopy
		}
		acknowledgements[dealerAddr] = ackMapCopy
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
