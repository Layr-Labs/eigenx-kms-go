package badger

import (
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	badgerdb "github.com/dgraph-io/badger/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeRawBytes bypasses the typed Save* methods and writes raw bytes to a
// badger key. Used to simulate corrupt storage for null-rejection tests.
func writeRawBytes(t *testing.T, bp *BadgerPersistence, key string, value []byte) {
	t.Helper()
	err := bp.db.Update(func(txn *badgerdb.Txn) error {
		return txn.Set([]byte(key), value)
	})
	require.NoError(t, err)
}

func TestBadgerPersistence_SaveAndLoadKeyShare(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	// Create a sample key share version
	privateShare := fr.NewElement(uint64(12345))
	version := &types.KeyShareVersion{
		Version:      1234567890,
		PrivateShare: &privateShare,
		Commitments: []types.G2Point{
			{CompressedBytes: []byte{1, 2, 3, 4}},
		},
		IsActive:       true,
		ParticipantIDs: []int64{1, 2, 3},
	}

	// Save
	err = bp.SaveKeyShareVersion(version)
	require.NoError(t, err)

	// Load
	loaded, err := bp.LoadKeyShareVersion(version.Version)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Verify
	assert.Equal(t, version.Version, loaded.Version)
	assert.Equal(t, version.IsActive, loaded.IsActive)
	assert.Equal(t, version.ParticipantIDs, loaded.ParticipantIDs)
	assert.True(t, version.PrivateShare.Equal(loaded.PrivateShare))
}

func TestBadgerPersistence_LoadKeyShare_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	loaded, err := bp.LoadKeyShareVersion(9999999)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestBadgerPersistence_SaveKeyShare_Nil(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	err = bp.SaveKeyShareVersion(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil KeyShareVersion")
}

func TestBadgerPersistence_DeleteKeyShare(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	// Create and save a key share
	privateShare := fr.NewElement(uint64(111))
	version := &types.KeyShareVersion{
		Version:        111,
		PrivateShare:   &privateShare,
		Commitments:    []types.G2Point{},
		IsActive:       true,
		ParticipantIDs: []int64{1},
	}
	err = bp.SaveKeyShareVersion(version)
	require.NoError(t, err)

	// Verify it exists
	loaded, err := bp.LoadKeyShareVersion(111)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Delete
	err = bp.DeleteKeyShareVersion(111)
	require.NoError(t, err)

	// Verify it's gone
	loaded, err = bp.LoadKeyShareVersion(111)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestBadgerPersistence_DeleteKeyShare_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	// Delete non-existent key (should not error)
	err = bp.DeleteKeyShareVersion(9999)
	require.NoError(t, err)
}

func TestBadgerPersistence_ListKeyShareVersions(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	// Create multiple versions
	for i := 0; i < 5; i++ {
		privateShare := fr.NewElement(uint64(i))
		version := &types.KeyShareVersion{
			Version:        int64(i * 100),
			PrivateShare:   &privateShare,
			Commitments:    []types.G2Point{},
			IsActive:       i == 4,
			ParticipantIDs: []int64{int64(i)},
		}
		err := bp.SaveKeyShareVersion(version)
		require.NoError(t, err)
	}

	// List
	listed, err := bp.ListKeyShareVersions()
	require.NoError(t, err)
	assert.Len(t, listed, 5)

	// Verify sorted by epoch
	for i := 0; i < len(listed)-1; i++ {
		assert.Less(t, listed[i].Version, listed[i+1].Version)
	}
}

func TestBadgerPersistence_ListKeyShareVersions_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	listed, err := bp.ListKeyShareVersions()
	require.NoError(t, err)
	assert.Empty(t, listed)
}

func TestBadgerPersistence_ActiveVersionTracking(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	// Initially no active version
	epoch, err := bp.GetActiveVersionTimestamp()
	require.NoError(t, err)
	assert.Equal(t, int64(0), epoch)

	// Set active version
	err = bp.SetActiveVersionTimestamp(1234567890)
	require.NoError(t, err)

	// Get active version
	epoch, err = bp.GetActiveVersionTimestamp()
	require.NoError(t, err)
	assert.Equal(t, int64(1234567890), epoch)

	// Update active version
	err = bp.SetActiveVersionTimestamp(9876543210)
	require.NoError(t, err)

	epoch, err = bp.GetActiveVersionTimestamp()
	require.NoError(t, err)
	assert.Equal(t, int64(9876543210), epoch)
}

func TestBadgerPersistence_NodeState(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	// Initially no state (first run)
	state, err := bp.LoadNodeState()
	require.NoError(t, err)
	assert.Nil(t, state)

	// Save state
	newState := &persistence.NodeState{
		LastProcessedBoundary: 12345,
		NodeStartTime:         9876543210,
		OperatorAddress:       "0x1234567890abcdef",
	}
	err = bp.SaveNodeState(newState)
	require.NoError(t, err)

	// Load state
	loaded, err := bp.LoadNodeState()
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, newState.LastProcessedBoundary, loaded.LastProcessedBoundary)
	assert.Equal(t, newState.NodeStartTime, loaded.NodeStartTime)
	assert.Equal(t, newState.OperatorAddress, loaded.OperatorAddress)
}

func TestBadgerPersistence_NodeState_Nil(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	err = bp.SaveNodeState(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil NodeState")
}

func TestBadgerPersistence_ProtocolSessions(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	// Create a session
	session := &persistence.ProtocolSessionState{
		SessionTimestamp:  1234567890,
		Type:              "dkg",
		Phase:             2,
		StartTime:         1234567800,
		OperatorAddresses: []string{"0x1234", "0x5678"},
		Shares: map[int64]string{
			1: "share1",
			2: "share2",
		},
		Commitments: map[int64][]types.G2Point{
			1: {{CompressedBytes: []byte{1, 2, 3}}},
		},
		Acknowledgements: map[int64]map[int64]*types.Acknowledgement{
			1: {
				2: {PlayerAddress: common.BigToAddress(big.NewInt(2)), DealerAddress: common.BigToAddress(big.NewInt(1)), SessionTimestamp: 1234567890},
			},
		},
	}

	// Save
	err = bp.SaveProtocolSession(session)
	require.NoError(t, err)

	// Load
	loaded, err := bp.LoadProtocolSession(session.SessionTimestamp)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, session.SessionTimestamp, loaded.SessionTimestamp)
	assert.Equal(t, session.Type, loaded.Type)
	assert.Equal(t, session.Phase, loaded.Phase)
	assert.Equal(t, session.StartTime, loaded.StartTime)
	assert.Equal(t, session.OperatorAddresses, loaded.OperatorAddresses)
	assert.Equal(t, session.Shares, loaded.Shares)
}

func TestBadgerPersistence_LoadProtocolSession_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	loaded, err := bp.LoadProtocolSession(9999999)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestBadgerPersistence_SaveProtocolSession_Nil(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	err = bp.SaveProtocolSession(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil ProtocolSessionState")
}

func TestBadgerPersistence_DeleteProtocolSession(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	// Create and save a session
	session := &persistence.ProtocolSessionState{
		SessionTimestamp:  111,
		Type:              "reshare",
		Phase:             1,
		StartTime:         100,
		OperatorAddresses: []string{"0x1"},
		Shares:            map[int64]string{},
		Commitments:       map[int64][]types.G2Point{},
		Acknowledgements:  map[int64]map[int64]*types.Acknowledgement{},
	}
	err = bp.SaveProtocolSession(session)
	require.NoError(t, err)

	// Delete
	err = bp.DeleteProtocolSession(111)
	require.NoError(t, err)

	// Verify it's gone
	loaded, err := bp.LoadProtocolSession(111)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestBadgerPersistence_ListProtocolSessions(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	// Create multiple sessions
	for i := 0; i < 3; i++ {
		session := &persistence.ProtocolSessionState{
			SessionTimestamp:  int64(i * 100),
			Type:              "dkg",
			Phase:             1,
			StartTime:         int64(i * 100),
			OperatorAddresses: []string{},
			Shares:            map[int64]string{},
			Commitments:       map[int64][]types.G2Point{},
			Acknowledgements:  map[int64]map[int64]*types.Acknowledgement{},
		}
		err := bp.SaveProtocolSession(session)
		require.NoError(t, err)
	}

	// List
	listed, err := bp.ListProtocolSessions()
	require.NoError(t, err)
	assert.Len(t, listed, 3)
}

func TestBadgerPersistence_ListProtocolSessions_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	listed, err := bp.ListProtocolSessions()
	require.NoError(t, err)
	assert.Empty(t, listed)
}

func TestBadgerPersistence_Close(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)

	err = bp.Close()
	require.NoError(t, err)

	// Operations after close should fail
	err = bp.SaveKeyShareVersion(&types.KeyShareVersion{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")

	_, err = bp.LoadKeyShareVersion(123)
	require.Error(t, err)

	err = bp.SaveNodeState(&persistence.NodeState{})
	require.Error(t, err)
}

func TestBadgerPersistence_Close_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)

	err = bp.Close()
	require.NoError(t, err)

	// Second close should also succeed
	err = bp.Close()
	require.NoError(t, err)
}

func TestBadgerPersistence_HealthCheck(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	err = bp.HealthCheck()
	require.NoError(t, err)

	// Health check after close should fail
	err = bp.Close()
	require.NoError(t, err)
	err = bp.HealthCheck()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestBadgerPersistence_ThreadSafety(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				privateShare := fr.NewElement(uint64(id*1000 + j))
				version := &types.KeyShareVersion{
					Version:        int64(id*1000 + j),
					PrivateShare:   &privateShare,
					Commitments:    []types.G2Point{},
					IsActive:       false,
					ParticipantIDs: []int64{int64(id)},
				}
				err := bp.SaveKeyShareVersion(version)
				assert.NoError(t, err)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				_, err := bp.LoadKeyShareVersion(int64(id*1000 + j))
				assert.NoError(t, err)
			}
		}(i)
	}

	// Concurrent lists
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				_, err := bp.ListKeyShareVersions()
				assert.NoError(t, err)
			}
		}()
	}

	wg.Wait()
}

func TestBadgerPersistence_Persistence_AcrossRestarts(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	// First instance - save data
	bp1, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)

	privateShare := fr.NewElement(uint64(99999))
	version := &types.KeyShareVersion{
		Version:        99999,
		PrivateShare:   &privateShare,
		Commitments:    []types.G2Point{{CompressedBytes: []byte{9, 9, 9}}},
		IsActive:       true,
		ParticipantIDs: []int64{1, 2, 3},
	}
	err = bp1.SaveKeyShareVersion(version)
	require.NoError(t, err)

	err = bp1.SetActiveVersionTimestamp(99999)
	require.NoError(t, err)

	nodeState := &persistence.NodeState{
		LastProcessedBoundary: 54321,
		NodeStartTime:         1234567890,
		OperatorAddress:       "0xabcdef",
	}
	err = bp1.SaveNodeState(nodeState)
	require.NoError(t, err)

	// Close first instance
	err = bp1.Close()
	require.NoError(t, err)

	// Second instance - verify data persisted
	bp2, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp2.Close() }()

	// Verify key share
	loadedVersion, err := bp2.LoadKeyShareVersion(99999)
	require.NoError(t, err)
	require.NotNil(t, loadedVersion)
	assert.Equal(t, version.Version, loadedVersion.Version)
	assert.True(t, version.PrivateShare.Equal(loadedVersion.PrivateShare))

	// Verify active version
	activeTimestamp, err := bp2.GetActiveVersionTimestamp()
	require.NoError(t, err)
	assert.Equal(t, int64(99999), activeTimestamp)

	// Verify node state
	loadedState, err := bp2.LoadNodeState()
	require.NoError(t, err)
	require.NotNil(t, loadedState)
	assert.Equal(t, nodeState.LastProcessedBoundary, loadedState.LastProcessedBoundary)
	assert.Equal(t, nodeState.OperatorAddress, loadedState.OperatorAddress)
}

// TestBadgerPersistence_LoadKeyShareVersion_NullJSON verifies that a stored
// JSON null literal is rejected with an explicit error rather than silently
// returning (nil, nil) — which would be indistinguishable from "not found".
func TestBadgerPersistence_LoadKeyShareVersion_NullJSON(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	const timestamp int64 = 1234567890
	writeRawBytes(t, bp, fmt.Sprintf("%s%d", keyPrefixKeyShare, timestamp), []byte("null"))

	loaded, err := bp.LoadKeyShareVersion(timestamp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JSON null")
	assert.Nil(t, loaded)
}

// TestBadgerPersistence_LoadNodeState_NullJSON verifies the same guard for
// the NodeState singleton.
func TestBadgerPersistence_LoadNodeState_NullJSON(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	writeRawBytes(t, bp, keyPrefixNodeState, []byte("null"))

	loaded, err := bp.LoadNodeState()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JSON null")
	assert.Nil(t, loaded)
}

// TestBadgerPersistence_LoadProtocolSession_NullJSON verifies the same guard
// for protocol session state.
func TestBadgerPersistence_LoadProtocolSession_NullJSON(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	const sessionTimestamp int64 = 1234567890
	writeRawBytes(t, bp, fmt.Sprintf("%s%d", keyPrefixSession, sessionTimestamp), []byte("null"))

	loaded, err := bp.LoadProtocolSession(sessionTimestamp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JSON null")
	assert.Nil(t, loaded)
}

// TestBadgerPersistence_ListKeyShareVersions_SkipsNull verifies that null
// entries are skipped with a warning rather than surfacing as nil *types.
func TestBadgerPersistence_ListKeyShareVersions_SkipsNull(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	// Store one valid version and one null entry.
	privateShare := fr.NewElement(uint64(42))
	valid := &types.KeyShareVersion{
		Version:      1000,
		PrivateShare: &privateShare,
		Commitments:  []types.G2Point{{CompressedBytes: []byte{1, 2, 3}}},
	}
	require.NoError(t, bp.SaveKeyShareVersion(valid))
	writeRawBytes(t, bp, fmt.Sprintf("%s%d", keyPrefixKeyShare, 2000), []byte("null"))

	versions, err := bp.ListKeyShareVersions()
	require.NoError(t, err)
	require.Len(t, versions, 1)
	assert.Equal(t, int64(1000), versions[0].Version)
}

// TestBadgerPersistence_ListProtocolSessions_SkipsNull verifies the same
// skip-with-warning behavior for protocol sessions.
func TestBadgerPersistence_ListProtocolSessions_SkipsNull(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bp, err := NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = bp.Close() }()

	valid := &persistence.ProtocolSessionState{
		SessionTimestamp: 1000,
		Type:             "dkg",
		Phase:            1,
	}
	require.NoError(t, bp.SaveProtocolSession(valid))
	writeRawBytes(t, bp, fmt.Sprintf("%s%d", keyPrefixSession, 2000), []byte("null"))

	sessions, err := bp.ListProtocolSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, int64(1000), sessions[0].SessionTimestamp)
}
