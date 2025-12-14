package memory

import (
	"sync"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryPersistence_SaveAndLoadKeyShare(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

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
	err := mp.SaveKeyShareVersion(version)
	require.NoError(t, err)

	// Load
	loaded, err := mp.LoadKeyShareVersion(version.Version)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Verify
	assert.Equal(t, version.Version, loaded.Version)
	assert.Equal(t, version.IsActive, loaded.IsActive)
	assert.Equal(t, version.ParticipantIDs, loaded.ParticipantIDs)

	// Verify private share (using serialization for comparison)
	originalSerialized := types.SerializeFr(version.PrivateShare)
	loadedSerialized := types.SerializeFr(loaded.PrivateShare)
	assert.Equal(t, originalSerialized.Data, loadedSerialized.Data)
}

func TestMemoryPersistence_LoadKeyShare_NotFound(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	loaded, err := mp.LoadKeyShareVersion(9999999)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestMemoryPersistence_SaveKeyShare_Nil(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	err := mp.SaveKeyShareVersion(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil KeyShareVersion")
}

func TestMemoryPersistence_DeleteKeyShare(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	// Create and save a key share
	privateShare := fr.NewElement(uint64(111))
	version := &types.KeyShareVersion{
		Version:        111,
		PrivateShare:   &privateShare,
		Commitments:    []types.G2Point{},
		IsActive:       true,
		ParticipantIDs: []int64{1},
	}
	err := mp.SaveKeyShareVersion(version)
	require.NoError(t, err)

	// Verify it exists
	loaded, err := mp.LoadKeyShareVersion(111)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Delete
	err = mp.DeleteKeyShareVersion(111)
	require.NoError(t, err)

	// Verify it's gone
	loaded, err = mp.LoadKeyShareVersion(111)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestMemoryPersistence_DeleteKeyShare_Idempotent(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	// Delete non-existent key (should not error)
	err := mp.DeleteKeyShareVersion(9999)
	require.NoError(t, err)
}

func TestMemoryPersistence_ListKeyShareVersions(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

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
		err := mp.SaveKeyShareVersion(version)
		require.NoError(t, err)
	}

	// List
	listed, err := mp.ListKeyShareVersions()
	require.NoError(t, err)
	assert.Len(t, listed, 5)

	// Verify sorted by epoch
	for i := 0; i < len(listed)-1; i++ {
		assert.Less(t, listed[i].Version, listed[i+1].Version)
	}
}

func TestMemoryPersistence_ListKeyShareVersions_Empty(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	listed, err := mp.ListKeyShareVersions()
	require.NoError(t, err)
	assert.Empty(t, listed)
}

func TestMemoryPersistence_ActiveVersionTracking(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	// Initially no active version
	epoch, err := mp.GetActiveVersionEpoch()
	require.NoError(t, err)
	assert.Equal(t, int64(0), epoch)

	// Set active version
	err = mp.SetActiveVersionEpoch(1234567890)
	require.NoError(t, err)

	// Get active version
	epoch, err = mp.GetActiveVersionEpoch()
	require.NoError(t, err)
	assert.Equal(t, int64(1234567890), epoch)

	// Update active version
	err = mp.SetActiveVersionEpoch(9876543210)
	require.NoError(t, err)

	epoch, err = mp.GetActiveVersionEpoch()
	require.NoError(t, err)
	assert.Equal(t, int64(9876543210), epoch)
}

func TestMemoryPersistence_NodeState(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	// Initially no state (first run)
	state, err := mp.LoadNodeState()
	require.NoError(t, err)
	assert.Nil(t, state)

	// Save state
	newState := &persistence.NodeState{
		LastProcessedBoundary: 12345,
		NodeStartTime:         9876543210,
		OperatorAddress:       "0x1234567890abcdef",
	}
	err = mp.SaveNodeState(newState)
	require.NoError(t, err)

	// Load state
	loaded, err := mp.LoadNodeState()
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, newState.LastProcessedBoundary, loaded.LastProcessedBoundary)
	assert.Equal(t, newState.NodeStartTime, loaded.NodeStartTime)
	assert.Equal(t, newState.OperatorAddress, loaded.OperatorAddress)
}

func TestMemoryPersistence_NodeState_Nil(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	err := mp.SaveNodeState(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil NodeState")
}

func TestMemoryPersistence_ProtocolSessions(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

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
				2: {PlayerID: 2, DealerID: 1, Epoch: 1234567890},
			},
		},
	}

	// Save
	err := mp.SaveProtocolSession(session)
	require.NoError(t, err)

	// Load
	loaded, err := mp.LoadProtocolSession(session.SessionTimestamp)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, session.SessionTimestamp, loaded.SessionTimestamp)
	assert.Equal(t, session.Type, loaded.Type)
	assert.Equal(t, session.Phase, loaded.Phase)
	assert.Equal(t, session.StartTime, loaded.StartTime)
	assert.Equal(t, session.OperatorAddresses, loaded.OperatorAddresses)
	assert.Equal(t, session.Shares, loaded.Shares)
}

func TestMemoryPersistence_LoadProtocolSession_NotFound(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	loaded, err := mp.LoadProtocolSession(9999999)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestMemoryPersistence_SaveProtocolSession_Nil(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	err := mp.SaveProtocolSession(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil ProtocolSessionState")
}

func TestMemoryPersistence_DeleteProtocolSession(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

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
	err := mp.SaveProtocolSession(session)
	require.NoError(t, err)

	// Delete
	err = mp.DeleteProtocolSession(111)
	require.NoError(t, err)

	// Verify it's gone
	loaded, err := mp.LoadProtocolSession(111)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestMemoryPersistence_ListProtocolSessions(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

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
		err := mp.SaveProtocolSession(session)
		require.NoError(t, err)
	}

	// List
	listed, err := mp.ListProtocolSessions()
	require.NoError(t, err)
	assert.Len(t, listed, 3)
}

func TestMemoryPersistence_ListProtocolSessions_Empty(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	listed, err := mp.ListProtocolSessions()
	require.NoError(t, err)
	assert.Empty(t, listed)
}

func TestMemoryPersistence_Close(t *testing.T) {
	mp := NewMemoryPersistence()

	err := mp.Close()
	require.NoError(t, err)

	// Operations after close should fail
	err = mp.SaveKeyShareVersion(&types.KeyShareVersion{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")

	_, err = mp.LoadKeyShareVersion(123)
	require.Error(t, err)

	err = mp.SaveNodeState(&persistence.NodeState{})
	require.Error(t, err)
}

func TestMemoryPersistence_Close_Idempotent(t *testing.T) {
	mp := NewMemoryPersistence()

	err := mp.Close()
	require.NoError(t, err)

	// Second close should also succeed
	err = mp.Close()
	require.NoError(t, err)
}

func TestMemoryPersistence_HealthCheck(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	err := mp.HealthCheck()
	require.NoError(t, err)

	// Health check after close should fail
	err = mp.Close()
	require.NoError(t, err)
	err = mp.HealthCheck()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestMemoryPersistence_ThreadSafety(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

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
				err := mp.SaveKeyShareVersion(version)
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
				_, err := mp.LoadKeyShareVersion(int64(id*1000 + j))
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
				_, err := mp.ListKeyShareVersions()
				assert.NoError(t, err)
			}
		}()
	}

	wg.Wait()
}

func TestMemoryPersistence_DeepCopy_Mutation(t *testing.T) {
	mp := NewMemoryPersistence()
	defer func() { _ = mp.Close() }()

	// Create and save a key share
	privateShare := fr.NewElement(uint64(123))
	version := &types.KeyShareVersion{
		Version:        123,
		PrivateShare:   &privateShare,
		Commitments:    []types.G2Point{{CompressedBytes: []byte{1, 2, 3}}},
		IsActive:       true,
		ParticipantIDs: []int64{1, 2, 3},
	}
	err := mp.SaveKeyShareVersion(version)
	require.NoError(t, err)

	// Load and mutate
	loaded, err := mp.LoadKeyShareVersion(123)
	require.NoError(t, err)
	loaded.IsActive = false
	loaded.ParticipantIDs[0] = 999
	loaded.Commitments[0].CompressedBytes[0] = 255

	// Load again and verify original is unchanged
	loaded2, err := mp.LoadKeyShareVersion(123)
	require.NoError(t, err)
	assert.True(t, loaded2.IsActive)
	assert.Equal(t, int64(1), loaded2.ParticipantIDs[0])
	assert.Equal(t, byte(1), loaded2.Commitments[0].CompressedBytes[0])
}
