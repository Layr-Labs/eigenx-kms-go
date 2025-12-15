package redis

import (
	"os"
	"sync"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getTestRedisAddress returns the Redis address for testing.
// Uses REDIS_TEST_ADDRESS env var if set, otherwise defaults to localhost:6379.
func getTestRedisAddress() string {
	if addr := os.Getenv("REDIS_TEST_ADDRESS"); addr != "" {
		return addr
	}
	return "localhost:6379"
}

// requireRedis fails the test if Redis is not available
func requireRedis(t *testing.T) *RedisPersistence {
	t.Helper()

	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	cfg := &RedisConfig{
		Address: getTestRedisAddress(),
		DB:      15, // Use DB 15 for tests to avoid conflicts
	}

	rp, err := NewRedisPersistence(cfg, testLogger)
	if err != nil {
		t.Fatalf("Redis not available at %s: %v", cfg.Address, err)
		return nil
	}

	return rp
}

// cleanupRedis clears all test keys from Redis
func cleanupRedis(t *testing.T, rp *RedisPersistence) {
	t.Helper()
	// Note: We're using DB 15 which is dedicated for tests
	// In a real scenario, you might want to FLUSHDB but that's risky
	// For now, we rely on test isolation by using unique epochs
}

func TestRedisPersistence_SaveAndLoadKeyShare(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()
	defer cleanupRedis(t, rp)

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
	err := rp.SaveKeyShareVersion(version)
	require.NoError(t, err)

	// Load
	loaded, err := rp.LoadKeyShareVersion(version.Version)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Verify
	assert.Equal(t, version.Version, loaded.Version)
	assert.Equal(t, version.IsActive, loaded.IsActive)
	assert.Equal(t, version.ParticipantIDs, loaded.ParticipantIDs)
	assert.True(t, version.PrivateShare.Equal(loaded.PrivateShare))

	// Cleanup
	_ = rp.DeleteKeyShareVersion(version.Version)
}

func TestRedisPersistence_LoadKeyShare_NotFound(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	loaded, err := rp.LoadKeyShareVersion(9999999)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestRedisPersistence_SaveKeyShare_Nil(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	err := rp.SaveKeyShareVersion(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil KeyShareVersion")
}

func TestRedisPersistence_DeleteKeyShare(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	// Create and save a key share
	privateShare := fr.NewElement(uint64(111))
	version := &types.KeyShareVersion{
		Version:        111222333,
		PrivateShare:   &privateShare,
		Commitments:    []types.G2Point{},
		IsActive:       true,
		ParticipantIDs: []int64{1},
	}
	err := rp.SaveKeyShareVersion(version)
	require.NoError(t, err)

	// Verify it exists
	loaded, err := rp.LoadKeyShareVersion(111222333)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Delete
	err = rp.DeleteKeyShareVersion(111222333)
	require.NoError(t, err)

	// Verify it's gone
	loaded, err = rp.LoadKeyShareVersion(111222333)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestRedisPersistence_DeleteKeyShare_Idempotent(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	// Delete non-existent key (should not error)
	err := rp.DeleteKeyShareVersion(9999888777)
	require.NoError(t, err)
}

func TestRedisPersistence_ListKeyShareVersions(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	// Create multiple versions with unique epochs
	baseEpoch := int64(2000000000)
	for i := 0; i < 5; i++ {
		privateShare := fr.NewElement(uint64(i))
		version := &types.KeyShareVersion{
			Version:        baseEpoch + int64(i*100),
			PrivateShare:   &privateShare,
			Commitments:    []types.G2Point{},
			IsActive:       i == 4,
			ParticipantIDs: []int64{int64(i)},
		}
		err := rp.SaveKeyShareVersion(version)
		require.NoError(t, err)
	}

	// Cleanup deferred
	defer func() {
		for i := 0; i < 5; i++ {
			_ = rp.DeleteKeyShareVersion(baseEpoch + int64(i*100))
		}
	}()

	// List
	listed, err := rp.ListKeyShareVersions()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(listed), 5)

	// Find our test versions and verify they're sorted
	var foundVersions []int64
	for _, v := range listed {
		if v.Version >= baseEpoch && v.Version < baseEpoch+500 {
			foundVersions = append(foundVersions, v.Version)
		}
	}
	assert.Len(t, foundVersions, 5)

	// Verify sorted by epoch
	for i := 0; i < len(foundVersions)-1; i++ {
		assert.Less(t, foundVersions[i], foundVersions[i+1])
	}
}

func TestRedisPersistence_ActiveVersionTracking(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	// Set active version
	err := rp.SetActiveVersionEpoch(1234567890)
	require.NoError(t, err)

	// Get active version
	epoch, err := rp.GetActiveVersionEpoch()
	require.NoError(t, err)
	assert.Equal(t, int64(1234567890), epoch)

	// Update active version
	err = rp.SetActiveVersionEpoch(9876543210)
	require.NoError(t, err)

	epoch, err = rp.GetActiveVersionEpoch()
	require.NoError(t, err)
	assert.Equal(t, int64(9876543210), epoch)
}

func TestRedisPersistence_NodeState(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	// Save state
	newState := &persistence.NodeState{
		LastProcessedBoundary: 12345,
		NodeStartTime:         9876543210,
		OperatorAddress:       "0x1234567890abcdef",
	}
	err := rp.SaveNodeState(newState)
	require.NoError(t, err)

	// Load state
	loaded, err := rp.LoadNodeState()
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, newState.LastProcessedBoundary, loaded.LastProcessedBoundary)
	assert.Equal(t, newState.NodeStartTime, loaded.NodeStartTime)
	assert.Equal(t, newState.OperatorAddress, loaded.OperatorAddress)
}

func TestRedisPersistence_NodeState_Nil(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	err := rp.SaveNodeState(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil NodeState")
}

func TestRedisPersistence_ProtocolSessions(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	sessionTS := int64(3000000001)

	// Create a session
	session := &persistence.ProtocolSessionState{
		SessionTimestamp:  sessionTS,
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
				2: {PlayerID: 2, DealerID: 1, Epoch: sessionTS},
			},
		},
	}

	// Cleanup deferred
	defer func() {
		_ = rp.DeleteProtocolSession(sessionTS)
	}()

	// Save
	err := rp.SaveProtocolSession(session)
	require.NoError(t, err)

	// Load
	loaded, err := rp.LoadProtocolSession(session.SessionTimestamp)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, session.SessionTimestamp, loaded.SessionTimestamp)
	assert.Equal(t, session.Type, loaded.Type)
	assert.Equal(t, session.Phase, loaded.Phase)
	assert.Equal(t, session.StartTime, loaded.StartTime)
	assert.Equal(t, session.OperatorAddresses, loaded.OperatorAddresses)
	assert.Equal(t, session.Shares, loaded.Shares)
}

func TestRedisPersistence_LoadProtocolSession_NotFound(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	loaded, err := rp.LoadProtocolSession(9999999999)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestRedisPersistence_SaveProtocolSession_Nil(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	err := rp.SaveProtocolSession(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil ProtocolSessionState")
}

func TestRedisPersistence_DeleteProtocolSession(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	sessionTS := int64(3000000002)

	// Create and save a session
	session := &persistence.ProtocolSessionState{
		SessionTimestamp:  sessionTS,
		Type:              "reshare",
		Phase:             1,
		StartTime:         100,
		OperatorAddresses: []string{"0x1"},
		Shares:            map[int64]string{},
		Commitments:       map[int64][]types.G2Point{},
		Acknowledgements:  map[int64]map[int64]*types.Acknowledgement{},
	}
	err := rp.SaveProtocolSession(session)
	require.NoError(t, err)

	// Delete
	err = rp.DeleteProtocolSession(sessionTS)
	require.NoError(t, err)

	// Verify it's gone
	loaded, err := rp.LoadProtocolSession(sessionTS)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestRedisPersistence_ListProtocolSessions(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	baseTS := int64(4000000000)

	// Create multiple sessions
	for i := 0; i < 3; i++ {
		session := &persistence.ProtocolSessionState{
			SessionTimestamp:  baseTS + int64(i*100),
			Type:              "dkg",
			Phase:             1,
			StartTime:         baseTS + int64(i*100),
			OperatorAddresses: []string{},
			Shares:            map[int64]string{},
			Commitments:       map[int64][]types.G2Point{},
			Acknowledgements:  map[int64]map[int64]*types.Acknowledgement{},
		}
		err := rp.SaveProtocolSession(session)
		require.NoError(t, err)
	}

	// Cleanup deferred
	defer func() {
		for i := 0; i < 3; i++ {
			_ = rp.DeleteProtocolSession(baseTS + int64(i*100))
		}
	}()

	// List
	listed, err := rp.ListProtocolSessions()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(listed), 3)
}

func TestRedisPersistence_Close(t *testing.T) {
	rp := requireRedis(t)

	err := rp.Close()
	require.NoError(t, err)

	// Operations after close should fail
	err = rp.SaveKeyShareVersion(&types.KeyShareVersion{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")

	_, err = rp.LoadKeyShareVersion(123)
	require.Error(t, err)

	err = rp.SaveNodeState(&persistence.NodeState{})
	require.Error(t, err)
}

func TestRedisPersistence_Close_Idempotent(t *testing.T) {
	rp := requireRedis(t)

	err := rp.Close()
	require.NoError(t, err)

	// Second close should also succeed
	err = rp.Close()
	require.NoError(t, err)
}

func TestRedisPersistence_HealthCheck(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	err := rp.HealthCheck()
	require.NoError(t, err)
}

func TestRedisPersistence_HealthCheck_AfterClose(t *testing.T) {
	rp := requireRedis(t)

	err := rp.Close()
	require.NoError(t, err)

	err = rp.HealthCheck()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestRedisPersistence_ThreadSafety(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 50
	baseEpoch := int64(5000000000)

	// Cleanup deferred
	defer func() {
		for i := 0; i < numGoroutines; i++ {
			for j := 0; j < numOperations; j++ {
				_ = rp.DeleteKeyShareVersion(baseEpoch + int64(i*1000+j))
			}
		}
	}()

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				privateShare := fr.NewElement(uint64(id*1000 + j))
				version := &types.KeyShareVersion{
					Version:        baseEpoch + int64(id*1000+j),
					PrivateShare:   &privateShare,
					Commitments:    []types.G2Point{},
					IsActive:       false,
					ParticipantIDs: []int64{int64(id)},
				}
				err := rp.SaveKeyShareVersion(version)
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
				_, err := rp.LoadKeyShareVersion(baseEpoch + int64(id*1000+j))
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
				_, err := rp.ListKeyShareVersions()
				assert.NoError(t, err)
			}
		}()
	}

	wg.Wait()
}

func TestRedisPersistence_Config_Nil(t *testing.T) {
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	_, err := NewRedisPersistence(nil, testLogger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestRedisPersistence_Config_EmptyAddress(t *testing.T) {
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	cfg := &RedisConfig{
		Address: "",
	}

	_, err := NewRedisPersistence(cfg, testLogger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}
