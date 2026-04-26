package redis

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// testRedisAddress holds the host:port of the Redis instance used by tests.
// It is set once by TestMain, either from a user-provided REDIS_TEST_ADDRESS
// env var (useful in CI environments that already run Redis) or from a
// testcontainers-managed Redis container started for the duration of the
// package's tests.
var testRedisAddress string

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

// runTests is split out from TestMain so defers execute even when a test
// panics or calls os.Exit indirectly.
func runTests(m *testing.M) int {
	if addr := os.Getenv("REDIS_TEST_ADDRESS"); addr != "" {
		testRedisAddress = addr
		return m.Run()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	container, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		log.Printf("skipping redis tests: failed to start redis container (is Docker running?): %v", err)
		return 0
	}
	defer func() {
		// Use a fresh context because ctx may already be done.
		termCtx, termCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer termCancel()
		if err := container.Terminate(termCtx); err != nil {
			log.Printf("failed to terminate redis container: %v", err)
		}
	}()

	connStr, err := container.ConnectionString(ctx)
	if err != nil {
		log.Printf("skipping redis tests: failed to get redis connection string: %v", err)
		return 0
	}
	addr, err := hostPortFromRedisURL(connStr)
	if err != nil {
		log.Printf("skipping redis tests: %v", err)
		return 0
	}
	testRedisAddress = addr
	return m.Run()
}

// hostPortFromRedisURL extracts the host:port from a redis://host:port URL.
func hostPortFromRedisURL(redisURL string) (string, error) {
	u, err := url.Parse(redisURL)
	if err != nil {
		return "", fmt.Errorf("parse redis url %q: %w", redisURL, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("redis url %q has no host", redisURL)
	}
	return u.Host, nil
}

// requireRedis returns a fresh RedisPersistence connected to the shared test
// Redis instance. Tests that call this must ensure TestMain has succeeded in
// provisioning Redis; if it hasn't, testRedisAddress is empty and the test
// is skipped rather than failing spuriously.
func requireRedis(t *testing.T) *RedisPersistence {
	t.Helper()

	if testRedisAddress == "" {
		t.Skip("redis not available for tests (Docker required; or set REDIS_TEST_ADDRESS)")
	}

	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	cfg := &RedisConfig{
		Address: testRedisAddress,
		DB:      15, // Use DB 15 for tests to avoid conflicts
	}

	rp, err := NewRedisPersistence(cfg, testLogger)
	if err != nil {
		t.Fatalf("Redis not available at %s: %v", cfg.Address, err)
		return nil
	}

	return rp
}

func TestRedisPersistence_SaveAndLoadKeyShare(t *testing.T) {
	rp := requireRedis(t)
	defer func() { _ = rp.Close() }()

	// Create a sample key share version
	privateShare := fr.NewElement(uint64(12345))
	version := &types.KeyShareVersion{
		Version:      1234567890,
		PrivateShare: &privateShare,
		Commitments: []types.G2Point{
			{CompressedBytes: []byte{1, 2, 3, 4}},
		},
		IsActive:       true,
		ParticipantIDs: []common.Address{common.HexToAddress("0x01"), common.HexToAddress("0x02"), common.HexToAddress("0x03")},
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
		ParticipantIDs: []common.Address{common.HexToAddress("0x01")},
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
			ParticipantIDs: []common.Address{common.HexToAddress(fmt.Sprintf("0x%040x", i))},
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
	err := rp.SetActiveVersionTimestamp(1234567890)
	require.NoError(t, err)

	// Get active version
	epoch, err := rp.GetActiveVersionTimestamp()
	require.NoError(t, err)
	assert.Equal(t, int64(1234567890), epoch)

	// Update active version
	err = rp.SetActiveVersionTimestamp(9876543210)
	require.NoError(t, err)

	epoch, err = rp.GetActiveVersionTimestamp()
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
		Shares: map[string]string{
			"0x0000000000000000000000000000000000000001": "share1",
			"0x0000000000000000000000000000000000000002": "share2",
		},
		Commitments: map[string][]types.G2Point{
			"0x0000000000000000000000000000000000000001": {{CompressedBytes: []byte{1, 2, 3}}},
		},
		Acknowledgements: map[string]map[string]*types.Acknowledgement{
			"0x0000000000000000000000000000000000000001": {
				"0x0000000000000000000000000000000000000002": {PlayerAddress: common.BigToAddress(big.NewInt(2)), DealerAddress: common.BigToAddress(big.NewInt(1)), SessionTimestamp: sessionTS},
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
		Shares:            map[string]string{},
		Commitments:       map[string][]types.G2Point{},
		Acknowledgements:  map[string]map[string]*types.Acknowledgement{},
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
			Shares:            map[string]string{},
			Commitments:       map[string][]types.G2Point{},
			Acknowledgements:  map[string]map[string]*types.Acknowledgement{},
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
					ParticipantIDs: []common.Address{common.HexToAddress(fmt.Sprintf("0x%040x", id))},
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
