package node

import (
	"context"
	"sync"
	"testing"
	"time"

	EVMChainPoller "github.com/Layr-Labs/chain-indexer/pkg/chainPollers/evm"
	"github.com/Layr-Labs/chain-indexer/pkg/chainPollers/persistence/memory"
	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	chainIndexerConfig "github.com/Layr-Labs/chain-indexer/pkg/config"
	"github.com/Layr-Labs/chain-indexer/pkg/contractStore/inMemoryContractStore"
	"github.com/Layr-Labs/chain-indexer/pkg/transactionLogParser"
	"github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/blockHandler"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering/localPeeringDataFetcher"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	persistenceBadger "github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/badger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/inMemoryTransportSigner"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	L1RpcUrl = "http://127.0.0.1:8545"
)

// createMockContractCaller creates a mock contract caller for tests
func createMockContractCaller(t *testing.T) (contractCaller.IContractCaller, common.Address) {
	mockCC := contractCaller.NewMockIContractCaller(t)
	mockCC.On("SubmitCommitment", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&ethTypes.Receipt{Status: 1}, nil).Maybe()
	return mockCC, common.HexToAddress("0x1111111111111111111111111111111111111111")
}

func TestNodePersistence(t *testing.T) {
	t.Run("CleanShutdown", testNodeRestart_CleanShutdown)
	t.Run("BlockBoundaryTracking", testNodeRestart_BlockBoundaryTracking)
	t.Run("MultipleKeyVersions", testNodeRestart_MultipleKeyVersions)
	t.Run("EmptyState", testNodeRestart_EmptyState)
	t.Run("IncompleteSessions", testNodeRestart_IncompleteSessions)
	t.Run("SessionPersistenceDuringDKG", testSessionPersistence_DuringDKG)
	t.Run("SessionExpirationCleanup", testSessionPersistence_ExpirationCleanup)
	t.Run("SessionCleanupOnCompletion", testSessionPersistence_CleanupOnCompletion)
}

// testNodeRestart_CleanShutdown tests that a node can restore state after clean shutdown
func testNodeRestart_CleanShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	// Get test data
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	require.NoError(t, err)

	peers := createSingleNodePeering(t, chainConfig)

	// Setup anvil
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_ = tests.KillallAnvils()

	l1Anvil, err := tests.StartL1Anvil(projectRoot, ctx)
	require.NoError(t, err)
	defer func() { _ = tests.KillAnvil(l1Anvil) }()

	// Wait for anvil
	anvilWg := &sync.WaitGroup{}
	anvilWg.Add(1)
	startErrorsChan := make(chan error, 1)

	l1EthereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   L1RpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, testLogger)

	go tests.WaitForAnvil(anvilWg, ctx, t, l1EthereumClient, startErrorsChan)
	anvilWg.Wait()
	close(startErrorsChan)
	for err := range startErrorsChan {
		require.NoError(t, err, "Failed to start Anvil")
	}

	// Phase 1: Create node with real poller, add key version, shutdown
	persistence1, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)

	bh1 := blockHandler.NewBlockHandler(testLogger)

	cs := inMemoryContractStore.NewInMemoryContractStore(nil, testLogger)
	logParser := transactionLogParser.NewTransactionLogParser(cs, testLogger)
	pollerStore := memory.NewInMemoryChainPollerPersistence()

	poller1, err := EVMChainPoller.NewEVMChainPoller(
		l1EthereumClient,
		logParser,
		&EVMChainPoller.EVMChainPollerConfig{
			ChainId:         chainIndexerConfig.ChainId(31337),
			PollingInterval: 1 * time.Second,
		},
		pollerStore, bh1, testLogger)
	require.NoError(t, err)

	pkBytes, err := hexutil.Decode(chainConfig.OperatorAccountPrivateKey1)
	require.NoError(t, err)
	imts1, err := inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(pkBytes, testLogger)
	require.NoError(t, err)

	attestationVerifier := attestation.NewStubVerifier()

	mockCC1, mockRegistryAddr := createMockContractCaller(t)

	node1, err := NewNode(
		Config{
			OperatorAddress: chainConfig.OperatorAccountAddress1,
			Port:            7501,
			ChainID:         config.ChainId_EthereumAnvil,
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
		},
		peers,
		bh1,
		poller1,
		imts1,
		attestationVerifier,
		mockCC1,
		mockRegistryAddr,
		persistence1,
		testLogger,
	)
	require.NoError(t, err)

	// Start node
	err = node1.Start()
	require.NoError(t, err)

	// Manually add a key version (simulating completed DKG)
	privateShare := fr.NewElement(uint64(12345))
	testVersion := &types.KeyShareVersion{
		Version:        1234567890,
		PrivateShare:   &privateShare,
		Commitments:    []types.G2Point{{CompressedBytes: []byte{1, 2, 3}}},
		IsActive:       true,
		ParticipantIDs: []int64{1},
	}

	node1.keyStore.AddVersion(testVersion)

	// Persist it
	err = node1.persistence.SaveKeyShareVersion(testVersion)
	require.NoError(t, err)
	err = node1.persistence.SetActiveVersionEpoch(testVersion.Version)
	require.NoError(t, err)

	t.Logf("Node 1 persisted key version: %d", testVersion.Version)

	// Clean shutdown
	err = node1.Stop()
	require.NoError(t, err)
	err = persistence1.Close()
	require.NoError(t, err)

	// Phase 2: Create new node with same data path
	persistence2, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = persistence2.Close() }()

	bh2 := blockHandler.NewBlockHandler(testLogger)

	poller2, err := EVMChainPoller.NewEVMChainPoller(
		l1EthereumClient,
		logParser,
		&EVMChainPoller.EVMChainPollerConfig{
			ChainId:         chainIndexerConfig.ChainId(31337),
			PollingInterval: 1 * time.Second,
		},
		pollerStore, bh2, testLogger)
	require.NoError(t, err)

	imts2, err := inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(pkBytes, testLogger)
	require.NoError(t, err)

	mockCC2, mockRegistryAddr2 := createMockContractCaller(t)

	node2, err := NewNode(
		Config{
			OperatorAddress: chainConfig.OperatorAccountAddress1,
			Port:            7502,
			ChainID:         config.ChainId_EthereumAnvil,
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
		},
		peers,
		bh2,
		poller2,
		imts2,
		attestationVerifier,
		mockCC2,
		mockRegistryAddr2,
		persistence2,
		testLogger,
	)
	require.NoError(t, err)

	// Start node (should restore state)
	err = node2.Start()
	require.NoError(t, err)
	defer func() { _ = node2.Stop() }()

	// Verify state was restored
	restoredVersion := node2.GetKeyStore().GetActiveVersion()
	require.NotNil(t, restoredVersion, "Active version not restored")
	assert.Equal(t, testVersion.Version, restoredVersion.Version, "Restored version mismatch")
	assert.True(t, testVersion.PrivateShare.Equal(restoredVersion.PrivateShare), "Private share mismatch")

	t.Logf("✓ Node successfully restored state with version: %d", restoredVersion.Version)
}

// testNodeRestart_BlockBoundaryTracking tests that block boundary tracking survives restart
func testNodeRestart_BlockBoundaryTracking(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	// Get test data
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	require.NoError(t, err)

	peers := createSingleNodePeering(t, chainConfig)

	// Setup anvil (shared for both phases)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_ = tests.KillallAnvils()

	l1Anvil, err := tests.StartL1Anvil(projectRoot, ctx)
	require.NoError(t, err)
	defer func() { _ = tests.KillAnvil(l1Anvil) }()

	anvilWg := &sync.WaitGroup{}
	anvilWg.Add(1)
	startErrorsChan := make(chan error, 1)

	l1EthereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   L1RpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, testLogger)

	go tests.WaitForAnvil(anvilWg, ctx, t, l1EthereumClient, startErrorsChan)
	anvilWg.Wait()
	close(startErrorsChan)

	// Phase 1: Create node and set block boundary
	persistence1, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)

	bh1 := blockHandler.NewBlockHandler(testLogger)

	cs := inMemoryContractStore.NewInMemoryContractStore(nil, testLogger)
	logParser := transactionLogParser.NewTransactionLogParser(cs, testLogger)
	pollerStore := memory.NewInMemoryChainPollerPersistence()

	poller1, err := EVMChainPoller.NewEVMChainPoller(
		l1EthereumClient,
		logParser,
		&EVMChainPoller.EVMChainPollerConfig{
			ChainId:         chainIndexerConfig.ChainId(31337),
			PollingInterval: 1 * time.Second,
		},
		pollerStore, bh1, testLogger)
	require.NoError(t, err)

	pkBytes, err := hexutil.Decode(chainConfig.OperatorAccountPrivateKey1)
	require.NoError(t, err)
	imts1, err := inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(pkBytes, testLogger)
	require.NoError(t, err)

	attestationVerifier := attestation.NewStubVerifier()

	mockCC1, mockRegistryAddr := createMockContractCaller(t)

	node1, err := NewNode(
		Config{
			OperatorAddress: chainConfig.OperatorAccountAddress1,
			Port:            7503,
			ChainID:         config.ChainId_EthereumAnvil,
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
		},
		peers,
		bh1,
		poller1,
		imts1,
		attestationVerifier,
		mockCC1,
		mockRegistryAddr,
		persistence1,
		testLogger,
	)
	require.NoError(t, err)

	err = node1.Start()
	require.NoError(t, err)

	// Manually set and persist block boundary
	node1.lastProcessedBoundary = 120

	nodeState := &persistence.NodeState{
		LastProcessedBoundary: 120,
		NodeStartTime:         time.Now().Unix(),
		OperatorAddress:       node1.OperatorAddress.Hex(),
	}
	err = node1.persistence.SaveNodeState(nodeState)
	require.NoError(t, err)

	t.Logf("Node 1 persisted block boundary: 120")

	// Shutdown
	err = node1.Stop()
	require.NoError(t, err)
	err = persistence1.Close()
	require.NoError(t, err)

	// Phase 2: Restart and verify boundary restored
	persistence2, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = persistence2.Close() }()

	bh2 := blockHandler.NewBlockHandler(testLogger)

	poller2, err := EVMChainPoller.NewEVMChainPoller(
		l1EthereumClient,
		logParser,
		&EVMChainPoller.EVMChainPollerConfig{
			ChainId:         chainIndexerConfig.ChainId(31337),
			PollingInterval: 1 * time.Second,
		},
		pollerStore, bh2, testLogger)
	require.NoError(t, err)

	imts2, err := inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(pkBytes, testLogger)
	require.NoError(t, err)

	mockCC2, mockRegistryAddr2 := createMockContractCaller(t)

	node2, err := NewNode(
		Config{
			OperatorAddress: chainConfig.OperatorAccountAddress1,
			Port:            7504,
			ChainID:         config.ChainId_EthereumAnvil,
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
		},
		peers,
		bh2,
		poller2,
		imts2,
		attestationVerifier,
		mockCC2,
		mockRegistryAddr2,
		persistence2,
		testLogger,
	)
	require.NoError(t, err)

	err = node2.Start()
	require.NoError(t, err)
	defer func() { _ = node2.Stop() }()

	// Verify restored boundary
	restoredBoundary := node2.lastProcessedBoundary
	assert.Equal(t, int64(120), restoredBoundary, "Block boundary not restored")

	t.Logf("✓ Block boundary correctly restored: %d", restoredBoundary)
}

// testNodeRestart_MultipleKeyVersions tests that multiple key versions persist correctly
func testNodeRestart_MultipleKeyVersions(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	// Get test data
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	require.NoError(t, err)

	peers := createSingleNodePeering(t, chainConfig)

	// Setup anvil
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_ = tests.KillallAnvils()

	l1Anvil, err := tests.StartL1Anvil(projectRoot, ctx)
	require.NoError(t, err)
	defer func() { _ = tests.KillAnvil(l1Anvil) }()

	anvilWg := &sync.WaitGroup{}
	anvilWg.Add(1)
	startErrorsChan := make(chan error, 1)

	l1EthereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   L1RpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, testLogger)

	go tests.WaitForAnvil(anvilWg, ctx, t, l1EthereumClient, startErrorsChan)
	anvilWg.Wait()
	close(startErrorsChan)

	// Phase 1: Create node and add multiple key versions
	persistence1, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)

	bh1 := blockHandler.NewBlockHandler(testLogger)

	cs := inMemoryContractStore.NewInMemoryContractStore(nil, testLogger)
	logParser := transactionLogParser.NewTransactionLogParser(cs, testLogger)
	pollerStore := memory.NewInMemoryChainPollerPersistence()

	poller1, err := EVMChainPoller.NewEVMChainPoller(
		l1EthereumClient,
		logParser,
		&EVMChainPoller.EVMChainPollerConfig{
			ChainId:         chainIndexerConfig.ChainId(31337),
			PollingInterval: 1 * time.Second,
		},
		pollerStore, bh1, testLogger)
	require.NoError(t, err)

	pkBytes, err := hexutil.Decode(chainConfig.OperatorAccountPrivateKey1)
	require.NoError(t, err)
	imts1, err := inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(pkBytes, testLogger)
	require.NoError(t, err)

	attestationVerifier := attestation.NewStubVerifier()

	mockCC1, mockRegistryAddr := createMockContractCaller(t)

	node1, err := NewNode(
		Config{
			OperatorAddress: chainConfig.OperatorAccountAddress1,
			Port:            7505,
			ChainID:         config.ChainId_EthereumAnvil,
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
		},
		peers,
		bh1,
		poller1,
		imts1,
		attestationVerifier,
		mockCC1,
		mockRegistryAddr,
		persistence1,
		testLogger,
	)
	require.NoError(t, err)

	err = node1.Start()
	require.NoError(t, err)

	// Create 3 key versions (simulating DKG + 2 reshares)
	versions := make([]*types.KeyShareVersion, 3)
	for i := 0; i < 3; i++ {
		privateShare := fr.NewElement(uint64(i * 1000))
		versions[i] = &types.KeyShareVersion{
			Version:        int64(1000 + i*100),
			PrivateShare:   &privateShare,
			Commitments:    []types.G2Point{{CompressedBytes: []byte{byte(i), byte(i + 1)}}},
			IsActive:       i == 2, // Last one is active
			ParticipantIDs: []int64{1},
		}

		node1.keyStore.AddVersion(versions[i])
		err = node1.persistence.SaveKeyShareVersion(versions[i])
		require.NoError(t, err)
	}

	// Set active version
	err = node1.persistence.SetActiveVersionEpoch(versions[2].Version)
	require.NoError(t, err)

	t.Logf("Persisted 3 key versions: %d, %d, %d", versions[0].Version, versions[1].Version, versions[2].Version)

	// Shutdown
	err = node1.Stop()
	require.NoError(t, err)
	err = persistence1.Close()
	require.NoError(t, err)

	// Phase 2: Restart and verify all versions restored
	persistence2, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = persistence2.Close() }()

	bh2 := blockHandler.NewBlockHandler(testLogger)

	poller2, err := EVMChainPoller.NewEVMChainPoller(
		l1EthereumClient,
		logParser,
		&EVMChainPoller.EVMChainPollerConfig{
			ChainId:         chainIndexerConfig.ChainId(31337),
			PollingInterval: 1 * time.Second,
		},
		pollerStore, bh2, testLogger)
	require.NoError(t, err)

	imts2, err := inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(pkBytes, testLogger)
	require.NoError(t, err)

	mockCC2, mockRegistryAddr2 := createMockContractCaller(t)

	node2, err := NewNode(
		Config{
			OperatorAddress: chainConfig.OperatorAccountAddress1,
			Port:            7506,
			ChainID:         config.ChainId_EthereumAnvil,
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
		},
		peers,
		bh2,
		poller2,
		imts2,
		attestationVerifier,
		mockCC2,
		mockRegistryAddr2,
		persistence2,
		testLogger,
	)
	require.NoError(t, err)

	err = node2.Start()
	require.NoError(t, err)
	defer func() { _ = node2.Stop() }()

	// Verify all 3 versions restored by loading them individually
	v1, err := persistence2.LoadKeyShareVersion(1000)
	require.NoError(t, err)
	require.NotNil(t, v1, "Version 1000 not restored")

	v2, err := persistence2.LoadKeyShareVersion(1100)
	require.NoError(t, err)
	require.NotNil(t, v2, "Version 1100 not restored")

	v3, err := persistence2.LoadKeyShareVersion(1200)
	require.NoError(t, err)
	require.NotNil(t, v3, "Version 1200 not restored")

	// Verify active version is the latest
	activeVersion2 := node2.GetKeyStore().GetActiveVersion()
	require.NotNil(t, activeVersion2)
	assert.Equal(t, int64(1200), activeVersion2.Version, "Active version not restored correctly")

	// Verify private shares match
	assert.True(t, versions[2].PrivateShare.Equal(activeVersion2.PrivateShare), "Private share mismatch")

	t.Logf("✓ All 3 key versions successfully restored with correct active version")
}

// testNodeRestart_EmptyState tests first-run behavior with no persisted state
func testNodeRestart_EmptyState(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	// Get test data
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	require.NoError(t, err)

	peers := createSingleNodePeering(t, chainConfig)

	// Setup anvil
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_ = tests.KillallAnvils()

	l1Anvil, err := tests.StartL1Anvil(projectRoot, ctx)
	require.NoError(t, err)
	defer func() { _ = tests.KillAnvil(l1Anvil) }()

	anvilWg := &sync.WaitGroup{}
	anvilWg.Add(1)
	startErrorsChan := make(chan error, 1)

	l1EthereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   L1RpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, testLogger)

	go tests.WaitForAnvil(anvilWg, ctx, t, l1EthereumClient, startErrorsChan)
	anvilWg.Wait()
	close(startErrorsChan)

	// Create node with fresh (empty) persistence
	persistence, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = persistence.Close() }()

	bh := blockHandler.NewBlockHandler(testLogger)

	cs := inMemoryContractStore.NewInMemoryContractStore(nil, testLogger)
	logParser := transactionLogParser.NewTransactionLogParser(cs, testLogger)
	pollerStore := memory.NewInMemoryChainPollerPersistence()

	poller, err := EVMChainPoller.NewEVMChainPoller(
		l1EthereumClient,
		logParser,
		&EVMChainPoller.EVMChainPollerConfig{
			ChainId:         chainIndexerConfig.ChainId(31337),
			PollingInterval: 1 * time.Second,
		},
		pollerStore, bh, testLogger)
	require.NoError(t, err)

	pkBytes, err := hexutil.Decode(chainConfig.OperatorAccountPrivateKey1)
	require.NoError(t, err)
	imts, err := inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(pkBytes, testLogger)
	require.NoError(t, err)

	attestationVerifier := attestation.NewStubVerifier()

	mockCC, mockRegistryAddr := createMockContractCaller(t)

	node, err := NewNode(
		Config{
			OperatorAddress: chainConfig.OperatorAccountAddress1,
			Port:            7507,
			ChainID:         config.ChainId_EthereumAnvil,
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
		},
		peers,
		bh,
		poller,
		imts,
		attestationVerifier,
		mockCC,
		mockRegistryAddr,
		persistence,
		testLogger,
	)
	require.NoError(t, err)

	// Start should succeed even with empty state
	err = node.Start()
	require.NoError(t, err)
	defer func() { _ = node.Stop() }()

	// Verify no active version (first run)
	assert.Nil(t, node.GetKeyStore().GetActiveVersion(), "Should have no active version on first run")

	// Verify lastProcessedBoundary is 0
	boundary := node.lastProcessedBoundary
	assert.Equal(t, int64(0), boundary, "Should have no processed boundary on first run")

	t.Logf("✓ Node handles empty state correctly on first run")
}

// testNodeRestart_IncompleteSessions tests cleanup of incomplete protocol sessions
func testNodeRestart_IncompleteSessions(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	// Get test data
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	require.NoError(t, err)

	peers := createSingleNodePeering(t, chainConfig)

	// Setup anvil
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_ = tests.KillallAnvils()

	l1Anvil, err := tests.StartL1Anvil(projectRoot, ctx)
	require.NoError(t, err)
	defer func() { _ = tests.KillAnvil(l1Anvil) }()

	anvilWg := &sync.WaitGroup{}
	anvilWg.Add(1)
	startErrorsChan := make(chan error, 1)

	l1EthereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   L1RpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, testLogger)

	go tests.WaitForAnvil(anvilWg, ctx, t, l1EthereumClient, startErrorsChan)
	anvilWg.Wait()
	close(startErrorsChan)

	// Phase 1: Create persistence with incomplete session
	persistence1, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)

	// Manually save an incomplete session (simulating crash during DKG)
	incompleteSession := &persistence.ProtocolSessionState{
		SessionTimestamp:  1234567890,
		Type:              "dkg",
		Phase:             2, // Incomplete (not finalized)
		StartTime:         time.Now().Unix(),
		OperatorAddresses: []string{chainConfig.OperatorAccountAddress1},
		Shares:            map[int64]string{1: "test"},
		Commitments:       map[int64][]types.G2Point{},
		Acknowledgements:  map[int64]map[int64]*types.Acknowledgement{},
	}

	err = persistence1.SaveProtocolSession(incompleteSession)
	require.NoError(t, err)

	// Verify session was saved
	sessions, err := persistence1.ListProtocolSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)

	err = persistence1.Close()
	require.NoError(t, err)

	t.Logf("Saved incomplete session: %d (phase %d)", incompleteSession.SessionTimestamp, incompleteSession.Phase)

	// Phase 2: Restart node - should clean up incomplete session
	persistence2, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = persistence2.Close() }()

	bh := blockHandler.NewBlockHandler(testLogger)

	cs2 := inMemoryContractStore.NewInMemoryContractStore(nil, testLogger)
	logParser2 := transactionLogParser.NewTransactionLogParser(cs2, testLogger)
	pollerStore := memory.NewInMemoryChainPollerPersistence()

	poller, err := EVMChainPoller.NewEVMChainPoller(
		l1EthereumClient,
		logParser2,
		&EVMChainPoller.EVMChainPollerConfig{
			ChainId:         chainIndexerConfig.ChainId(31337),
			PollingInterval: 1 * time.Second,
		},
		pollerStore, bh, testLogger)
	require.NoError(t, err)

	pkBytes, err := hexutil.Decode(chainConfig.OperatorAccountPrivateKey1)
	require.NoError(t, err)
	imts, err := inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(pkBytes, testLogger)
	require.NoError(t, err)

	attestationVerifier := attestation.NewStubVerifier()

	mockCC, mockRegistryAddr := createMockContractCaller(t)

	node, err := NewNode(
		Config{
			OperatorAddress: chainConfig.OperatorAccountAddress1,
			Port:            7508,
			ChainID:         config.ChainId_EthereumAnvil,
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
		},
		peers,
		bh,
		poller,
		imts,
		attestationVerifier,
		mockCC,
		mockRegistryAddr,
		persistence2,
		testLogger,
	)
	require.NoError(t, err)

	// Start should clean up incomplete sessions
	err = node.Start()
	require.NoError(t, err)
	defer func() { _ = node.Stop() }()

	// Verify session was cleaned up
	sessionsAfter, err := persistence2.ListProtocolSessions()
	require.NoError(t, err)
	assert.Empty(t, sessionsAfter, "Incomplete session not cleaned up")

	t.Logf("✓ Incomplete session successfully cleaned up on restart")
}

// Helper function to create single-node peering for isolated tests
func createSingleNodePeering(t *testing.T, chainConfig *tests.ChainConfig) peering.IPeeringDataFetcher {
	// Parse ECDSA private key for peering
	privKey, err := ecdsa.NewPrivateKeyFromHexString(chainConfig.OperatorAccountPrivateKey1)
	require.NoError(t, err)

	peers := []*peering.OperatorSetPeer{
		{
			OperatorAddress: common.HexToAddress(chainConfig.OperatorAccountAddress1),
			SocketAddress:   "http://localhost:7500",
			WrappedPublicKey: peering.WrappedPublicKey{
				PublicKey:    privKey.Public(),
				ECDSAAddress: common.HexToAddress(chainConfig.OperatorAccountAddress1),
			},
			CurveType: config.CurveTypeECDSA,
		},
	}

	operatorSet := &peering.OperatorSetPeers{
		OperatorSetId: 1,
		AVSAddress:    common.HexToAddress("0x1234567890123456789012345678901234567890"),
		Peers:         peers,
	}

	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	return localPeeringDataFetcher.NewLocalPeeringDataFetcher([]*peering.OperatorSetPeers{operatorSet}, testLogger)
}

// testSessionPersistence_DuringDKG tests that protocol sessions are saved during DKG execution
func testSessionPersistence_DuringDKG(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	// Get test data
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	require.NoError(t, err)

	peers := createSingleNodePeering(t, chainConfig)

	persistence, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = persistence.Close() }()

	// Get operators from peering
	ctx := context.Background()
	opSet, err := peers.ListKMSOperators(ctx, "0x1234567890123456789012345678901234567890", 1)
	require.NoError(t, err)

	// Create a session manually
	session := &ProtocolSession{
		SessionTimestamp:  1234567890,
		Type:              "dkg",
		Phase:             1,
		StartTime:         time.Now(),
		Operators:         opSet.Peers,
		shares:            make(map[int64]*fr.Element),
		commitments:       make(map[int64][]types.G2Point),
		acks:              make(map[int64]map[int64]*types.Acknowledgement),
		verifiedOperators: make(map[int64]bool),
	}

	// Convert and save
	persistenceState := session.toPersistenceState()
	err = persistence.SaveProtocolSession(persistenceState)
	require.NoError(t, err)

	// Verify it was saved
	loaded, err := persistence.LoadProtocolSession(session.SessionTimestamp)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, session.SessionTimestamp, loaded.SessionTimestamp)
	assert.Equal(t, session.Type, loaded.Type)
	assert.Equal(t, session.Phase, loaded.Phase)

	t.Logf("✓ Session successfully persisted and loaded")
}

// testSessionPersistence_ExpirationCleanup tests that expired sessions are cleaned up
func testSessionPersistence_ExpirationCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	// Get test data
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	require.NoError(t, err)

	peers := createSingleNodePeering(t, chainConfig)

	// Create persistence with an expired session
	persistence1, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)

	// Create a session that started 1 hour ago (definitely expired)
	expiredSession := &persistence.ProtocolSessionState{
		SessionTimestamp:  1234567890,
		Type:              "dkg",
		Phase:             2,
		StartTime:         time.Now().Unix() - 3600, // 1 hour ago
		OperatorAddresses: []string{chainConfig.OperatorAccountAddress1},
		Shares:            map[int64]string{},
		Commitments:       map[int64][]types.G2Point{},
		Acknowledgements:  map[int64]map[int64]*types.Acknowledgement{},
	}

	err = persistence1.SaveProtocolSession(expiredSession)
	require.NoError(t, err)

	// Verify it's expired
	protocolTimeout := config.GetProtocolTimeoutForChain(config.ChainId_EthereumAnvil)
	assert.True(t, expiredSession.IsExpired(int64(protocolTimeout.Seconds())), "Session should be expired")

	err = persistence1.Close()
	require.NoError(t, err)

	// Setup anvil
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_ = tests.KillallAnvils()

	l1Anvil, err := tests.StartL1Anvil(projectRoot, ctx)
	require.NoError(t, err)
	defer func() { _ = tests.KillAnvil(l1Anvil) }()

	anvilWg := &sync.WaitGroup{}
	anvilWg.Add(1)
	startErrorsChan := make(chan error, 1)

	l1EthereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   L1RpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, testLogger)

	go tests.WaitForAnvil(anvilWg, ctx, t, l1EthereumClient, startErrorsChan)
	anvilWg.Wait()
	close(startErrorsChan)

	// Restart node - should clean up expired session
	persistence2, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = persistence2.Close() }()

	bh := blockHandler.NewBlockHandler(testLogger)

	cs := inMemoryContractStore.NewInMemoryContractStore(nil, testLogger)
	logParser := transactionLogParser.NewTransactionLogParser(cs, testLogger)
	pollerStore := memory.NewInMemoryChainPollerPersistence()

	poller, err := EVMChainPoller.NewEVMChainPoller(
		l1EthereumClient,
		logParser,
		&EVMChainPoller.EVMChainPollerConfig{
			ChainId:         chainIndexerConfig.ChainId(31337),
			PollingInterval: 1 * time.Second,
		},
		pollerStore, bh, testLogger)
	require.NoError(t, err)

	pkBytes, err := hexutil.Decode(chainConfig.OperatorAccountPrivateKey1)
	require.NoError(t, err)
	imts, err := inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(pkBytes, testLogger)
	require.NoError(t, err)

	attestationVerifier := attestation.NewStubVerifier()

	mockCC, mockRegistryAddr := createMockContractCaller(t)

	node, err := NewNode(
		Config{
			OperatorAddress: chainConfig.OperatorAccountAddress1,
			Port:            7509,
			ChainID:         config.ChainId_EthereumAnvil,
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
		},
		peers,
		bh,
		poller,
		imts,
		attestationVerifier,
		mockCC,
		mockRegistryAddr,
		persistence2,
		testLogger,
	)
	require.NoError(t, err)

	// Start should clean up expired session
	err = node.Start()
	require.NoError(t, err)
	defer func() { _ = node.Stop() }()

	// Verify session was cleaned up
	sessions, err := persistence2.ListProtocolSessions()
	require.NoError(t, err)
	assert.Empty(t, sessions, "Expired session should have been cleaned up")

	t.Logf("✓ Expired session successfully cleaned up on restart")
}

// testSessionPersistence_CleanupOnCompletion tests that sessions are deleted when protocols complete
func testSessionPersistence_CleanupOnCompletion(t *testing.T) {
	tmpDir := t.TempDir()
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	persistenceLayer, err := persistenceBadger.NewBadgerPersistence(tmpDir, testLogger)
	require.NoError(t, err)
	defer func() { _ = persistenceLayer.Close() }()

	// Manually save a session
	testSession := &persistence.ProtocolSessionState{
		SessionTimestamp:  9999999,
		Type:              "dkg",
		Phase:             1,
		StartTime:         time.Now().Unix(),
		OperatorAddresses: []string{"0x1234"},
		Shares:            map[int64]string{},
		Commitments:       map[int64][]types.G2Point{},
		Acknowledgements:  map[int64]map[int64]*types.Acknowledgement{},
	}

	err = persistenceLayer.SaveProtocolSession(testSession)
	require.NoError(t, err)

	// Verify it exists
	sessions, err := persistenceLayer.ListProtocolSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)

	// Delete it (simulating protocol completion)
	err = persistenceLayer.DeleteProtocolSession(testSession.SessionTimestamp)
	require.NoError(t, err)

	// Verify it's gone
	sessions, err = persistenceLayer.ListProtocolSessions()
	require.NoError(t, err)
	assert.Empty(t, sessions, "Session should be deleted after completion")

	// Verify individual load returns nil
	loaded, err := persistenceLayer.LoadProtocolSession(testSession.SessionTimestamp)
	require.NoError(t, err)
	assert.Nil(t, loaded, "Deleted session should not be loadable")

	t.Logf("✓ Session successfully deleted on completion")
}
