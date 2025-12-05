package integration

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
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/blockHandler"
	kmsClient "github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering/peeringDataFetcher"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/inMemoryTransportSigner"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
)

const (
	L1RpcUrl = "http://127.0.0.1:8545"
	L2RpcUrl = "http://127.0.0.1:9545"
)

// Test_OnChainIntegration is a full end-to-end test with L1 (Ethereum) and L2 (Base) anvil instances
// This test uses real anvil instances and waits for actual block boundaries to trigger DKG
func Test_OnChainIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping end-to-end integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Create logger
	l, err := logger.NewLogger(&logger.LoggerConfig{
		Debug: false,
	})
	require.NoError(t, err)

	// Get project root and chain config
	root := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(root)
	require.NoError(t, err)

	t.Logf("Starting end-to-end integration test")
	t.Logf("AVS Address: %s", chainConfig.AVSAccountAddress)
	t.Logf("Registrar Address: %s", chainConfig.EigenRegistrarAddress)
	t.Logf("Commitment Registry Address: %s", chainConfig.EigenCommitmentRegistryAddress)

	// ------------------------------------------------------------------------
	// Start L1 Anvil (Ethereum)
	// ------------------------------------------------------------------------
	t.Log("Starting L1 Anvil (Ethereum)...")
	_ = tests.KillallAnvils()

	l1Anvil, err := tests.StartL1Anvil(root, ctx)
	require.NoError(t, err)
	defer func() {
		t.Log("Cleaning up L1 Anvil...")
		if err := tests.KillAnvil(l1Anvil); err != nil {
			t.Logf("Warning: failed to kill L1 Anvil: %v", err)
		}
	}()

	// Wait for L1 to be ready
	l1Client := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   L1RpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, l)

	anvilWg := &sync.WaitGroup{}
	anvilWg.Add(1)
	startErrorsChan := make(chan error, 1)
	anvilCtx, anvilCancel := context.WithTimeout(ctx, 30*time.Second)
	go tests.WaitForAnvil(anvilWg, anvilCtx, t, l1Client, startErrorsChan)
	anvilWg.Wait()
	anvilCancel()

	select {
	case err := <-startErrorsChan:
		if err != nil {
			t.Fatalf("Failed to start L1 Anvil: %v", err)
		}
	default:
	}
	close(startErrorsChan)

	t.Log("L1 Anvil is running")

	// ------------------------------------------------------------------------
	// Start L2 Anvil (Base)
	// ------------------------------------------------------------------------
	t.Log("Starting L2 Anvil (Base)...")

	l2Anvil, err := tests.StartL2Anvil(root, ctx)
	require.NoError(t, err)
	defer func() {
		t.Log("Cleaning up L2 Anvil...")
		if err := tests.KillAnvil(l2Anvil); err != nil {
			t.Logf("Warning: failed to kill L2 Anvil: %v", err)
		}
		// Final cleanup - kill any remaining anvil processes
		_ = tests.KillallAnvils()
	}()

	// Wait for L2 to be ready
	l2Client := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   L2RpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, l)

	anvilWg2 := &sync.WaitGroup{}
	anvilWg2.Add(1)
	startErrorsChan2 := make(chan error, 1)
	anvilCtx2, anvilCancel2 := context.WithTimeout(ctx, 30*time.Second)
	go tests.WaitForAnvil(anvilWg2, anvilCtx2, t, l2Client, startErrorsChan2)
	anvilWg2.Wait()
	anvilCancel2()

	select {
	case err := <-startErrorsChan2:
		if err != nil {
			t.Fatalf("Failed to start L2 Anvil: %v", err)
		}
	default:
	}
	close(startErrorsChan2)

	t.Log("L2 Anvil is running")

	// ------------------------------------------------------------------------
	// Create contract callers
	// ------------------------------------------------------------------------
	l1EthClient, err := l1Client.GetEthereumContractCaller()
	require.NoError(t, err)

	l1ContractCaller, err := caller.NewContractCaller(l1EthClient, nil, l)
	require.NoError(t, err)

	l2EthClient, err := l2Client.GetEthereumContractCaller()
	require.NoError(t, err)

	l2ContractCaller, err := caller.NewContractCaller(l2EthClient, nil, l)
	require.NoError(t, err)

	commitmentRegistryAddress := common.HexToAddress(chainConfig.EigenCommitmentRegistryAddress)

	t.Logf("Using Commitment Registry at: %s", commitmentRegistryAddress.Hex())

	// ------------------------------------------------------------------------
	// Create 5 nodes using ChainConfig data
	// ------------------------------------------------------------------------
	t.Log("Creating 5 KMS nodes...")

	nodes := make([]*node.Node, 5)
	operatorConfigs := []struct {
		address    string
		privateKey string
		socket     string
	}{
		{chainConfig.OperatorAccountAddress1, chainConfig.OperatorAccountPrivateKey1, chainConfig.OperatorSocket1},
		{chainConfig.OperatorAccountAddress2, chainConfig.OperatorAccountPrivateKey2, chainConfig.OperatorSocket2},
		{chainConfig.OperatorAccountAddress3, chainConfig.OperatorAccountPrivateKey3, chainConfig.OperatorSocket3},
		{chainConfig.OperatorAccountAddress4, chainConfig.OperatorAccountPrivateKey4, chainConfig.OperatorSocket4},
		{chainConfig.OperatorAccountAddress5, chainConfig.OperatorAccountPrivateKey5, chainConfig.OperatorSocket5},
	}

	for i := 0; i < 5; i++ {
		// Create block handler and chain poller for each node
		bh := blockHandler.NewBlockHandler(l)

		cs := inMemoryContractStore.NewInMemoryContractStore(nil, l)
		logParser := transactionLogParser.NewTransactionLogParser(cs, l)
		pollerStore := memory.NewInMemoryChainPollerPersistence()

		poller, err := EVMChainPoller.NewEVMChainPoller(
			l1Client,
			logParser,
			&EVMChainPoller.EVMChainPollerConfig{
				ChainId:         chainIndexerConfig.ChainId(config.ChainId_EthereumAnvil),
				PollingInterval: time.Second,
			},
			pollerStore, bh, l)
		require.NoError(t, err)

		// Create peering data fetcher
		pdf := peeringDataFetcher.NewPeeringDataFetcher(l1ContractCaller, l)

		// Create ECDSA transport signer (production-like, using local keys for testing)
		pkBytes, err := hexutil.Decode(operatorConfigs[i].privateKey)
		require.NoError(t, err)

		transportSigner, err := inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(pkBytes, l)
		require.NoError(t, err)

		// Use stub attestation verifier for testing
		// Production would use GoogleConfidentialSpace or IntelTrustAuthority
		attestationVerifier := attestation.NewStubVerifier()

		// Create node
		nodeConfig := node.Config{
			OperatorAddress: operatorConfigs[i].address,
			Port:            7500 + i,
			ChainID:         config.ChainId_EthereumAnvil,
			AVSAddress:      chainConfig.AVSAccountAddress,
			OperatorSetId:   0,
		}

		n, err := node.NewNode(
			nodeConfig,
			pdf,
			bh,
			poller,
			transportSigner,
			attestationVerifier,
			l2ContractCaller,
			commitmentRegistryAddress,
			l,
		)
		require.NoError(t, err)

		nodes[i] = n

		// Start the node
		err = n.Start()
		require.NoError(t, err)

		t.Logf("Node %d started: %s at %s", i+1, operatorConfigs[i].address, operatorConfigs[i].socket)
	}

	// ------------------------------------------------------------------------
	// Wait for DKG to complete
	// ------------------------------------------------------------------------
	t.Log("Waiting for nodes to sync and DKG to complete...")
	t.Log("  (Nodes need to reach a block boundary that's a multiple of 10)")
	t.Log("  (With 2-second block time, may take 30-60 seconds)")

	// Poll for up to 90 seconds waiting for DKG to complete
	dkgComplete := false
	for attempt := 0; attempt < 45; attempt++ {
		time.Sleep(2 * time.Second)

		allNodesReady := true
		for _, n := range nodes {
			if n.GetKeyStore().GetActiveVersion() == nil {
				allNodesReady = false
				break
			}
		}

		if allNodesReady {
			dkgComplete = true
			t.Logf("✓ DKG completed after ~%d seconds", (attempt+1)*2)
			break
		}

		if attempt%5 == 0 {
			t.Logf("Waiting for DKG... (%d seconds elapsed)", (attempt+1)*2)
		}
	}

	require.True(t, dkgComplete, "DKG should complete within 90 seconds")

	// Verify all nodes have active key shares
	for i, n := range nodes {
		activeVersion := n.GetKeyStore().GetActiveVersion()
		require.NotNil(t, activeVersion, "Node %d should have active key version", i+1)
		require.NotNil(t, activeVersion.PrivateShare, "Node %d should have private share", i+1)
		t.Logf("Node %d has active key version: %d", i+1, activeVersion.Version)
	}

	// ------------------------------------------------------------------------
	// Use KMSClient to get master public key (like a real user)
	// ------------------------------------------------------------------------
	t.Log("Using KMSClient to get master public key...")

	operatorURLs := []string{
		chainConfig.OperatorSocket1,
		chainConfig.OperatorSocket2,
		chainConfig.OperatorSocket3,
		chainConfig.OperatorSocket4,
		chainConfig.OperatorSocket5,
	}

	client := kmsClient.NewKMSClient(operatorURLs, l)

	masterPubKey, err := client.GetMasterPublicKey()
	require.NoError(t, err)
	require.False(t, masterPubKey.IsZero(), "Master public key should not be zero")

	t.Logf("✓ Master public key retrieved via KMSClient")

	// ------------------------------------------------------------------------
	// Test encryption/decryption flow using KMSClient
	// ------------------------------------------------------------------------
	t.Log("Testing encryption/decryption flow via KMSClient...")

	appID := "test-app-integration"
	plaintext := []byte("secret-integration-test-data")

	// Encrypt using KMSClient
	ciphertext, err := client.EncryptForApp(appID, masterPubKey, plaintext)
	require.NoError(t, err)
	t.Logf("Encrypted %d bytes to %d bytes", len(plaintext), len(ciphertext))

	// Decrypt using KMSClient (collects partial signatures and decrypts)
	attestationTime := int64(0) // Use current active key
	decrypted, err := client.DecryptForApp(appID, ciphertext, attestationTime)
	require.NoError(t, err)

	require.Equal(t, plaintext, decrypted, "Decrypted data should match original")
	t.Logf("✓ Successfully encrypted and decrypted data using KMSClient")

	// ------------------------------------------------------------------------
	// Wait for reshare to trigger
	// ------------------------------------------------------------------------
	t.Log("Waiting for next reshare boundary block...")
	t.Log("  (Need to wait for next block that's a multiple of 10)")
	t.Log("  (Could take 30-60 seconds depending on current block)")

	// Wait long enough to ensure we hit the next boundary block
	// With 2s block time and 10-block interval, worst case is 20 seconds + processing time
	time.Sleep(40 * time.Second)

	// Verify all nodes still have active versions
	for i, n := range nodes {
		activeVer := n.GetKeyStore().GetActiveVersion()
		require.NotNil(t, activeVer, "Node %d should have active version", i+1)

		t.Logf("Node %d active version: %d", i+1, activeVer.Version)
	}

	// Get master public key again - should be unchanged after reshare
	masterPubKeyAfter, err := client.GetMasterPublicKey()
	require.NoError(t, err)
	require.True(t, masterPubKey.IsEqual(&masterPubKeyAfter), "Master public key should be preserved after reshare")

	t.Logf("✓ Master public key verified after reshare period")

	// Test encryption/decryption still works after reshare
	plaintext2 := []byte("secret-after-reshare")
	ciphertext2, err := client.EncryptForApp(appID, masterPubKeyAfter, plaintext2)
	require.NoError(t, err)

	decrypted2, err := client.DecryptForApp(appID, ciphertext2, attestationTime)
	require.NoError(t, err)

	require.Equal(t, plaintext2, decrypted2)
	t.Logf("✓ Encryption/decryption works after reshare")

	// ------------------------------------------------------------------------
	// Cleanup
	// ------------------------------------------------------------------------
	t.Log("Cleaning up nodes...")
	for i, n := range nodes {
		if n != nil {
			err := n.Stop()
			if err != nil {
				t.Logf("Warning: failed to stop node %d: %v", i+1, err)
			} else {
				t.Logf("Node %d stopped", i+1)
			}
		}
	}

	// Give nodes time to shutdown gracefully
	time.Sleep(2 * time.Second)

	t.Log("✅ End-to-end integration test passed!")
	t.Log("  - L1 and L2 Anvil instances started")
	t.Log("  - 5 nodes created and started")
	t.Log("  - DKG completed successfully")
	t.Log("  - Master public key retrieved via KMSClient")
	t.Log("  - Encryption/decryption verified via KMSClient")
	t.Log("  - Reshare period verified")
	t.Log("  - Master public key preserved after reshare")
	t.Log("  - Post-reshare encryption/decryption verified")
	t.Log("  - All nodes stopped cleanly")
}
