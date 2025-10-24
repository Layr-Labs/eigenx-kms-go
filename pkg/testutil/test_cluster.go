package testutil

import (
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering/localPeeringDataFetcher"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
)

// TestCluster represents a cluster of KMS nodes for testing  
type TestCluster struct {
	Nodes       []*node.Node
	Servers     []*httptest.Server  
	ServerURLs  []string
	NumNodes    int
	MasterPubKey types.G2Point
}

// NewTestCluster creates a test cluster of KMS nodes with completed DKG
func NewTestCluster(t *testing.T, numNodes int) *TestCluster {
	if numNodes > 5 {
		t.Fatalf("Cannot create more than 5 nodes (limited by ChainConfig)")
	}

	// Get test data from ChainConfig
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	if err != nil {
		t.Fatalf("Failed to read chain config: %v", err)
	}

	addresses := []string{
		chainConfig.OperatorAccountAddress1,
		chainConfig.OperatorAccountAddress2, 
		chainConfig.OperatorAccountAddress3,
		chainConfig.OperatorAccountAddress4,
		chainConfig.OperatorAccountAddress5,
	}
	privateKeys := []string{
		chainConfig.OperatorAccountPrivateKey1,
		chainConfig.OperatorAccountPrivateKey2,
		chainConfig.OperatorAccountPrivateKey3,
		chainConfig.OperatorAccountPrivateKey4,
		chainConfig.OperatorAccountPrivateKey5,
	}

	// Create test cluster
	cluster := &TestCluster{
		Nodes:      make([]*node.Node, numNodes),
		Servers:    make([]*httptest.Server, numNodes),
		ServerURLs: make([]string, numNodes),
		NumNodes:   numNodes,
	}

	// Create nodes with real addresses and keys
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	// First, create test servers to get URLs before creating peering data
	cluster.Servers = make([]*httptest.Server, numNodes)
	cluster.ServerURLs = make([]string, numNodes)

	for i := 0; i < numNodes; i++ {
		// Create placeholder server to get URL
		cluster.Servers[i] = httptest.NewServer(nil)
		cluster.ServerURLs[i] = cluster.Servers[i].URL
	}

	// Now create peering data fetcher with actual server URLs
	peeringDataFetcher := createTestPeeringDataFetcherWithURLs(t, addresses, privateKeys, cluster.ServerURLs, numNodes)

	// Create nodes with proper configuration
	for i := 0; i < numNodes; i++ {
		cfg := node.Config{
			OperatorAddress: addresses[i],
			Port:            0,
			BN254PrivateKey: privateKeys[i],
			ChainID:         config.ChainId_EthereumAnvil, // Use anvil for tests (1 minute reshare)
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
			Logger:          testLogger,
		}

		cluster.Nodes[i] = node.NewNode(cfg, peeringDataFetcher)

		// Replace placeholder server with actual server
		server := node.NewServer(cluster.Nodes[i], 0)
		cluster.Servers[i].Config.Handler = server.GetHandler()
	}

	// Execute coordinated DKG
	t.Logf("Executing DKG with %d nodes...", numNodes)
	if err := executeCoordinatedDKG(t, cluster); err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	// Compute master public key from commitments
	cluster.MasterPubKey = computeMasterPublicKey(cluster)

	t.Logf("✓ Test cluster ready with DKG complete")
	t.Logf("  - Nodes: %d", numNodes)
	t.Logf("  - Threshold: %d", calculateThreshold(numNodes))
	t.Logf("  - Master Public Key: X=%s", cluster.MasterPubKey.X.String()[:20]+"...")

	return cluster
}

// createTestPeeringDataFetcherWithURLs creates a peering data fetcher with actual test server URLs
func createTestPeeringDataFetcherWithURLs(t *testing.T, addresses, privateKeys, serverURLs []string, numNodes int) peering.IPeeringDataFetcher {
	peers := make([]*peering.OperatorSetPeer, numNodes)

	for i := 0; i < numNodes; i++ {
		privKey, err := bn254.NewPrivateKeyFromHexString(privateKeys[i])
		if err != nil {
			t.Fatalf("Failed to create BN254 private key: %v", err)
		}

		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress(addresses[i]),
			SocketAddress:   serverURLs[i], // Use actual test server URL
			WrappedPublicKey: peering.WrappedPublicKey{
				PublicKey:    privKey.Public(),
				ECDSAAddress: common.HexToAddress(addresses[i]),
			},
			CurveType: config.CurveTypeBN254,
		}
	}

	operatorSet := &peering.OperatorSetPeers{
		OperatorSetId: 1,
		AVSAddress:    common.HexToAddress("0x1234567890123456789012345678901234567890"),
		Peers:         peers,
	}

	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	return localPeeringDataFetcher.NewLocalPeeringDataFetcher([]*peering.OperatorSetPeers{operatorSet}, testLogger)
}

// executeCoordinatedDKG runs DKG across all nodes in the cluster
func executeCoordinatedDKG(t *testing.T, cluster *TestCluster) error {
	var wg sync.WaitGroup
	errors := make(chan error, cluster.NumNodes)

	// Start DKG on all nodes concurrently
	for i, n := range cluster.Nodes {
		wg.Add(1)
		go func(nodeIdx int, node *node.Node) {
			defer wg.Done()
			t.Logf("  Starting DKG on node %d (%s)", nodeIdx+1, node.GetOperatorAddress().Hex())
			if err := node.RunDKG(); err != nil {
				t.Logf("  ❌ Node %d DKG failed: %v", nodeIdx+1, err)
				errors <- fmt.Errorf("node %d DKG failed: %w", nodeIdx+1, err)
			} else {
				t.Logf("  ✅ Node %d DKG completed", nodeIdx+1)
			}
		}(i, n)
	}

	// Wait for all nodes with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All completed
		close(errors)
		if len(errors) > 0 {
			return <-errors
		}
		return nil
	case <-time.After(60 * time.Second):
		return fmt.Errorf("DKG timeout after 60 seconds")
	}
}

// computeMasterPublicKey computes the master public key from all node commitments
func computeMasterPublicKey(cluster *TestCluster) types.G2Point {
	var allCommitments [][]types.G2Point

	for _, n := range cluster.Nodes {
		activeVersion := n.GetKeyStore().GetActiveVersion()
		if activeVersion != nil && len(activeVersion.Commitments) > 0 {
			allCommitments = append(allCommitments, activeVersion.Commitments)
		}
	}

	if len(allCommitments) == 0 {
		return types.G2Point{}
	}

	return crypto.ComputeMasterPublicKey(allCommitments)
}

// calculateThreshold calculates the threshold for a given number of nodes
func calculateThreshold(n int) int {
	return (2*n + 2) / 3
}

// GetMasterPublicKey returns the master public key
func (c *TestCluster) GetMasterPublicKey() types.G2Point {
	return c.MasterPubKey
}

// GetServerURLs returns the list of server URLs
func (c *TestCluster) GetServerURLs() []string {
	return c.ServerURLs
}

// Close shuts down all nodes in the cluster
func (c *TestCluster) Close() {
	if c == nil {
		return
	}
	
	for i, server := range c.Servers {
		if server != nil {
			server.Close()
		}
		if i < len(c.Nodes) && c.Nodes[i] != nil {
			_ = c.Nodes[i].Stop()
		}
	}
}