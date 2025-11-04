package testutil

import (
	"fmt"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/blockHandler"
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
	Nodes        []*node.Node
	Servers      []*httptest.Server
	ServerURLs   []string
	NumNodes     int
	MasterPubKey types.G2Point
	MockPoller   *MockChainPoller // Exposed for test control
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

	// Create one block handler per node
	nodeBlockHandlers := make([]blockHandler.IBlockHandler, numNodes)
	for i := 0; i < numNodes; i++ {
		nodeBlockHandlers[i] = blockHandler.NewBlockHandler(testLogger)
	}

	// Create mock poller that broadcasts to all node handlers
	cluster.MockPoller = NewMockChainPoller(nodeBlockHandlers, 5, testLogger)

	// Create nodes with proper configuration
	for i := 0; i < numNodes; i++ {
		portNumber, _ := strconv.Atoi(fmt.Sprintf("750%d", i))
		cfg := node.Config{
			OperatorAddress: addresses[i],
			Port:            portNumber,
			BN254PrivateKey: privateKeys[i],
			ChainID:         config.ChainId_EthereumAnvil, // Use anvil for tests (5 block reshare)
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
		}

		cluster.Nodes[i] = node.NewNode(cfg, peeringDataFetcher, nodeBlockHandlers[i], cluster.MockPoller, testLogger)

		// Replace placeholder server with actual server
		server := node.NewServer(cluster.Nodes[i], 0)
		cluster.Servers[i].Config.Handler = server.GetHandler()

		// Start the node (starts scheduler and server)
		if err := cluster.Nodes[i].Start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", i+1, err)
		}
	}

	// Give all nodes time to start their schedulers
	time.Sleep(200 * time.Millisecond)

	// Emit initial block to initialize the scheduler (block 5)
	t.Logf("Emitting block 5 to initialize scheduler...")
	if err := cluster.MockPoller.EmitBlockAtNumber(5); err != nil {
		t.Fatalf("Failed to emit initial block: %v", err)
	}

	// Give nodes a moment to initialize
	time.Sleep(100 * time.Millisecond)

	// Now emit block 10 to trigger DKG (next interval boundary)
	t.Logf("Emitting block 10 to trigger DKG...")
	if err := cluster.MockPoller.EmitBlockAtNumber(10); err != nil {
		t.Fatalf("Failed to emit trigger block: %v", err)
	}

	// Wait for automatic DKG to complete
	t.Logf("Waiting for automatic DKG to complete...")
	if !WaitForDKGCompletion(cluster, 30*time.Second) {
		t.Fatalf("DKG did not complete within timeout")
	}

	// Compute master public key from commitments
	cluster.MasterPubKey = ComputeMasterPublicKey(cluster)

	t.Logf("✓ Test cluster ready with DKG complete")
	t.Logf("  - Nodes: %d", numNodes)
	t.Logf("  - Block interval: 5 blocks")
	t.Logf("  - Current block: %d", cluster.MockPoller.GetCurrentBlock())
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

// WaitForDKGCompletion polls nodes until all have completed DKG
func WaitForDKGCompletion(cluster *TestCluster, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	checkInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		allComplete := true
		for _, n := range cluster.Nodes {
			if n.GetKeyStore().GetActiveVersion() == nil {
				allComplete = false
				break
			}
		}

		if allComplete {
			return true
		}

		time.Sleep(checkInterval)
	}

	return false
}

// WaitForReshare waits for nodes to complete a reshare (key version change)
// It automatically emits a block to trigger the reshare
func WaitForReshare(cluster *TestCluster, initialVersions map[int]int64, timeout time.Duration) bool {
	// Emit next block to trigger reshare (next interval boundary)
	if err := cluster.MockPoller.EmitBlock(); err != nil {
		return false
	}

	deadline := time.Now().Add(timeout)
	checkInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		reshareOccurred := false
		for i, n := range cluster.Nodes {
			activeVersion := n.GetKeyStore().GetActiveVersion()
			if activeVersion != nil && activeVersion.Version != initialVersions[i] {
				reshareOccurred = true
				break
			}
		}

		if reshareOccurred {
			return true
		}

		time.Sleep(checkInterval)
	}

	return false
}

// ComputeMasterPublicKey computes the master public key from all node commitments
func ComputeMasterPublicKey(cluster *TestCluster) types.G2Point {
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
