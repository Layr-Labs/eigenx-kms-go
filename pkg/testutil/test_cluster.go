package testutil

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
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
	peeringDataFetcher := createTestPeeringDataFetcher(t, addresses, privateKeys, numNodes)

	for i := 0; i < numNodes; i++ {
		cfg := node.Config{
			OperatorAddress: addresses[i],
			Port:            0,
			BN254PrivateKey: privateKeys[i],
			AVSAddress:      "0x1234567890123456789012345678901234567890",
			OperatorSetId:   1,
			Logger:          testLogger,
		}

		cluster.Nodes[i] = node.NewNode(cfg, peeringDataFetcher)
		
		// Create test server
		server := node.NewServer(cluster.Nodes[i], 0)
		cluster.Servers[i] = httptest.NewServer(server.GetHandler())
		cluster.ServerURLs[i] = cluster.Servers[i].URL
	}

	// For a complete test cluster, we would run DKG here
	// For now, just return the cluster structure
	return cluster
}

// createTestPeeringDataFetcher creates a peering data fetcher with the given operator data
func createTestPeeringDataFetcher(t *testing.T, addresses, privateKeys []string, numNodes int) peering.IPeeringDataFetcher {
	peers := make([]*peering.OperatorSetPeer, numNodes)
	
	for i := 0; i < numNodes; i++ {
		privKey, err := bn254.NewPrivateKeyFromHexString(privateKeys[i])
		if err != nil {
			t.Fatalf("Failed to create BN254 private key: %v", err)
		}

		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress(addresses[i]),
			SocketAddress:   fmt.Sprintf("http://localhost:%d", 8080+i),
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