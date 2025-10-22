package testutil

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/registry"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// TestCluster represents a cluster of KMS nodes for testing
type TestCluster struct {
	Nodes       []*node.Node
	Servers     []*httptest.Server
	ServerURLs  []string
	Operators   []types.OperatorInfo
	NumNodes    int
	Threshold   int
	MasterPubKey types.G2Point
	logger      *zap.Logger
}

// NewTestCluster creates a test cluster of KMS nodes with completed DKG
func NewTestCluster(t *testing.T, numNodes int) *TestCluster {
	threshold := dkg.CalculateThreshold(numNodes)

	// Create operators
	operators := make([]types.OperatorInfo, numNodes)
	for i := 0; i < numNodes; i++ {
		operators[i] = types.OperatorInfo{
			ID:           i + 1,
			P2PPubKey:    []byte(fmt.Sprintf("pubkey-%d", i+1)),
			P2PNodeURL:   fmt.Sprintf("http://node%d", i+1),
			KMSServerURL: fmt.Sprintf("http://kms%d", i+1),
		}
	}

	// Create peering data fetcher for testing
	clusterLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	peeringDataFetcher := createTestPeeringDataFetcher(operators, clusterLogger)

	// Create nodes
	nodes := make([]*node.Node, numNodes)
	for i := 0; i < numNodes; i++ {
		cfg := node.Config{
			ID:         i + 1,
			Port:       8000 + i + 1,
			P2PPrivKey: []byte(fmt.Sprintf("privkey-%d", i+1)),
			P2PPubKey:  []byte(fmt.Sprintf("pubkey-%d", i+1)),
			Operators:  operators,
			Logger:     clusterLogger,
		}

		nodes[i] = node.NewNode(cfg, peeringDataFetcher)
	}

	// Run DKG to establish shared keys
	cluster := &TestCluster{
		Nodes:     nodes,
		Operators: operators,
		NumNodes:  numNodes,
		Threshold: threshold,
		logger:    clusterLogger,
	}

	if err := cluster.RunDKG(); err != nil {
		t.Fatalf("Failed to run DKG: %v", err)
	}

	// Start HTTP servers
	cluster.startServers()

	// Add test releases to all nodes
	cluster.addTestReleases()

	return cluster
}

// RunDKG executes the DKG protocol across all nodes  
func (tc *TestCluster) RunDKG() error {
	sugar := tc.logger.Sugar()
	sugar.Infow("Running DKG", "nodes", tc.NumNodes, "threshold", tc.Threshold)

	// Each node runs DKG
	allShares := make([]map[int]*fr.Element, tc.NumNodes)
	allCommitments := make([][][]types.G2Point, tc.NumNodes)

	// Phase 1: Generate shares and commitments
	for i, n := range tc.Nodes {
		shares, commitments, err := n.RunDKGPhase1()
		if err != nil {
			return fmt.Errorf("node %d DKG phase 1 failed: %w", i+1, err)
		}
		allShares[i] = shares
		allCommitments[i] = [][]types.G2Point{commitments}
	}

	// Phase 2: Distribute shares and verify  
	for i, n := range tc.Nodes {
		// Node receives its own share
		if err := n.ReceiveShare(n.GetID(), allShares[i][n.GetID()], allCommitments[i][0]); err != nil {
			return fmt.Errorf("node %d failed to receive own share: %w", i+1, err)
		}
		
		// Receive shares from other nodes
		for j, sourceNode := range tc.Nodes {
			if i == j {
				continue
			}
			
			// Node i receives share from node j
			share := allShares[j][n.GetID()]
			commitments := allCommitments[j][0]
			
			if err := n.ReceiveShare(sourceNode.GetID(), share, commitments); err != nil {
				return fmt.Errorf("node %d failed to receive share from node %d: %w", i+1, j+1, err)
			}
		}
	}

	// Phase 3: Finalize all nodes
	masterPubKeyCommitments := make([][]types.G2Point, 0)
	for i := range tc.Nodes {
		masterPubKeyCommitments = append(masterPubKeyCommitments, allCommitments[i][0])
	}
	
	tc.MasterPubKey = crypto.ComputeMasterPublicKey(masterPubKeyCommitments)
	
	// Finalize key shares for each node
	for i, n := range tc.Nodes {
		participantIDs := make([]int, tc.NumNodes)
		for j := 0; j < tc.NumNodes; j++ {
			participantIDs[j] = j + 1
		}
		
		if err := n.FinalizeDKG(masterPubKeyCommitments, participantIDs); err != nil {
			return fmt.Errorf("node %d failed to finalize DKG: %w", i+1, err)
		}
	}
	
	sugar.Infow("DKG completed", "master_public_key", fmt.Sprintf("%x", tc.MasterPubKey.X.Bytes()[:8]))

	return nil
}

// startServers starts HTTP test servers for all nodes
func (tc *TestCluster) startServers() {
	tc.Servers = make([]*httptest.Server, tc.NumNodes)
	tc.ServerURLs = make([]string, tc.NumNodes)

	for i, n := range tc.Nodes {
		server := node.NewServer(n, 0)
		testServer := httptest.NewServer(server.GetHandler())
		
		tc.Servers[i] = testServer
		tc.ServerURLs[i] = testServer.URL
		
		tc.logger.Sugar().Debugw("Started server", "node", i+1, "url", testServer.URL)
	}
}

// addTestReleases adds test application releases to all nodes
func (tc *TestCluster) addTestReleases() {
	testApps := map[string]*types.Release{
		"test-app": {
			ImageDigest:  "sha256:test123",
			EncryptedEnv: "encrypted-secrets-for-test-app",
			PublicEnv:    "NODE_ENV=test",
			Timestamp:    time.Now().Unix(),
		},
		"demo-app": {
			ImageDigest:  "sha256:demo456",
			EncryptedEnv: "encrypted-secrets-for-demo-app",
			PublicEnv:    "NODE_ENV=demo",
			Timestamp:    time.Now().Unix(),
		},
		"production-app": {
			ImageDigest:  "sha256:prod789",
			EncryptedEnv: "encrypted-secrets-for-production-app",
			PublicEnv:    "NODE_ENV=production",
			Timestamp:    time.Now().Unix(),
		},
	}

	for _, n := range tc.Nodes {
		if stubRegistry, ok := n.GetReleaseRegistry().(*registry.StubClient); ok {
			for appID, release := range testApps {
				stubRegistry.AddTestRelease(appID, release)
			}
		}
	}

	tc.logger.Sugar().Debugw("Added test releases", "applications", len(testApps))
}

// GetServerURLs returns the HTTP server URLs for the test cluster
func (tc *TestCluster) GetServerURLs() []string {
	return tc.ServerURLs
}

// GetMasterPublicKey returns the master public key from DKG
func (tc *TestCluster) GetMasterPublicKey() types.G2Point {
	return tc.MasterPubKey
}

// Close shuts down all test servers
func (tc *TestCluster) Close() {
	for i, server := range tc.Servers {
		if server != nil {
			server.Close()
			tc.logger.Sugar().Debugw("Closed server", "node", i+1)
		}
	}
}

// SimulateReshare simulates a reshare operation changing the operator set
func (tc *TestCluster) SimulateReshare(newOperatorIDs []int) error {
	reshareLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	reshareLogger.Sugar().Infow("Simulating reshare", "new_operator_set", newOperatorIDs)

	// Update operator set for all participating nodes
	newOperators := make([]types.OperatorInfo, len(newOperatorIDs))
	for i, id := range newOperatorIDs {
		// Find existing operator info or create new
		var opInfo types.OperatorInfo
		found := false
		for _, existingOp := range tc.Operators {
			if existingOp.ID == id {
				opInfo = existingOp
				found = true
				break
			}
		}
		if !found {
			// Create new operator info for joining node
			opInfo = types.OperatorInfo{
				ID:           id,
				P2PPubKey:    []byte(fmt.Sprintf("pubkey-%d", id)),
				P2PNodeURL:   fmt.Sprintf("http://node%d", id),
				KMSServerURL: fmt.Sprintf("http://kms%d", id),
			}
		}
		newOperators[i] = opInfo
	}

	// Update operator set
	tc.Operators = newOperators
	newThreshold := dkg.CalculateThreshold(len(newOperatorIDs))

	// Run reshare on participating nodes
	participatingNodeIDs := make([]int, 0)
	for _, nodeID := range newOperatorIDs {
		if nodeID <= tc.NumNodes { // Only existing nodes can participate
			participatingNodeIDs = append(participatingNodeIDs, nodeID)
		}
	}

	for _, nodeID := range participatingNodeIDs {
		n := tc.Nodes[nodeID-1]
		
		// Update the node's operator set
		n.UpdateOperatorSet(newOperators)
		
		if err := n.RunReshare(); err != nil {
			return fmt.Errorf("node %d reshare failed: %w", nodeID, err)
		}
	}

	tc.Threshold = newThreshold
	reshareLogger.Sugar().Infow("Reshare completed", "new_threshold", newThreshold)
	
	return nil
}

// createTestPeeringDataFetcher creates a local peering data fetcher for testing
func createTestPeeringDataFetcher(operators []types.OperatorInfo, clusterLogger *zap.Logger) peering.IPeeringDataFetcher {
	// Use the stub for testing since we don't need real peering functionality in tests
	return peering.NewStubPeeringDataFetcher(nil)
}