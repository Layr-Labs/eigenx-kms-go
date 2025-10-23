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
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
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

	// Create test operators for the cluster
	testOperators := make([]types.OperatorInfo, numNodes)
	for i := 0; i < numNodes; i++ {
		testOperators[i] = types.OperatorInfo{
			ID:           i + 1,
			P2PPubKey:    []byte(fmt.Sprintf("pubkey-%d", i+1)),
			P2PNodeURL:   fmt.Sprintf("http://node%d", i+1),
			KMSServerURL: fmt.Sprintf("http://kms%d", i+1),
		}
	}

	// Create peering data fetcher for testing
	clusterLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	peeringDataFetcher := createTestPeeringDataFetcher(testOperators, clusterLogger)

	// Create nodes (no operators at startup - fetched dynamically)
	nodes := make([]*node.Node, numNodes)
	for i := 0; i < numNodes; i++ {
		cfg := node.Config{
			OperatorAddress: fmt.Sprintf("0x%040d", i+1), // Mock addresses
			Port:            8000 + i + 1,
			BN254PrivateKey: fmt.Sprintf("%064d", i+1), // Simple test keys
			Logger:          clusterLogger,
		}

		nodes[i] = node.NewNode(cfg, peeringDataFetcher)
	}

	// Run DKG to establish shared keys
	cluster := &TestCluster{
		Nodes:     nodes,
		Operators: testOperators, // Store for reference/testing
		NumNodes:  numNodes,
		Threshold: threshold,
		logger:    clusterLogger,
	}

	if err := cluster.RunDKGWithOperators(testOperators); err != nil {
		t.Fatalf("Failed to run DKG: %v", err)
	}

	// Start HTTP servers
	cluster.startServers()

	// Add test releases to all nodes
	cluster.addTestReleases()

	return cluster
}

// RunDKGWithOperators executes the DKG protocol with specified operators
func (tc *TestCluster) RunDKGWithOperators(operators []types.OperatorInfo) error {
	sugar := tc.logger.Sugar()
	sugar.Infow("Running DKG", "nodes", tc.NumNodes, "threshold", tc.Threshold)

	// For testing, we'll simulate a successful DKG by directly adding key shares
	// In production, nodes would communicate via HTTP to exchange shares
	
	// Create a test master secret and distribute shares
	threshold := tc.Threshold
	masterSecret := new(fr.Element).SetInt64(int64(time.Now().Unix() % 1000000))
	
	// Create polynomial with master secret
	poly := make(polynomial.Polynomial, threshold)
	poly[0].Set(masterSecret)
	for i := 1; i < threshold; i++ {
		poly[i].SetRandom()
	}
	
	// Give each node their share directly (simulates completed DKG)
	for i, n := range tc.Nodes {
		nodeID := i + 1
		keyShare := crypto.EvaluatePolynomial(poly, nodeID)
		
		// Create a key version for this node
		keyVersion := &types.KeyShareVersion{
			Version:        time.Now().Unix(),
			PrivateShare:   keyShare,
			Commitments:    []types.G2Point{},
			IsActive:       true,
			ParticipantIDs: make([]int, tc.NumNodes),
		}
		
		for j := 0; j < tc.NumNodes; j++ {
			keyVersion.ParticipantIDs[j] = j + 1
		}
		
		// Add the key version to the node's keystore
		n.GetKeyStore().AddVersion(keyVersion)
		
		sugar.Debugw("Added test key share", "node", nodeID, "share_set", true)
	}
	
	// Compute master public key for the cluster
	tc.MasterPubKey = crypto.ScalarMulG2(crypto.G2Generator, masterSecret)
	
	sugar.Infow("DKG simulation completed", "nodes", tc.NumNodes, "master_public_key", fmt.Sprintf("%x", tc.MasterPubKey.X.Bytes()[:8]))
	
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
	// For testing, create a mock master public key
	// In real implementation, this would be computed from DKG commitments
	if tc.MasterPubKey.X == nil {
		// Create a test master public key
		tc.MasterPubKey = crypto.ScalarMulG2(crypto.G2Generator, 
			func() *fr.Element { e := new(fr.Element); e.SetInt64(12345); return e }())
	}
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

	// TODO: Implement actual reshare with dynamic operator fetching
	// For now, just update the threshold
	tc.logger.Sugar().Infow("Reshare simulation completed", "old_operators", tc.NumNodes, "new_operators", len(newOperatorIDs))

	tc.Threshold = newThreshold
	reshareLogger.Sugar().Infow("Reshare completed", "new_threshold", newThreshold)
	
	return nil
}

// createTestPeeringDataFetcher creates a local peering data fetcher for testing
func createTestPeeringDataFetcher(operators []types.OperatorInfo, clusterLogger *zap.Logger) peering.IPeeringDataFetcher {
	// Use the stub for testing since we don't need real peering functionality in tests
	return peering.NewStubPeeringDataFetcher(nil)
}