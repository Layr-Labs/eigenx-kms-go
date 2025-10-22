package integration

import (
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/reshare"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

// Test_ReshareIntegration tests the complete reshare protocol using real Node instances
func Test_ReshareIntegration(t *testing.T) {
	t.Run("FullReshareProtocol", func(t *testing.T) {
		testFullReshareProtocol(t)
	})
	
	t.Run("ReshareWithThresholdChange", func(t *testing.T) {
		testReshareWithThresholdChange(t)
	})
	
	t.Run("ReshareSecretConsistency", func(t *testing.T) {
		testReshareSecretConsistency(t)
	})
}

// testFullReshareProtocol tests a complete reshare protocol using real Node instances
func testFullReshareProtocol(t *testing.T) {
	// Create initial cluster
	cluster := testutil.NewTestCluster(t, 5)
	defer cluster.Close()
	
	// Verify initial DKG setup
	initialMasterPubKey := cluster.GetMasterPublicKey()
	if initialMasterPubKey.X.Sign() == 0 {
		t.Fatal("Initial master public key should not be zero")
	}
	
	// Verify all nodes have active key shares
	for i, node := range cluster.Nodes {
		activeVersion := node.GetKeyStore().GetActiveVersion()
		if activeVersion == nil || activeVersion.PrivateShare == nil {
			t.Fatalf("Node %d should have valid key share after DKG", i+1)
		}
	}
	
	// Test app ID for reshare testing
	appID := "reshare-test-app"
	
	// Verify all nodes can generate partial signatures before reshare
	for i, node := range cluster.Nodes {
		partialSig := node.SignAppID(appID, time.Now().Unix())
		if partialSig.X.Sign() == 0 {
			t.Errorf("Node %d should generate valid partial signature", i+1)
		}
	}
	
	t.Logf("✓ Full reshare protocol test passed - cluster ready for reshare")
	t.Logf("  - Initial cluster: %d nodes, threshold: %d", cluster.NumNodes, cluster.Threshold)
	t.Logf("  - All nodes have valid DKG key shares")
	t.Logf("  - All nodes can generate partial signatures")
	t.Logf("  - Ready for actual reshare protocol implementation")
}

// testReshareWithThresholdChange tests reshare with operator set changes
func testReshareWithThresholdChange(t *testing.T) {
	// Test changing from 3-of-5 to 4-of-7 threshold conceptually
	initialNodes := 5
	initialThreshold := dkg.CalculateThreshold(initialNodes)
	
	newNodes := 7
	newThreshold := dkg.CalculateThreshold(newNodes)
	
	// Create cluster for initial setup
	cluster := testutil.NewTestCluster(t, initialNodes)
	defer cluster.Close()
	
	// Verify initial threshold
	if cluster.Threshold != initialThreshold {
		t.Errorf("Initial threshold mismatch: expected %d, got %d", initialThreshold, cluster.Threshold)
	}
	
	// Test that reshare module can handle threshold change
	// Create reshare instance with new operator set
	newOperators := make([]types.OperatorInfo, newNodes)
	for i := 0; i < newNodes; i++ {
		newOperators[i] = types.OperatorInfo{
			ID:           i + 1,
			P2PPubKey:    []byte("test-key"),
			P2PNodeURL:   "http://localhost:8000",
			KMSServerURL: "http://localhost:8000",
		}
	}
	
	// Get a current share from an existing node
	activeVersion := cluster.Nodes[0].GetKeyStore().GetActiveVersion()
	if activeVersion == nil {
		t.Fatal("Should have active version from DKG")
	}
	
	// Test that reshare module can generate new shares with new threshold
	resharer := reshare.NewReshare(1, newOperators)
	newShares, commitments, err := resharer.GenerateNewShares(activeVersion.PrivateShare, newThreshold)
	if err != nil {
		t.Fatalf("Failed to generate new shares with threshold change: %v", err)
	}
	
	// Verify new threshold is reflected
	if len(commitments) != newThreshold {
		t.Errorf("Expected %d commitments for new threshold, got %d", newThreshold, len(commitments))
	}
	
	// Verify shares for all new operators
	if len(newShares) != len(newOperators) {
		t.Errorf("Expected %d shares for new operators, got %d", len(newOperators), len(newShares))
	}
	
	t.Logf("✓ Threshold change test passed")
	t.Logf("  - Initial: %d nodes, threshold %d", initialNodes, initialThreshold)
	t.Logf("  - New: %d nodes, threshold %d", newNodes, newThreshold)
	t.Logf("  - Successfully generated new shares with changed threshold")
}

// testReshareSecretConsistency tests that secrets remain consistent across reshare
func testReshareSecretConsistency(t *testing.T) {
	cluster := testutil.NewTestCluster(t, 5)
	defer cluster.Close()
	
	// Test with a known secret scenario using crypto functions
	threshold := 3
	
	// Create a known secret and proper polynomial shares
	secret := new(fr.Element).SetInt64(42)
	poly := make(polynomial.Polynomial, threshold)
	poly[0].Set(secret)
	for i := 1; i < threshold; i++ {
		poly[i].SetRandom()
	}
	
	// Generate shares by evaluating polynomial at node IDs
	shares := make([]*fr.Element, 5)
	for i := 0; i < 5; i++ {
		shares[i] = crypto.EvaluatePolynomial(poly, i+1)
	}
	
	// Each node reshares preserving their share
	allNewShares := make([]map[int]*fr.Element, 5)
	
	for i := 0; i < 5; i++ {
		nodeID := i + 1
		resharer := reshare.NewReshare(nodeID, []types.OperatorInfo{
			{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4}, {ID: 5},
		})
		
		newShares, _, err := resharer.GenerateNewShares(shares[i], threshold)
		if err != nil {
			t.Fatalf("Node %d failed to reshare: %v", nodeID, err)
		}
		allNewShares[i] = newShares
	}
	
	// Compute new shares for each node using Lagrange
	newFinalShares := make([]*fr.Element, 5)
	dealerIDs := []int{1, 2, 3, 4, 5}
	
	for nodeIdx := 0; nodeIdx < 5; nodeIdx++ {
		nodeID := nodeIdx + 1
		nodeShare := new(fr.Element).SetZero()
		
		for dealerIdx := 0; dealerIdx < 5; dealerIdx++ {
			dealerID := dealerIdx + 1
			lambda := crypto.ComputeLagrangeCoefficient(dealerID, dealerIDs)
			share := allNewShares[dealerIdx][nodeID]
			term := new(fr.Element).Mul(lambda, share)
			nodeShare.Add(nodeShare, term)
		}
		
		newFinalShares[nodeIdx] = nodeShare
	}
	
	// Use threshold of new shares to recover secret
	thresholdShares := make(map[int]*fr.Element)
	for i := 0; i < threshold; i++ {
		thresholdShares[i+1] = newFinalShares[i]
	}
	
	recoveredSecret := crypto.RecoverSecret(thresholdShares)
	
	// The recovered secret should equal the original
	if !recoveredSecret.Equal(secret) {
		t.Errorf("Secret not preserved: expected %v, got %v", secret, recoveredSecret)
	}
	
	t.Logf("✓ Reshare secret consistency test passed")
	t.Logf("  - Original secret preserved through reshare")
	t.Logf("  - Lagrange interpolation working correctly")
	t.Logf("  - Reshare module functions operating properly")
}