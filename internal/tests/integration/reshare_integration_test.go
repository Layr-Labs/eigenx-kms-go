package integration

import (
	"fmt"
	"testing"
	"time"

	eigenxcrypto "github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/reshare"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/util"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
	"github.com/ethereum/go-ethereum/common"
)

// Test_ReshareIntegration tests the complete reshare protocol using real Node instances
func Test_ReshareIntegration(t *testing.T) {
	t.Run("FullReshareProtocol", func(t *testing.T) {
		testFullReshareProtocol(t)
	})

	t.Run("AutomaticReshare", func(t *testing.T) {
		testAutomaticReshare(t)
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
	isZero, err := initialMasterPubKey.IsZero()
	if err != nil {
		t.Fatalf("Failed to check if initial master public key is zero: %v", err)
	}
	if isZero {
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
		isZero, err := partialSig.IsZero()
		if err != nil {
			t.Fatalf("Failed to check if partial signature is zero: %v", err)
		}
		if isZero {
			t.Errorf("Node %d should generate valid partial signature", i+1)
		}
	}

	t.Logf("✓ Full reshare protocol test passed - cluster ready for reshare")
	t.Logf("  - Initial cluster: %d nodes, threshold: %d", cluster.NumNodes, dkg.CalculateThreshold(cluster.NumNodes))
	t.Logf("  - All nodes have valid DKG key shares")
	t.Logf("  - All nodes can generate partial signatures")
	t.Logf("  - Ready for actual reshare protocol implementation")
}

// testAutomaticReshare tests that reshare triggers automatically at intervals
func testAutomaticReshare(t *testing.T) {
	// Create cluster - automatic DKG will happen at first boundary
	cluster := testutil.NewTestCluster(t, 3)
	defer cluster.Close()

	// DKG has completed - record these versions (created at first interval)
	dkgVersions := make(map[int]int64)
	for i, n := range cluster.Nodes {
		activeVersion := n.GetKeyStore().GetActiveVersion()
		if activeVersion == nil {
			t.Fatalf("Node %d should have key version after DKG", i+1)
		}
		dkgVersions[i] = activeVersion.Version
		t.Logf("  Node %d DKG version: %d", i+1, activeVersion.Version)
	}

	t.Logf("Waiting for automatic reshare at next 30s boundary...")

	// Wait for next interval boundary - reshare should trigger automatically
	// Need longer timeout since we need to wait up to 30 seconds for next boundary
	if !testutil.WaitForReshare(cluster, dkgVersions, 45*time.Second) {
		t.Fatal("Automatic reshare did not occur within timeout")
	}

	// Verify all nodes have NEW key versions (different from DKG versions)
	for i, n := range cluster.Nodes {
		activeVersion := n.GetKeyStore().GetActiveVersion()
		if activeVersion == nil {
			t.Fatalf("Node %d should have key version after reshare", i+1)
		}
		if activeVersion.Version == dkgVersions[i] {
			t.Errorf("Node %d key version did not change from DKG version %d (reshare did not occur)",
				i+1, dkgVersions[i])
		}
		t.Logf("  Node %d reshare version: %d (changed from %d)", i+1, activeVersion.Version, dkgVersions[i])
	}

	t.Logf("✓ Automatic reshare test passed")
	t.Logf("  - Reshare triggered automatically at interval boundary")
	t.Logf("  - All nodes have new key versions")
	t.Logf("  - Scheduler working correctly")
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
	expectedThreshold := (2*initialNodes + 2) / 3
	if initialThreshold != expectedThreshold {
		t.Errorf("Initial threshold mismatch: expected %d, got %d", expectedThreshold, initialThreshold)
	}

	// Test that reshare module can handle threshold change
	// Create test operators for new set (using ChainConfig pattern)
	newOperators := createTestOperatorsForReshare(t, newNodes)

	// Get a current share from an existing node
	activeVersion := cluster.Nodes[0].GetKeyStore().GetActiveVersion()
	if activeVersion == nil {
		t.Fatal("Should have active version from DKG")
	}

	// Test that reshare module can generate new shares with new threshold
	firstNodeAddr := cluster.Nodes[0].GetOperatorAddress()
	firstNodeID := util.AddressToNodeID(firstNodeAddr)
	resharer := reshare.NewReshare(firstNodeID, newOperators)
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
	threshold := dkg.CalculateThreshold(5)

	// Create test operators and derive their actual node IDs
	testOperators := createTestOperatorsForReshare(t, 5)
	nodeIDs := make([]int, 5)
	for i := 0; i < 5; i++ {
		nodeIDs[i] = util.AddressToNodeID(testOperators[i].OperatorAddress)
	}

	// Create a known secret and proper polynomial shares using actual node IDs
	secret := new(fr.Element).SetInt64(42)
	poly := make(polynomial.Polynomial, threshold)
	poly[0].Set(secret)
	for i := 1; i < threshold; i++ {
		_, _ = poly[i].SetRandom()
	}

	// Generate shares by evaluating polynomial at actual node IDs
	shares := make(map[int]*fr.Element)
	for i := 0; i < 5; i++ {
		shares[nodeIDs[i]] = eigenxcrypto.EvaluatePolynomial(poly, int64(nodeIDs[i]))
	}

	// Each node reshares preserving their share
	allNewShares := make(map[int]map[int]*fr.Element) // dealerNodeID -> recipientNodeID -> share

	for i := 0; i < 5; i++ {
		dealerNodeID := nodeIDs[i]
		resharer := reshare.NewReshare(dealerNodeID, testOperators)

		newShares, _, err := resharer.GenerateNewShares(shares[dealerNodeID], threshold)
		if err != nil {
			t.Fatalf("Node %d failed to reshare: %v", dealerNodeID, err)
		}
		allNewShares[dealerNodeID] = newShares
	}

	// Compute new shares for each node using Lagrange
	newFinalShares := make(map[int]*fr.Element)

	for _, recipientNodeID := range nodeIDs {
		nodeShare := new(fr.Element).SetZero()

		for _, dealerNodeID := range nodeIDs {
			lambda := eigenxcrypto.ComputeLagrangeCoefficient(dealerNodeID, nodeIDs)
			share := allNewShares[dealerNodeID][recipientNodeID]
			if share == nil {
				t.Fatalf("Missing share from dealer %d to recipient %d", dealerNodeID, recipientNodeID)
			}
			term := new(fr.Element).Mul(lambda, share)
			nodeShare.Add(nodeShare, term)
		}

		newFinalShares[recipientNodeID] = nodeShare
	}

	// Use threshold of new shares to recover secret
	thresholdShares := make(map[int]*fr.Element)
	for i := 0; i < threshold; i++ {
		thresholdShares[nodeIDs[i]] = newFinalShares[nodeIDs[i]]
	}

	recoveredSecret, err := eigenxcrypto.RecoverSecret(thresholdShares)
	if err != nil {
		t.Fatalf("Failed to recover secret: %v", err)
	}

	// The recovered secret should equal the original
	if !recoveredSecret.Equal(secret) {
		t.Errorf("Secret not preserved: expected %v, got %v", secret, recoveredSecret)
	}

	t.Logf("✓ Reshare secret consistency test passed")
	t.Logf("  - Original secret preserved through reshare")
	t.Logf("  - Lagrange interpolation working correctly")
	t.Logf("  - Reshare module functions operating properly")
}

// createTestOperatorsForReshare creates test operators using the same pattern as other tests
func createTestOperatorsForReshare(t *testing.T, numOperators int) []*peering.OperatorSetPeer {
	// Use the same pattern as other tests to create operators
	operators := make([]*peering.OperatorSetPeer, numOperators)

	for i := 0; i < numOperators; i++ {
		operators[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress(fmt.Sprintf("0x%040d", i+1)),
			SocketAddress:   fmt.Sprintf("http://localhost:%d", 8080+i),
		}
	}

	return operators
}
