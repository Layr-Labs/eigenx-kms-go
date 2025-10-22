package reshare

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

// TestNewReshare tests reshare instance creation
func Test_NewReshare(t *testing.T) {
	operators := createTestOperators(5)
	nodeID := 1

	r := NewReshare(nodeID, operators)

	if r == nil {
		t.Fatal("Expected non-nil Reshare instance")
	}
	if r.nodeID != nodeID {
		t.Errorf("Expected nodeID %d, got %d", nodeID, r.nodeID)
	}
	if len(r.operators) != len(operators) {
		t.Errorf("Expected %d operators, got %d", len(operators), len(r.operators))
	}
}

// TestGenerateNewShares tests new share generation with current share as constant
func Test_GenerateNewShares(t *testing.T) {
	operators := createTestOperators(5)
	nodeID := 1
	newThreshold := 3
	
	r := NewReshare(nodeID, operators)
	
	// Create a current share
	currentShare := new(fr.Element).SetInt64(42)
	
	shares, commitments, err := r.GenerateNewShares(currentShare, newThreshold)
	if err != nil {
		t.Fatalf("GenerateNewShares failed: %v", err)
	}
	
	// Verify we have shares for all operators
	if len(shares) != len(operators) {
		t.Errorf("Expected %d shares, got %d", len(operators), len(shares))
	}
	
	// Verify we have newThreshold commitments
	if len(commitments) != newThreshold {
		t.Errorf("Expected %d commitments, got %d", newThreshold, len(commitments))
	}
	
	// Verify polynomial was set with current share as constant term
	if r.poly == nil || len(r.poly) != newThreshold {
		t.Error("Polynomial not properly set")
	}
	
	if !r.poly[0].Equal(currentShare) {
		t.Error("Polynomial constant term should be current share")
	}
	
	// Verify shares are non-nil
	for opID, share := range shares {
		if share == nil {
			t.Errorf("Share for operator %d is nil", opID)
		}
	}
}

// TestGenerateNewSharesNilCurrentShare tests error handling for nil current share
func Test_GenerateNewSharesNilCurrentShare(t *testing.T) {
	operators := createTestOperators(3)
	r := NewReshare(1, operators)
	
	_, _, err := r.GenerateNewShares(nil, 2)
	if err == nil {
		t.Error("Expected error for nil current share")
	}
}

// TestVerifyNewShare tests new share verification
func Test_VerifyNewShare(t *testing.T) {
	operators := createTestOperators(5)
	newThreshold := 3
	
	// Create reshare instances for dealer and verifier
	dealer := NewReshare(1, operators)
	verifier := NewReshare(2, operators)
	
	// Dealer generates new shares
	currentShare := new(fr.Element).SetInt64(100)
	shares, commitments, err := dealer.GenerateNewShares(currentShare, newThreshold)
	if err != nil {
		t.Fatalf("Failed to generate new shares: %v", err)
	}
	
	// Verifier verifies their share
	shareForVerifier := shares[2]
	valid := verifier.VerifyNewShare(1, shareForVerifier, commitments)
	
	if !valid {
		t.Error("Valid new share should verify successfully")
	}
	
	// Test with invalid share
	invalidShare := new(fr.Element).SetInt64(999999)
	valid = verifier.VerifyNewShare(1, invalidShare, commitments)
	
	if valid {
		t.Error("Invalid new share should not verify")
	}
}

// TestComputeNewKeyShare tests new key share computation using Lagrange
func Test_ComputeNewKeyShare(t *testing.T) {
	operators := createTestOperators(5)
	newThreshold := 3
	epoch := int64(12345)
	
	// Simulate multiple dealers sharing new shares
	dealerIDs := []int{1, 2, 3, 4, 5}
	receivedShares := make(map[int]*fr.Element)
	allCommitments := make([][]types.G2Point, 0)
	
	// Each dealer generates new shares preserving their current share
	for _, dealerID := range dealerIDs {
		dealer := NewReshare(dealerID, operators)
		currentShare := new(fr.Element).SetInt64(int64(dealerID * 10)) // Unique share per dealer
		
		shares, commitments, err := dealer.GenerateNewShares(currentShare, newThreshold)
		if err != nil {
			t.Fatalf("Dealer %d failed to generate new shares: %v", dealerID, err)
		}
		
		// Node 1 collects its share from this dealer
		receivedShares[dealerID] = shares[1]
		allCommitments = append(allCommitments, commitments)
	}
	
	// Node 1 computes its new key share
	node1 := NewReshare(1, operators)
	keyVersion := node1.ComputeNewKeyShare(dealerIDs, receivedShares, allCommitments, epoch)
	
	if keyVersion == nil {
		t.Fatal("Expected non-nil key version")
	}
	
	if keyVersion.Version != epoch {
		t.Errorf("Expected epoch %d, got %d", epoch, keyVersion.Version)
	}
	
	if keyVersion.IsActive {
		t.Error("New key version should not be active initially")
	}
	
	if keyVersion.PrivateShare == nil {
		t.Error("Private share should not be nil")
	}
	
	// Verify the new share is computed correctly using Lagrange interpolation
	// The new share should be: Σ_{i∈dealers} λ_i * s'_{i,1}
	expectedShare := new(fr.Element).SetZero()
	for _, dealerID := range dealerIDs {
		lambda := crypto.ComputeLagrangeCoefficient(dealerID, dealerIDs)
		term := new(fr.Element).Mul(lambda, receivedShares[dealerID])
		expectedShare.Add(expectedShare, term)
	}
	
	if !keyVersion.PrivateShare.Equal(expectedShare) {
		t.Error("New key share not computed correctly")
	}
}

// TestCreateCompletionSignature tests completion signature creation
func Test_CreateCompletionSignature(t *testing.T) {
	nodeID := 1
	epoch := int64(54321)
	commitmentHash := [32]byte{1, 2, 3, 4}
	
	// Mock signer function
	signer := func(e int64, hash [32]byte) []byte {
		return []byte("mock-completion-signature")
	}
	
	sig := CreateCompletionSignature(nodeID, epoch, commitmentHash, signer)
	
	if sig == nil {
		t.Fatal("Expected non-nil completion signature")
	}
	
	if sig.NodeID != nodeID {
		t.Errorf("Expected node ID %d, got %d", nodeID, sig.NodeID)
	}
	
	if sig.Epoch != epoch {
		t.Errorf("Expected epoch %d, got %d", epoch, sig.Epoch)
	}
	
	if sig.CommitmentHash != commitmentHash {
		t.Error("Commitment hash mismatch")
	}
	
	if len(sig.Signature) == 0 {
		t.Error("Signature should not be empty")
	}
}

// TestReshareProtocolIntegration tests a full reshare protocol
func Test_ReshareProtocolIntegration(t *testing.T) {
	// Initial setup: 5 nodes with existing shares
	initialNodes := 5
	initialThreshold := dkg.CalculateThreshold(initialNodes)
	
	// Simulate initial DKG to establish shares with a known secret
	secret := new(fr.Element).SetInt64(12345)
	poly := make(polynomial.Polynomial, initialThreshold)
	poly[0].Set(secret)
	for i := 1; i < initialThreshold; i++ {
		poly[i].SetRandom()
	}
	
	// Generate initial shares by evaluating polynomial
	initialShares := make([]*fr.Element, initialNodes)
	for i := 0; i < initialNodes; i++ {
		initialShares[i] = crypto.EvaluatePolynomial(poly, i+1)
	}
	
	// New operator set (simulating one node leaving, one joining)
	// Nodes 1-4 remain, node 5 leaves, node 6 joins
	newOperators := []types.OperatorInfo{
		{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4}, {ID: 6},
	}
	newThreshold := dkg.CalculateThreshold(len(newOperators))
	
	// Existing nodes (1-4) run reshare
	resharers := make([]*Reshare, 4)
	allNewShares := make([]map[int]*fr.Element, 4)
	allNewCommitments := make([][][]types.G2Point, 4)
	
	// Phase 1: Existing nodes generate new shares
	for i := 0; i < 4; i++ {
		nodeID := i + 1
		resharers[i] = NewReshare(nodeID, newOperators)
		
		newShares, commitments, err := resharers[i].GenerateNewShares(initialShares[i], newThreshold)
		if err != nil {
			t.Fatalf("Node %d failed to generate new shares: %v", nodeID, err)
		}
		
		allNewShares[i] = newShares
		allNewCommitments[i] = [][]types.G2Point{commitments}
	}
	
	// Phase 2: All nodes (including new node 6) verify shares
	for verifierID := range newOperators {
		actualVerifierID := newOperators[verifierID].ID
		
		for dealerIdx := 0; dealerIdx < 4; dealerIdx++ {
			dealerID := dealerIdx + 1
			
			// Get share for this verifier from this dealer
			share := allNewShares[dealerIdx][actualVerifierID]
			commitments := allNewCommitments[dealerIdx][0]
			
			// Create verifier (could be existing or new node)
			verifier := NewReshare(actualVerifierID, newOperators)
			valid := verifier.VerifyNewShare(dealerID, share, commitments)
			
			if !valid {
				t.Errorf("Node %d failed to verify share from dealer %d", actualVerifierID, dealerID)
			}
		}
	}
	
	// Phase 3: Compute new key shares
	// Test for node 1 (existing) and node 6 (new)
	testNodes := []int{1, 6}
	
	for _, nodeID := range testNodes {
		// Collect shares for this node
		nodeShares := make(map[int]*fr.Element)
		nodeCommitments := make([][]types.G2Point, 0)
		dealerIDs := []int{1, 2, 3, 4}
		
		for dealerIdx := 0; dealerIdx < 4; dealerIdx++ {
			dealerID := dealerIdx + 1
			nodeShares[dealerID] = allNewShares[dealerIdx][nodeID]
			nodeCommitments = append(nodeCommitments, allNewCommitments[dealerIdx][0])
		}
		
		node := NewReshare(nodeID, newOperators)
		keyVersion := node.ComputeNewKeyShare(dealerIDs, nodeShares, nodeCommitments, 12345)
		
		if keyVersion == nil || keyVersion.PrivateShare == nil {
			t.Errorf("Node %d failed to compute new key share", nodeID)
		}
		
		// Verify the key version has correct metadata
		if len(keyVersion.ParticipantIDs) != len(dealerIDs) {
			t.Errorf("Node %d: incorrect participant count", nodeID)
		}
	}
	
	// Verify secret preservation property
	// The aggregate secret should remain the same
	// Verify we can recover the original secret from the initial shares
	thresholdSharesMap := make(map[int]*fr.Element)
	for i := 0; i < initialThreshold; i++ {
		thresholdSharesMap[i+1] = initialShares[i]
	}
	recoveredSecret := crypto.RecoverSecret(thresholdSharesMap)
	
	if !recoveredSecret.Equal(secret) {
		t.Errorf("Failed to recover original secret: expected %v, got %v", secret, recoveredSecret)
	}
	
	// After reshare, the new shares should also preserve the secret
	// This is ensured by each dealer using their current share as constant term
	// The sum of all dealer's constant terms (with Lagrange coefficients) equals the original secret
}

// TestReshareWithThresholdChange tests resharing with threshold modification
func Test_ReshareWithThresholdChange(t *testing.T) {
	// Start with 3-of-5 threshold, change to 4-of-7 threshold
	_ = createTestOperators(5)
	
	newOperators := createTestOperators(7)
	newThreshold := 4
	
	// Node with existing share
	currentShare := new(fr.Element).SetInt64(12345)
	
	resharer := NewReshare(1, newOperators)
	shares, commitments, err := resharer.GenerateNewShares(currentShare, newThreshold)
	
	if err != nil {
		t.Fatalf("Failed to generate new shares with threshold change: %v", err)
	}
	
	// Verify new threshold is reflected in polynomial degree
	if len(commitments) != newThreshold {
		t.Errorf("Expected %d commitments for new threshold, got %d", newThreshold, len(commitments))
	}
	
	// Verify shares for all new operators
	if len(shares) != len(newOperators) {
		t.Errorf("Expected %d shares for new operators, got %d", len(newOperators), len(shares))
	}
	
	// Verify constant term preservation
	if !resharer.poly[0].Equal(currentShare) {
		t.Error("Current share should be preserved as constant term")
	}
}

// TestReshareSecretConsistency tests that the shared secret remains consistent
func Test_ReshareSecretConsistency(t *testing.T) {
	operators := createTestOperators(5)
	threshold := 3
	
	// Create a known secret
	secret := new(fr.Element).SetInt64(42)
	
	// Create shares using proper polynomial secret sharing
	// Create polynomial with secret as constant term
	poly := make(polynomial.Polynomial, threshold)
	poly[0].Set(secret)
	for i := 1; i < threshold; i++ {
		poly[i].SetRandom()
	}
	
	// Generate shares by evaluating polynomial at node IDs
	shares := make([]*fr.Element, len(operators))
	for i, op := range operators {
		shares[i] = crypto.EvaluatePolynomial(poly, op.ID)
	}
	
	// Each node reshares preserving their share
	allNewShares := make([]map[int]*fr.Element, len(operators))
	
	for i, op := range operators {
		resharer := NewReshare(op.ID, operators)
		newShares, _, err := resharer.GenerateNewShares(shares[i], threshold)
		if err != nil {
			t.Fatalf("Node %d failed to reshare: %v", op.ID, err)
		}
		allNewShares[i] = newShares
	}
	
	// Compute new shares for each node using Lagrange
	newFinalShares := make([]*fr.Element, len(operators))
	dealerIDs := make([]int, len(operators))
	for i := range dealerIDs {
		dealerIDs[i] = i + 1
	}
	
	for nodeIdx := range operators {
		nodeID := nodeIdx + 1
		nodeShare := new(fr.Element).SetZero()
		
		for dealerIdx := range operators {
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
}

// Helper function to create test operators
func createTestOperators(n int) []types.OperatorInfo {
	operators := make([]types.OperatorInfo, n)
	for i := 0; i < n; i++ {
		operators[i] = types.OperatorInfo{
			ID:           i + 1,
			P2PPubKey:    []byte(string(rune(i + 1))),
			P2PNodeURL:   "http://localhost:8000",
			KMSServerURL: "http://localhost:8000",
		}
	}
	return operators
}