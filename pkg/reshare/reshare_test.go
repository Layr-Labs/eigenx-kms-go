package reshare

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func Test_ReshareProtocol(t *testing.T) {
	t.Run("NewReshare", func(t *testing.T) { testNewReshare(t) })
	t.Run("GenerateNewShares", func(t *testing.T) { testGenerateNewShares(t) })
	t.Run("GenerateNewSharesNilCurrentShare", func(t *testing.T) { testGenerateNewSharesNilCurrentShare(t) })
	t.Run("VerifyNewShare", func(t *testing.T) { testVerifyNewShare(t) })
	t.Run("ComputeNewKeyShare", func(t *testing.T) { testComputeNewKeyShare(t) })
	t.Run("CreateCompletionSignature", func(t *testing.T) { testCreateCompletionSignature(t) })
}

// testNewReshare tests reshare instance creation
func testNewReshare(t *testing.T) {
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

// testGenerateNewShares tests new share generation with current share as constant
func testGenerateNewShares(t *testing.T) {
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

// testGenerateNewSharesNilCurrentShare tests error handling for nil current share
func testGenerateNewSharesNilCurrentShare(t *testing.T) {
	operators := createTestOperators(3)
	r := NewReshare(1, operators)
	
	_, _, err := r.GenerateNewShares(nil, 2)
	if err == nil {
		t.Error("Expected error for nil current share")
	}
}

// testVerifyNewShare tests new share verification
func testVerifyNewShare(t *testing.T) {
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

// testComputeNewKeyShare tests new key share computation using Lagrange
func testComputeNewKeyShare(t *testing.T) {
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

// testCreateCompletionSignature tests completion signature creation
func testCreateCompletionSignature(t *testing.T) {
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
