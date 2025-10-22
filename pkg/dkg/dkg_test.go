package dkg

import (
	"math/big"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Test_DKGProtocol runs all DKG protocol tests
func Test_DKGProtocol(t *testing.T) {
	t.Run("CalculateThreshold", func(t *testing.T) { testCalculateThreshold(t) })
	t.Run("NewDKG", func(t *testing.T) { testNewDKG(t) })
	t.Run("GenerateShares", func(t *testing.T) { testGenerateShares(t) })
	t.Run("VerifyShare", func(t *testing.T) { testVerifyShare(t) })
	t.Run("FinalizeKeyShare", func(t *testing.T) { testFinalizeKeyShare(t) })
	t.Run("CreateAcknowledgement", func(t *testing.T) { testCreateAcknowledgement(t) })
	t.Run("DKGProtocolIntegration", func(t *testing.T) { testDKGProtocolIntegration(t) })
}

// testCalculateThreshold tests threshold calculation
func testCalculateThreshold(t *testing.T) {
	tests := []struct {
		n         int
		expected  int
		desc      string
	}{
		{1, 1, "single node"},
		{2, 2, "two nodes"},
		{3, 2, "three nodes"},
		{4, 3, "four nodes"},
		{5, 4, "five nodes"},
		{6, 4, "six nodes"},
		{7, 5, "seven nodes"},
		{10, 7, "ten nodes"},
		{100, 67, "hundred nodes"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := CalculateThreshold(tt.n)
			if result != tt.expected {
				t.Errorf("CalculateThreshold(%d) = %d, expected %d", tt.n, result, tt.expected)
			}
		})
	}
}

// testNewDKG tests DKG instance creation
func testNewDKG(t *testing.T) {
	operators := createTestOperators(5)
	nodeID := 1
	threshold := CalculateThreshold(len(operators))

	dkg := NewDKG(nodeID, threshold, operators)

	if dkg == nil {
		t.Fatal("Expected non-nil DKG instance")
	}
	if dkg.nodeID != nodeID {
		t.Errorf("Expected nodeID %d, got %d", nodeID, dkg.nodeID)
	}
	if dkg.threshold != threshold {
		t.Errorf("Expected threshold %d, got %d", threshold, dkg.threshold)
	}
	if len(dkg.operators) != len(operators) {
		t.Errorf("Expected %d operators, got %d", len(operators), len(dkg.operators))
	}
}

// testGenerateShares tests share generation
func testGenerateShares(t *testing.T) {
	operators := createTestOperators(5)
	nodeID := 1
	threshold := CalculateThreshold(len(operators))
	
	d := NewDKG(nodeID, threshold, operators)
	
	shares, commitments, err := d.GenerateShares()
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}
	
	// Verify we have shares for all operators
	if len(shares) != len(operators) {
		t.Errorf("Expected %d shares, got %d", len(operators), len(shares))
	}
	
	// Verify we have threshold commitments
	if len(commitments) != threshold {
		t.Errorf("Expected %d commitments, got %d", threshold, len(commitments))
	}
	
	// Verify shares are non-nil
	for opID, share := range shares {
		if share == nil {
			t.Errorf("Share for operator %d is nil", opID)
		}
	}
	
	// Verify commitments are valid
	for i, commitment := range commitments {
		if commitment.X == nil || commitment.Y == nil {
			t.Errorf("Commitment %d has nil values", i)
		}
	}
	
	// Verify polynomial was set
	if d.poly == nil || len(d.poly) != threshold {
		t.Error("Polynomial not properly set")
	}
}

// testVerifyShare tests share verification
func testVerifyShare(t *testing.T) {
	operators := createTestOperators(5)
	
	// Create two DKG instances
	dealer := NewDKG(1, CalculateThreshold(len(operators)), operators)
	verifier := NewDKG(2, CalculateThreshold(len(operators)), operators)
	
	// Dealer generates shares
	shares, commitments, err := dealer.GenerateShares()
	if err != nil {
		t.Fatalf("Failed to generate shares: %v", err)
	}
	
	// Verifier verifies their share
	shareForVerifier := shares[2]
	valid := verifier.VerifyShare(1, shareForVerifier, commitments)
	
	if !valid {
		t.Error("Valid share should verify successfully")
	}
}

// testFinalizeKeyShare tests key share finalization
func testFinalizeKeyShare(t *testing.T) {
	operators := createTestOperators(3)
	participantIDs := []int{1, 2, 3}
	
	// Create shares from multiple dealers
	shares := make(map[int]*fr.Element)
	allCommitments := make([][]types.G2Point, 0)
	
	for i, op := range operators {
		dealer := NewDKG(op.ID, CalculateThreshold(len(operators)), operators)
		dealerShares, commitments, err := dealer.GenerateShares()
		if err != nil {
			t.Fatalf("Dealer %d failed to generate shares: %v", op.ID, err)
		}
		
		// Node 1 collects its share from each dealer
		shares[op.ID] = dealerShares[1]
		allCommitments = append(allCommitments, commitments)
		
		if i == 0 && len(commitments) == 0 {
			t.Fatal("Expected non-empty commitments")
		}
	}
	
	// Node 1 finalizes its key share
	node1 := NewDKG(1, CalculateThreshold(len(operators)), operators)
	keyVersion := node1.FinalizeKeyShare(shares, allCommitments, participantIDs)
	
	if keyVersion == nil {
		t.Fatal("Expected non-nil key version")
	}
	
	if keyVersion.PrivateShare == nil {
		t.Error("Private share should not be nil")
	}
	
	if !keyVersion.IsActive {
		t.Error("Key version should be active")
	}
	
	if len(keyVersion.ParticipantIDs) != len(participantIDs) {
		t.Errorf("Expected %d participants, got %d", len(participantIDs), len(keyVersion.ParticipantIDs))
	}
	
	// Verify private share is sum of received shares
	expectedSum := new(fr.Element).SetZero()
	for _, share := range shares {
		expectedSum.Add(expectedSum, share)
	}
	
	if !keyVersion.PrivateShare.Equal(expectedSum) {
		t.Error("Private share should be sum of received shares")
	}
}

// testCreateAcknowledgement tests acknowledgement creation
func testCreateAcknowledgement(t *testing.T) {
	nodeID := 1
	dealerID := 2
	commitments := []types.G2Point{
		{X: big.NewInt(1), Y: big.NewInt(2)},
		{X: big.NewInt(3), Y: big.NewInt(4)},
	}
	
	// Mock signer function
	signer := func(dealer int, hash [32]byte) []byte {
		return []byte("mock-signature")
	}
	
	ack := CreateAcknowledgement(nodeID, dealerID, commitments, signer)
	
	if ack == nil {
		t.Fatal("Expected non-nil acknowledgement")
	}
	
	if ack.DealerID != dealerID {
		t.Errorf("Expected dealer ID %d, got %d", dealerID, ack.DealerID)
	}
	
	if ack.PlayerID != nodeID {
		t.Errorf("Expected player ID %d, got %d", nodeID, ack.PlayerID)
	}
	
	if len(ack.Signature) == 0 {
		t.Error("Signature should not be empty")
	}
	
	// Verify commitment hash is consistent
	expectedHash := crypto.HashCommitment(commitments)
	if ack.CommitmentHash != expectedHash {
		t.Error("Commitment hash mismatch")
	}
}

// testDKGProtocolIntegration tests a full DKG protocol run
func testDKGProtocolIntegration(t *testing.T) {
	
	numNodes := 5
	threshold := CalculateThreshold(numNodes)
	operators := createTestOperators(numNodes)
	
	// Each node runs DKG
	nodes := make([]*DKG, numNodes)
	allShares := make([]map[int]*fr.Element, numNodes)
	allCommitments := make([][][]types.G2Point, numNodes)
	
	// Phase 1: Generate shares and commitments
	for i := 0; i < numNodes; i++ {
		nodes[i] = NewDKG(i+1, threshold, operators)
		shares, commitments, err := nodes[i].GenerateShares()
		if err != nil {
			t.Fatalf("Node %d failed to generate shares: %v", i+1, err)
		}
		allShares[i] = shares
		allCommitments[i] = [][]types.G2Point{commitments}
	}
	
	// Phase 2: Verify shares
	for verifierIdx := 0; verifierIdx < numNodes; verifierIdx++ {
		for dealerIdx := 0; dealerIdx < numNodes; dealerIdx++ {
			share := allShares[dealerIdx][verifierIdx+1]
			commitments := allCommitments[dealerIdx][0]
			
			valid := nodes[verifierIdx].VerifyShare(dealerIdx+1, share, commitments)
			if !valid {
				t.Errorf("Node %d failed to verify share from dealer %d", verifierIdx+1, dealerIdx+1)
			}
		}
	}
	
	// Phase 3: Finalize key shares
	finalShares := make([]*fr.Element, numNodes)
	for i := 0; i < numNodes; i++ {
		// Collect shares for this node from all dealers
		nodeShares := make(map[int]*fr.Element)
		nodeCommitments := make([][]types.G2Point, 0)
		
		for j := 0; j < numNodes; j++ {
			nodeShares[j+1] = allShares[j][i+1]
			nodeCommitments = append(nodeCommitments, allCommitments[j][0])
		}
		
		participantIDs := make([]int, numNodes)
		for k := 0; k < numNodes; k++ {
			participantIDs[k] = k + 1
		}
		
		keyVersion := nodes[i].FinalizeKeyShare(nodeShares, nodeCommitments, participantIDs)
		if keyVersion == nil || keyVersion.PrivateShare == nil {
			t.Fatalf("Node %d failed to finalize key share", i+1)
		}
		finalShares[i] = keyVersion.PrivateShare
	}
	
	// Verify that we can recover the secret
	// The secret is the sum of all constant terms
	expectedSecret := new(fr.Element).SetZero()
	for i := 0; i < numNodes; i++ {
		if nodes[i].poly != nil && len(nodes[i].poly) > 0 {
			expectedSecret.Add(expectedSecret, &nodes[i].poly[0])
		}
	}
	
	// Use threshold shares to recover
	thresholdShares := make(map[int]*fr.Element)
	for i := 0; i < threshold; i++ {
		thresholdShares[i+1] = finalShares[i]
	}
	
	recovered := crypto.RecoverSecret(thresholdShares)
	if !recovered.Equal(expectedSecret) {
		t.Error("Failed to recover correct secret from threshold shares")
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