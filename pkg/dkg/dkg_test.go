package dkg

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
)

// Test_DKGProtocol runs all DKG protocol unit tests
func Test_DKGProtocol(t *testing.T) {
	t.Run("CalculateThreshold", func(t *testing.T) { testCalculateThreshold(t) })
	t.Run("NewDKG", func(t *testing.T) { testNewDKG(t) })
	t.Run("GenerateShares", func(t *testing.T) { testGenerateShares(t) })
	t.Run("VerifyShare", func(t *testing.T) { testVerifyShare(t) })
	t.Run("FinalizeKeyShare", func(t *testing.T) { testFinalizeKeyShare(t) })
	t.Run("CreateAcknowledgement", func(t *testing.T) { testCreateAcknowledgement(t) })
}

// createTestOperators creates test operators using ChainConfig data
func createTestOperators(t *testing.T, numOperators int) []*peering.OperatorSetPeer {
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	if err != nil {
		t.Fatalf("Failed to read chain config: %v", err)
	}

	operators := make([]*peering.OperatorSetPeer, numOperators)
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

	for i := 0; i < numOperators && i < len(addresses); i++ {
		// Create BN254 public key from private key
		privKey, err := bn254.NewPrivateKeyFromHexString(privateKeys[i])
		if err != nil {
			t.Fatalf("Failed to create BN254 private key: %v", err)
		}

		operators[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress(addresses[i]),
			SocketAddress:   fmt.Sprintf("http://localhost:%d", 8080+i),
			WrappedPublicKey: peering.WrappedPublicKey{
				PublicKey:    privKey.Public(),
				ECDSAAddress: common.HexToAddress(addresses[i]),
			},
			CurveType: config.CurveTypeBN254,
		}
	}

	return operators
}

// testCalculateThreshold tests threshold calculation
func testCalculateThreshold(t *testing.T) {
	tests := []struct {
		n        int
		expected int
		desc     string
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
	operators := createTestOperators(t, 3)
	nodeID := addressToNodeID(operators[0].OperatorAddress)
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
	operators := createTestOperators(t, 5)
	nodeID := addressToNodeID(operators[0].OperatorAddress)
	threshold := CalculateThreshold(len(operators))
	dkg := NewDKG(nodeID, threshold, operators)

	shares, commitments, err := dkg.GenerateShares()
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	if len(shares) != len(operators) {
		t.Errorf("Expected %d shares, got %d", len(operators), len(shares))
	}
	if len(commitments) != threshold {
		t.Errorf("Expected %d commitments, got %d", threshold, len(commitments))
	}

	// Verify all operators have shares
	for _, op := range operators {
		opNodeID := addressToNodeID(op.OperatorAddress)
		if shares[opNodeID] == nil {
			t.Errorf("Missing share for operator %s (ID: %d)", op.OperatorAddress.Hex(), opNodeID)
		}
	}
}

// testVerifyShare tests share verification
func testVerifyShare(t *testing.T) {
	operators := createTestOperators(t, 3)
	nodeID := addressToNodeID(operators[0].OperatorAddress)
	threshold := CalculateThreshold(len(operators))
	dealerDKG := NewDKG(nodeID, threshold, operators)

	shares, commitments, err := dealerDKG.GenerateShares()
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Test verification with valid share - create verifier DKG instance
	targetNodeID := addressToNodeID(operators[1].OperatorAddress)
	verifierDKG := NewDKG(targetNodeID, threshold, operators)
	valid := verifierDKG.VerifyShare(nodeID, shares[targetNodeID], commitments)
	if !valid {
		t.Error("Valid share should verify successfully")
	}

	// Test verification with invalid share
	invalidShare := new(fr.Element)
	_, _ = invalidShare.SetRandom()
	valid = verifierDKG.VerifyShare(nodeID, invalidShare, commitments)
	if valid {
		t.Error("Invalid share should fail verification")
	}
}

// testFinalizeKeyShare tests key finalization
func testFinalizeKeyShare(t *testing.T) {
	operators := createTestOperators(t, 3)
	nodeID := addressToNodeID(operators[0].OperatorAddress)
	threshold := CalculateThreshold(len(operators))
	dkg := NewDKG(nodeID, threshold, operators)

	shares, commitments, err := dkg.GenerateShares()
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Create participant IDs from addresses
	participantIDs := make([]int, len(operators))
	allCommitments := [][]types.G2Point{commitments}
	for i, op := range operators {
		participantIDs[i] = addressToNodeID(op.OperatorAddress)
	}

	keyVersion := dkg.FinalizeKeyShare(shares, allCommitments, participantIDs)
	if keyVersion == nil {
		t.Fatal("Expected non-nil key version")
	}
	if keyVersion.PrivateShare == nil {
		t.Error("Expected non-nil private share")
	}
	if len(keyVersion.Commitments) != threshold {
		t.Errorf("Expected %d commitments, got %d", threshold, len(keyVersion.Commitments))
	}
}

// testCreateAcknowledgement tests acknowledgement creation
func testCreateAcknowledgement(t *testing.T) {
	operators := createTestOperators(t, 3)
	nodeID := addressToNodeID(operators[0].OperatorAddress)
	dealerID := addressToNodeID(operators[1].OperatorAddress)

	// Create test commitments
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
	if ack.PlayerID != nodeID {
		t.Errorf("Expected PlayerID %d, got %d", nodeID, ack.PlayerID)
	}
	if ack.DealerID != dealerID {
		t.Errorf("Expected DealerID %d, got %d", dealerID, ack.DealerID)
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
