package reshare

import (
	"fmt"
	"testing"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
)

func Test_ReshareProtocol(t *testing.T) {
	t.Run("NewReshare", func(t *testing.T) { testNewReshare(t) })
	t.Run("GenerateNewShares", func(t *testing.T) { testGenerateNewShares(t) })
	t.Run("GenerateNewSharesNilCurrentShare", func(t *testing.T) { testGenerateNewSharesNilCurrentShare(t) })
	t.Run("VerifyNewShare", func(t *testing.T) { testVerifyNewShare(t) })
	t.Run("ComputeNewKeyShare", func(t *testing.T) { testComputeNewKeyShare(t) })
	t.Run("CreateCompletionSignature", func(t *testing.T) { testCreateCompletionSignature(t) })
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

// testNewReshare tests reshare instance creation
func testNewReshare(t *testing.T) {
	operators := createTestOperators(t, 5)
	nodeID := addressToNodeID(operators[0].OperatorAddress)

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

// testGenerateNewShares tests new share generation
func testGenerateNewShares(t *testing.T) {
	operators := createTestOperators(t, 3)
	nodeID := addressToNodeID(operators[0].OperatorAddress)
	threshold := 2 // (2*3+2)/3 = 2.67 -> 2

	r := NewReshare(nodeID, operators)

	// Create a current share to reshare
	currentShare := new(fr.Element)
	_, _ = currentShare.SetRandom()

	shares, commitments, err := r.GenerateNewShares(currentShare, threshold)
	if err != nil {
		t.Fatalf("GenerateNewShares failed: %v", err)
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

// testGenerateNewSharesNilCurrentShare tests error handling for nil current share
func testGenerateNewSharesNilCurrentShare(t *testing.T) {
	operators := createTestOperators(t, 3)
	nodeID := addressToNodeID(operators[0].OperatorAddress)
	r := NewReshare(nodeID, operators)

	_, _, err := r.GenerateNewShares(nil, 2)
	if err == nil {
		t.Error("Expected error for nil current share")
	}
}

// testVerifyNewShare tests new share verification
func testVerifyNewShare(t *testing.T) {
	operators := createTestOperators(t, 3)
	nodeID := addressToNodeID(operators[0].OperatorAddress)
	threshold := 2

	r := NewReshare(nodeID, operators)

	currentShare := new(fr.Element)
	_, _ = currentShare.SetRandom()

	shares, commitments, err := r.GenerateNewShares(currentShare, threshold)
	if err != nil {
		t.Fatalf("GenerateNewShares failed: %v", err)
	}

	// Test valid share verification
	targetNodeID := addressToNodeID(operators[1].OperatorAddress)
	verifierReshare := NewReshare(targetNodeID, operators)
	valid := verifierReshare.VerifyNewShare(nodeID, shares[targetNodeID], commitments)
	if !valid {
		t.Error("Valid share should verify successfully")
	}

	// Test invalid share
	invalidShare := new(fr.Element)
	_, _ = invalidShare.SetRandom()
	valid = verifierReshare.VerifyNewShare(nodeID, invalidShare, commitments)
	if valid {
		t.Error("Invalid share should fail verification")
	}
}

// testComputeNewKeyShare tests new key share computation
func testComputeNewKeyShare(t *testing.T) {
	operators := createTestOperators(t, 3)
	nodeID := addressToNodeID(operators[0].OperatorAddress)

	r := NewReshare(nodeID, operators)

	// Create test shares
	dealerIDs := []int{1, 2, 3}
	shares := make(map[int]*fr.Element)
	for _, id := range dealerIDs {
		shares[id] = new(fr.Element)
		_, _ = shares[id].SetRandom()
	}

	// Create test commitments with random g2 point
	var point1 bls12381.G2Affine
	point1.X.SetRandom()
	point1.Y.SetRandom()
	allCommitments := [][]types.G2Point{
		{{CompressedBytes: point1.Marshal()}},
	}

	keyVersion := r.ComputeNewKeyShare(dealerIDs, shares, allCommitments)
	if keyVersion == nil {
		t.Fatal("Expected non-nil key version")
	}
	if keyVersion.PrivateShare == nil {
		t.Error("Expected non-nil private share")
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
		t.Errorf("Expected NodeID %d, got %d", nodeID, sig.NodeID)
	}
	if sig.Epoch != epoch {
		t.Errorf("Expected Epoch %d, got %d", epoch, sig.Epoch)
	}
	if sig.CommitmentHash != commitmentHash {
		t.Error("Expected matching commitment hash")
	}
	if len(sig.Signature) == 0 {
		t.Error("Signature should not be empty")
	}
}
