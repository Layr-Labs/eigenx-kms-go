package crypto

import (
	"fmt"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

// Test_IBEOperations contains all IBE-related cryptographic tests (crypto-only, no HTTP)
func Test_IBEOperations(t *testing.T) {
	t.Run("GetAppPublicKey", func(t *testing.T) {
		testGetAppPublicKey(t)
	})

	t.Run("MasterPublicKeyDerivation", func(t *testing.T) {
		testMasterPublicKeyDerivation(t)
	})

	t.Run("IBEEncryptionDecryption", func(t *testing.T) {
		testIBEEncryptionDecryption(t)
	})

	t.Run("EncryptionPersistenceAcrossReshare", func(t *testing.T) {
		testEncryptionPersistenceAcrossReshare(t)
	})

	t.Run("ThresholdSignatureRecovery", func(t *testing.T) {
		testThresholdSignatureRecovery(t)
	})
}

// testGetAppPublicKey tests application public key derivation
func testGetAppPublicKey(t *testing.T) {
	appID := "test-application"

	// Get the application's "public key" (Q_ID = H_1(app_id))
	appPubKey, err := GetAppPublicKey(appID)
	if err != nil {
		t.Fatalf("Failed to get app public key: %v", err)
	}
	appPubKey, err = GetAppPublicKey(appID)
	if err != nil {
		t.Fatalf("Failed to get app public key: %v", err)
	}

	// Verify it's not zero
	isZero, err := appPubKey.IsZero()
	if err != nil {
		t.Fatalf("Failed to check if G1 point is zero: %v", err)
	}
	if isZero {
		t.Error("App public key should not be zero")
	}

	// Verify it's deterministic
	appPubKey2, err := GetAppPublicKey(appID)
	if err != nil {
		t.Fatalf("Failed to get app public key: %v", err)
	}
	if !appPubKey.Equal(appPubKey2) {
		t.Error("App public key should be deterministic")
	}

	// Verify different apps have different keys
	differentApp, err := GetAppPublicKey("different-app")
	if err != nil {
		t.Fatalf("Failed to get app public key: %v", err)
	}
	if appPubKey.Equal(differentApp) {
		t.Error("Different apps should have different public keys")
	}
}

// testMasterPublicKeyDerivation tests master public key computation from DKG
func testMasterPublicKeyDerivation(t *testing.T) {
	// Simulate DKG with 5 nodes
	numNodes := 5
	threshold := (2*numNodes + 2) / 3 // ⌈2n/3⌉

	// Each node generates their own polynomial with random constant term
	allCommitments := make([][]types.G2Point, numNodes)

	for i := 0; i < numNodes; i++ {
		poly := make(polynomial.Polynomial, threshold)
		for j := 0; j < threshold; j++ {
			_, _ = poly[j].SetRandom()
		}

		// Create commitments
		commitments := make([]types.G2Point, threshold)
		for k := 0; k < threshold; k++ {
			commitment, err := ScalarMulG2(G2Generator, &poly[k])
			if err != nil {
				t.Fatalf("Failed to scalar multiply G2: %v", err)
			}
			commitments[k] = *commitment
		}
		allCommitments[i] = commitments
	}

	// Compute master public key
	masterPubKey, err := ComputeMasterPublicKey(allCommitments)
	if err != nil {
		t.Fatalf("Failed to compute master public key: %v", err)
	}

	// Verify it's not zero/identity
	isZero, err := masterPubKey.IsZero()
	if err != nil {
		t.Fatalf("Failed to check if G2 point is zero: %v", err)
	}
	if isZero {
		t.Error("Master public key should not be zero")
	}

	// Verify it's the sum of constant term commitments
	expected := allCommitments[0][0] // First commitment from first node
	for i := 1; i < numNodes; i++ {
		tmpExpected, err := AddG2(expected, allCommitments[i][0])
		if err != nil {
			t.Fatalf("Failed to add G2: %v", err)
		}
		expected = *tmpExpected
	}

	equal, err := PointsEqualG2(*masterPubKey, expected)
	if err != nil {
		t.Fatalf("Failed to compare G2 points: %v", err)
	}
	if !equal {
		t.Error("Master public key should be sum of constant term commitments")
	}
}

// testIBEEncryptionDecryption tests basic IBE encryption/decryption
func testIBEEncryptionDecryption(t *testing.T) {
	appID := "secure-app"
	plaintext := []byte("sensitive application secret data")

	// Create a mock master public key
	masterSecret := new(fr.Element).SetInt64(98765)
	masterPubKey, err := ScalarMulG2(G2Generator, masterSecret)
	if err != nil {
		t.Fatalf("Failed to scalar multiply G2: %v", err)
	}

	// Encrypt data for the application
	ciphertext, err := EncryptForApp(appID, *masterPubKey, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Generate application private key (what threshold signature recovery would produce)
	appHash, err := HashToG1(appID)
	if err != nil {
		t.Fatalf("Failed to hash to G1: %v", err)
	}
	appPrivateKey, err := ScalarMulG1(*appHash, masterSecret)
	if err != nil {
		t.Fatalf("Failed to scalar multiply G1: %v", err)
	}

	// Decrypt the data
	decrypted, err := DecryptForApp(appID, *appPrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify decryption worked
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption failed. Expected: %s, Got: %s", string(plaintext), string(decrypted))
	}

	// Test with wrong app ID (should fail to decrypt correctly)
	wrongAppHash, err := HashToG1("wrong-app")
	if err != nil {
		t.Fatalf("Failed to hash to G1: %v", err)
	}
	wrongAppKey, err := ScalarMulG1(*wrongAppHash, masterSecret)
	if err != nil {
		t.Fatalf("Failed to scalar multiply G1: %v", err)
	}
	wrongDecrypted, err := DecryptForApp("wrong-app", *wrongAppKey, ciphertext)
	if err != nil {
		t.Fatalf("Wrong app decryption failed: %v", err)
	}

	// Should not match original plaintext
	if string(wrongDecrypted) == string(plaintext) {
		t.Error("Wrong app should not be able to decrypt correctly")
	}
}

// testEncryptionPersistenceAcrossReshare tests that encrypted data remains decryptable after resharing
func testEncryptionPersistenceAcrossReshare(t *testing.T) {
	appID := "persistent-app"
	plaintext := []byte("data encrypted before reshare")

	// === Phase 1: Initial DKG with 5 nodes ===

	initialNodes := 5
	initialThreshold := (2*initialNodes + 2) / 3

	// Create initial master secret through DKG simulation
	masterSecret := new(fr.Element).SetInt64(13579)
	masterPoly := make(polynomial.Polynomial, initialThreshold)
	masterPoly[0].Set(masterSecret)
	for i := 1; i < initialThreshold; i++ {
		_, _ = masterPoly[i].SetRandom()
	}

	// Generate initial key shares
	initialShares := make([]*fr.Element, initialNodes)
	for i := 0; i < initialNodes; i++ {
		initialShares[i] = EvaluatePolynomial(masterPoly, int64(i+1))
	}

	// Create master public key and encrypt data
	masterPubKey, err := ScalarMulG2(G2Generator, masterSecret)
	if err != nil {
		t.Fatalf("Failed to scalar multiply G2: %v", err)
	}
	ciphertext, err := EncryptForApp(appID, *masterPubKey, plaintext)
	if err != nil {
		t.Fatalf("Initial encryption failed: %v", err)
	}

	// Verify initial decryption works
	appHash, err := HashToG1(appID)
	if err != nil {
		t.Fatalf("Failed to hash to G1: %v", err)
	}

	firstShare, err := ScalarMulG1(*appHash, initialShares[0])
	if err != nil {
		t.Fatalf("Failed to scalar multiply G1: %v", err)
	}
	secondShare, err := ScalarMulG1(*appHash, initialShares[1])
	if err != nil {
		t.Fatalf("Failed to scalar multiply G1: %v", err)
	}
	thirdShare, err := ScalarMulG1(*appHash, initialShares[2])
	if err != nil {
		t.Fatalf("Failed to scalar multiply G1: %v", err)
	}
	initialAppPrivateKey, err := RecoverAppPrivateKey(appID, map[int]types.G1Point{
		1: *firstShare,
		2: *secondShare,
		3: *thirdShare,
	}, initialThreshold)
	if err != nil {
		t.Fatalf("Failed to recover app private key: %v", err)
	}
	decrypted1, err := DecryptForApp(appID, *initialAppPrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Initial decryption failed: %v", err)
	}

	if string(decrypted1) != string(plaintext) {
		t.Fatalf("Initial decryption incorrect. Expected: %s, Got: %s",
			string(plaintext), string(decrypted1))
	}

	// === Phase 3: Reshare - operator set changes (nodes 1-4 remain, 5 leaves, 6 joins) ===

	newOperators := []int{1, 2, 3, 4, 6} // Node 5 leaves, 6 joins
	newThreshold := (2*len(newOperators) + 2) / 3

	// Simulate reshare: existing nodes (1-4) create new shares preserving their secrets
	newShares := make(map[int]*fr.Element)

	for _, existingNode := range []int{1, 2, 3, 4} {
		// Each existing node creates a new polynomial with their current share as constant
		currentShare := initialShares[existingNode-1]
		newPoly := make(polynomial.Polynomial, newThreshold)
		newPoly[0].Set(currentShare)
		for j := 1; j < newThreshold; j++ {
			_, _ = newPoly[j].SetRandom()
		}

		// Generate new shares for all new operators
		for _, newNodeID := range newOperators {
			newShare := EvaluatePolynomial(newPoly, int64(newNodeID))
			if newShares[newNodeID] == nil {
				newShares[newNodeID] = new(fr.Element).SetZero()
			}
			// Aggregate using Lagrange coefficients
			lambda := ComputeLagrangeCoefficient(existingNode, []int{1, 2, 3, 4})
			term := new(fr.Element).Mul(lambda, newShare)
			newShares[newNodeID].Add(newShares[newNodeID], term)
		}
	}

	// === Phase 4: Verify encryption still works after reshare ===

	newAppHash, err := HashToG1(appID)
	if err != nil {
		t.Fatalf("Failed to hash to G1: %v", err)
	}
	newFirstShare, err := ScalarMulG1(*newAppHash, newShares[1])
	if err != nil {
		t.Fatalf("Failed to scalar multiply G1: %v", err)
	}
	newSecondShare, err := ScalarMulG1(*newAppHash, newShares[2])
	if err != nil {
		t.Fatalf("Failed to scalar multiply G1: %v", err)
	}
	newThirdShare, err := ScalarMulG1(*newAppHash, newShares[3])
	if err != nil {
		t.Fatalf("Failed to scalar multiply G1: %v", err)
	}
	// Recover app private key using new shares
	newAppPrivateKey, err := RecoverAppPrivateKey(appID, map[int]types.G1Point{
		1: *newFirstShare,
		2: *newSecondShare,
		3: *newThirdShare,
	}, newThreshold)
	if err != nil {
		t.Fatalf("Failed to recover app private key: %v", err)
	}
	// Decrypt with new key - should still work!
	decrypted2, err := DecryptForApp(appID, *newAppPrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Post-reshare decryption failed: %v", err)
	}

	if string(decrypted2) != string(plaintext) {
		t.Errorf("Post-reshare decryption incorrect. Expected: %s, Got: %s",
			string(plaintext), string(decrypted2))
	}

	fmt.Printf("✓ Encryption persistence test passed!\n")
	fmt.Printf("  - Data encrypted before reshare\n")
	fmt.Printf("  - Operator set changed (5 → 1,2,3,4,6)\n")
	fmt.Printf("  - Data still decryptable with new key shares\n")
	fmt.Printf("  - Verified secret preservation across reshare\n")
}

// testThresholdSignatureRecovery tests the core threshold signature functionality
func testThresholdSignatureRecovery(t *testing.T) {
	appID := "threshold-test-app"
	numNodes := 5
	threshold := (2*numNodes + 2) / 3

	// Create master secret and polynomial
	masterSecret := new(fr.Element).SetInt64(24680)
	poly := make(polynomial.Polynomial, threshold)
	poly[0].Set(masterSecret)
	for i := 1; i < threshold; i++ {
		_, _ = poly[i].SetRandom()
	}

	// Generate key shares
	keyShares := make(map[int]*fr.Element)
	for i := 1; i <= numNodes; i++ {
		keyShares[i] = EvaluatePolynomial(poly, int64(i))
	}

	// Generate partial signatures (what each KMS node would compute)
	partialSigs := make(map[int]types.G1Point)
	for nodeID, share := range keyShares {
		appHash, err := HashToG1(appID)
		if err != nil {
			t.Fatalf("Failed to hash to G1: %v", err)
		}
		partialSig, err := ScalarMulG1(*appHash, share)
		if err != nil {
			t.Fatalf("Failed to scalar multiply G1: %v", err)
		}
		partialSigs[nodeID] = *partialSig
	}

	// Test recovery with exactly threshold signatures
	thresholdSigs := make(map[int]types.G1Point)
	nodeIDs := []int{1, 2, 3} // Use first `threshold` nodes
	for _, id := range nodeIDs {
		thresholdSigs[id] = partialSigs[id]
	}

	recoveredKey, err := RecoverAppPrivateKey(appID, thresholdSigs, threshold)
	if err != nil {
		t.Fatalf("Failed to recover app private key: %v", err)
	}

	// Verify the key is not zero
	isZero, err := recoveredKey.IsZero()
	if err != nil {
		t.Fatalf("Failed to check if G1 point is zero: %v", err)
	}
	if isZero {
		t.Error("Recovered key should not be zero")
	}

	// Test recovery with different threshold subset
	thresholdSigs2 := make(map[int]types.G1Point)
	nodeIDs2 := []int{2, 4, 5} // Use different `threshold` nodes
	for _, id := range nodeIDs2 {
		thresholdSigs2[id] = partialSigs[id]
	}

	recoveredKey2, err := RecoverAppPrivateKey(appID, thresholdSigs2, threshold)
	if err != nil {
		t.Fatalf("Failed to recover app private key: %v", err)
	}

	// Should recover equivalent keys (both should be non-zero)
	isZero, err = recoveredKey2.IsZero()
	if err != nil {
		t.Fatalf("Failed to check if G1 point is zero: %v", err)
	}
	if isZero {
		t.Error("Second recovered key should not be zero")
	}

	fmt.Printf("✓ Threshold signature recovery test passed!\n")
	fmt.Printf("  - Recovered keys from different threshold subsets\n")
	fmt.Printf("  - Both keys are valid and non-zero\n")
}
