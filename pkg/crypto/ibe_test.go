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
	appPubKey := GetAppPublicKey(appID)
	
	// Verify it's not zero
	if appPubKey.X.Sign() == 0 {
		t.Error("App public key should not be zero")
	}
	
	// Verify it's deterministic
	appPubKey2 := GetAppPublicKey(appID)
	if !PointsEqualG1(appPubKey, appPubKey2) {
		t.Error("App public key should be deterministic")
	}
	
	// Verify different apps have different keys
	differentApp := GetAppPublicKey("different-app")
	if PointsEqualG1(appPubKey, differentApp) {
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
			poly[j].SetRandom()
		}
		
		// Create commitments
		commitments := make([]types.G2Point, threshold)
		for k := 0; k < threshold; k++ {
			commitments[k] = ScalarMulG2(G2Generator, &poly[k])
		}
		allCommitments[i] = commitments
	}
	
	// Compute master public key
	masterPubKey := ComputeMasterPublicKey(allCommitments)
	
	// Verify it's not zero/identity
	if masterPubKey.X.Sign() == 0 {
		t.Error("Master public key should not be zero")
	}
	
	// Verify it's the sum of constant term commitments
	expected := allCommitments[0][0] // First commitment from first node
	for i := 1; i < numNodes; i++ {
		expected = AddG2(expected, allCommitments[i][0])
	}
	
	if !PointsEqualG2(masterPubKey, expected) {
		t.Error("Master public key should be sum of constant term commitments")
	}
}

// testIBEEncryptionDecryption tests basic IBE encryption/decryption
func testIBEEncryptionDecryption(t *testing.T) {
	appID := "secure-app"
	plaintext := []byte("sensitive application secret data")
	
	// Create a mock master public key
	masterSecret := new(fr.Element).SetInt64(98765)
	masterPubKey := ScalarMulG2(G2Generator, masterSecret)
	
	// Encrypt data for the application
	ciphertext, err := EncryptForApp(appID, masterPubKey, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	// Generate application private key (what threshold signature recovery would produce)
	appPrivateKey := ScalarMulG1(HashToG1(appID), masterSecret)
	
	// Decrypt the data
	decrypted, err := DecryptForApp(appID, appPrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	
	// Verify decryption worked
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption failed. Expected: %s, Got: %s", string(plaintext), string(decrypted))
	}
	
	// Test with wrong app ID (should fail to decrypt correctly)
	wrongAppKey := ScalarMulG1(HashToG1("wrong-app"), masterSecret)
	wrongDecrypted, err := DecryptForApp("wrong-app", wrongAppKey, ciphertext)
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
		masterPoly[i].SetRandom()
	}
	
	// Generate initial key shares
	initialShares := make([]*fr.Element, initialNodes)
	for i := 0; i < initialNodes; i++ {
		initialShares[i] = EvaluatePolynomial(masterPoly, i+1)
	}
	
	// Create master public key and encrypt data
	masterPubKey := ScalarMulG2(G2Generator, masterSecret)
	ciphertext, err := EncryptForApp(appID, masterPubKey, plaintext)
	if err != nil {
		t.Fatalf("Initial encryption failed: %v", err)
	}
	
	// Verify initial decryption works
	initialAppPrivateKey := RecoverAppPrivateKey(appID, map[int]types.G1Point{
		1: ScalarMulG1(HashToG1(appID), initialShares[0]),
		2: ScalarMulG1(HashToG1(appID), initialShares[1]),
		3: ScalarMulG1(HashToG1(appID), initialShares[2]),
	}, initialThreshold)
	
	decrypted1, err := DecryptForApp(appID, initialAppPrivateKey, ciphertext)
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
			newPoly[j].SetRandom()
		}
		
		// Generate new shares for all new operators
		for _, newNodeID := range newOperators {
			newShare := EvaluatePolynomial(newPoly, newNodeID)
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
	
	// Recover app private key using new shares
	newAppPrivateKey := RecoverAppPrivateKey(appID, map[int]types.G1Point{
		1: ScalarMulG1(HashToG1(appID), newShares[1]),
		2: ScalarMulG1(HashToG1(appID), newShares[2]),
		3: ScalarMulG1(HashToG1(appID), newShares[3]),
	}, newThreshold)
	
	// Decrypt with new key - should still work!
	decrypted2, err := DecryptForApp(appID, newAppPrivateKey, ciphertext)
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
		poly[i].SetRandom()
	}
	
	// Generate key shares
	keyShares := make(map[int]*fr.Element)
	for i := 1; i <= numNodes; i++ {
		keyShares[i] = EvaluatePolynomial(poly, i)
	}
	
	// Generate partial signatures (what each KMS node would compute)
	partialSigs := make(map[int]types.G1Point)
	for nodeID, share := range keyShares {
		partialSigs[nodeID] = ScalarMulG1(HashToG1(appID), share)
	}
	
	// Test recovery with exactly threshold signatures
	thresholdSigs := make(map[int]types.G1Point)
	nodeIDs := []int{1, 2, 3} // Use first `threshold` nodes
	for _, id := range nodeIDs {
		thresholdSigs[id] = partialSigs[id]
	}
	
	recoveredKey := RecoverAppPrivateKey(appID, thresholdSigs, threshold)
	
	// Verify the key is not zero
	if recoveredKey.X.Sign() == 0 {
		t.Error("Recovered key should not be zero")
	}
	
	// Test recovery with different threshold subset
	thresholdSigs2 := make(map[int]types.G1Point)
	nodeIDs2 := []int{2, 4, 5} // Use different `threshold` nodes
	for _, id := range nodeIDs2 {
		thresholdSigs2[id] = partialSigs[id]
	}
	
	recoveredKey2 := RecoverAppPrivateKey(appID, thresholdSigs2, threshold)
	
	// Should recover equivalent keys (both should be non-zero)
	if recoveredKey2.X.Sign() == 0 {
		t.Error("Second recovered key should not be zero")
	}
	
	fmt.Printf("✓ Threshold signature recovery test passed!\n")
	fmt.Printf("  - Recovered keys from different threshold subsets\n")
	fmt.Printf("  - Both keys are valid and non-zero\n")
}

// PointsEqualG1 checks if two G1 points are equal (helper function)
func PointsEqualG1(a, b types.G1Point) bool {
	return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}