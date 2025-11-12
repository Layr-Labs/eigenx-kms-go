package crypto

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/bls"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

var (
	// G1Generator is the generator point for G1
	G1Generator types.G1Point
	// G2Generator is the generator point for G2
	G2Generator types.G2Point
)

func init() {
	// Initialize generators from the BLS module
	g1X, g1Y := bls.G1Generator.ToBigInt()
	G1Generator = types.G1Point{X: g1X, Y: g1Y}

	g2X, g2Y := bls.G2Generator.ToBigInt()
	G2Generator = types.G2Point{X: g2X, Y: g2Y}
}

// ScalarMulG1 performs scalar multiplication on G1
func ScalarMulG1(point types.G1Point, scalar *fr.Element) types.G1Point {
	// Convert to BLS module point
	g1Point, err := bls.G1PointFromBigInt(point.X, point.Y)
	if err != nil {
		// Return identity on error
		return types.G1Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}

	// Perform scalar multiplication
	result, err := bls.ScalarMulG1(g1Point, scalar)
	if err != nil {
		return types.G1Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}

	// Convert back to types.G1Point
	x, y := result.ToBigInt()
	return types.G1Point{X: x, Y: y}
}

// ScalarMulG2 performs scalar multiplication on G2
func ScalarMulG2(point types.G2Point, scalar *fr.Element) types.G2Point {
	// Convert to BLS module point
	g2Point, err := bls.G2PointFromBigInt(point.X, point.Y)
	if err != nil {
		// Return identity on error
		return types.G2Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}

	// Perform scalar multiplication
	result, err := bls.ScalarMulG2(g2Point, scalar)
	if err != nil {
		return types.G2Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}

	// Convert back to types.G2Point
	x, y := result.ToBigInt()
	return types.G2Point{X: x, Y: y}
}

// AddG1 adds two G1 points
func AddG1(a, b types.G1Point) types.G1Point {
	// Convert to BLS module points
	aPoint, err1 := bls.G1PointFromBigInt(a.X, a.Y)
	bPoint, err2 := bls.G1PointFromBigInt(b.X, b.Y)

	if err1 != nil {
		return b
	}
	if err2 != nil {
		return a
	}

	// Perform addition
	result, err := bls.AddG1(aPoint, bPoint)
	if err != nil {
		return types.G1Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}

	// Convert back to types.G1Point
	x, y := result.ToBigInt()
	return types.G1Point{X: x, Y: y}
}

// AddG2 adds two G2 points
func AddG2(a, b types.G2Point) types.G2Point {
	// Convert to BLS module points
	aPoint, err1 := bls.G2PointFromBigInt(a.X, a.Y)
	bPoint, err2 := bls.G2PointFromBigInt(b.X, b.Y)

	if err1 != nil {
		return b
	}
	if err2 != nil {
		return a
	}

	// Perform addition
	result, err := bls.AddG2(aPoint, bPoint)
	if err != nil {
		return types.G2Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}

	// Convert back to types.G2Point
	x, y := result.ToBigInt()
	return types.G2Point{X: x, Y: y}
}

// PointsEqualG2 checks if two G2 points are equal
func PointsEqualG2(a, b types.G2Point) bool {
	// Convert to BLS module points
	aPoint, err1 := bls.G2PointFromBigInt(a.X, a.Y)
	bPoint, err2 := bls.G2PointFromBigInt(b.X, b.Y)

	if err1 != nil || err2 != nil {
		// If either conversion fails, compare the big ints directly
		return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
	}

	return aPoint.Equal(bPoint)
}

// HashToG1 hashes a string to a G1 point using proper hash-to-curve
func HashToG1(appID string) types.G1Point {
	g1Point, err := bls.HashToG1([]byte(appID))
	if err != nil {
		return types.G1Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}
	x, y := g1Point.ToBigInt()
	return types.G1Point{X: x, Y: y}
}

// HashCommitment hashes commitments
func HashCommitment(commitments []types.G2Point) [32]byte {
	h := sha256.New()
	for _, c := range commitments {
		h.Write(c.X.Bytes())
		// Y is not used in our encoding
	}
	return [32]byte(h.Sum(nil))
}

// EvaluatePolynomial evaluates a polynomial at point x
func EvaluatePolynomial(poly polynomial.Polynomial, x int64) *fr.Element {
	return bls.EvaluatePolynomial(poly, x)
}

// ComputeLagrangeCoefficient computes the Lagrange coefficient for participant i
func ComputeLagrangeCoefficient(i int, participants []int) *fr.Element {
	return bls.ComputeLagrangeCoefficient(i, participants)
}

// RecoverSecret recovers secret from shares using Lagrange interpolation
func RecoverSecret(shares map[int]*fr.Element) *fr.Element {
	return bls.RecoverSecret(shares)
}

// RecoverAppPrivateKey recovers app private key from partial signatures
func RecoverAppPrivateKey(appID string, partialSigs map[int]types.G1Point, threshold int) types.G1Point {
	participants := make([]int, 0, len(partialSigs))
	for id := range partialSigs {
		participants = append(participants, id)
		if len(participants) >= threshold {
			break
		}
	}

	result := types.G1Point{X: big.NewInt(0), Y: big.NewInt(0)}

	for _, id := range participants {
		lambda := ComputeLagrangeCoefficient(id, participants)
		scaledSig := ScalarMulG1(partialSigs[id], lambda)
		result = AddG1(result, scaledSig)
	}

	return result
}

// ComputeMasterPublicKey computes the master public key from commitments
func ComputeMasterPublicKey(allCommitments [][]types.G2Point) types.G2Point {
	masterPK := types.G2Point{X: big.NewInt(0), Y: big.NewInt(0)}

	for _, commitments := range allCommitments {
		if len(commitments) > 0 {
			masterPK = AddG2(masterPK, commitments[0])
		}
	}

	return masterPK
}

// VerifyShareWithCommitments verifies a share against polynomial commitments
func VerifyShareWithCommitments(nodeID int, share *fr.Element, commitments []types.G2Point) bool {
	// Convert commitments to BLS module points
	blsCommitments := make([]*bls.G2Point, len(commitments))
	for i, c := range commitments {
		g2Point, err := bls.G2PointFromBigInt(c.X, c.Y)
		if err != nil {
			return false
		}
		blsCommitments[i] = g2Point
	}

	// Use the BLS module's verification
	valid, err := bls.VerifyShare(nodeID, share, blsCommitments)
	if err != nil {
		return false
	}
	return valid
}

// GetAppPublicKey computes the public key for an application given the master public key
// This implements Q_ID = H_1(app_id) for IBE encryption
func GetAppPublicKey(appID string) types.G1Point {
	// For IBE, the "public key" is just the hash of the identity to G1
	return HashToG1(appID)
}

// ComputeAppPublicKeyFromMaster computes the application's public encryption key
// using the master public key and pairing operations
func ComputeAppPublicKeyFromMaster(appID string, masterPublicKey types.G2Point) types.G1Point {
	// In IBE, the app's "public key" for encryption is H_1(app_id)
	// The actual encryption involves pairing with master public key
	// For now, we return the hash-to-G1 result
	return HashToG1(appID)
}

// EncryptForApp encrypts data for an application using IBE
// This is a simplified version - full IBE would involve pairings
// TODO(seanmcgary): make this full IBE
func EncryptForApp(appID string, masterPublicKey types.G2Point, plaintext []byte) ([]byte, error) {
	// STUB: Full IBE implementation would be more complex
	// For now, this is a placeholder that demonstrates the concept
	// Real implementation would follow the IBE encryption scheme from the design docs

	// Step 1: Compute Q_ID = H_1(app_id)
	_ = HashToG1(appID)

	// Step 2-5: Full IBE encryption (simplified for now)
	// In production: Choose random α, compute r = H_3(α, M), etc.

	// For testing, we'll use a simple XOR with the app's hash
	appHash := HashToG1(appID + "-encryption-key")
	keyBytes := appHash.X.Bytes()

	// Simple XOR encryption (NOT secure, just for testing)
	encrypted := make([]byte, len(plaintext))
	for i, b := range plaintext {
		encrypted[i] = b ^ keyBytes[i%len(keyBytes)]
	}

	fmt.Printf("IBE encryption for app %s (simplified)\n", appID)
	return encrypted, nil
}

// DecryptForApp decrypts data using the recovered application private key
func DecryptForApp(appID string, appPrivateKey types.G1Point, ciphertext []byte) ([]byte, error) {
	// STUB: This matches the simplified encryption above
	// In production, this would use the full IBE decryption scheme

	// Use the same "key" derivation as encryption
	appHash := HashToG1(appID + "-encryption-key")
	keyBytes := appHash.X.Bytes()

	// Simple XOR decryption
	decrypted := make([]byte, len(ciphertext))
	for i, b := range ciphertext {
		decrypted[i] = b ^ keyBytes[i%len(keyBytes)]
	}

	fmt.Printf("IBE decryption for app %s (simplified)\n", appID)
	return decrypted, nil
}
