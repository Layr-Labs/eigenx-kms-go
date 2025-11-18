package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/bls"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

var (
	// G1Generator is the generator point for G1
	G1Generator types.G1Point
	// G2Generator is the generator point for G2
	G2Generator types.G2Point
)

func init() {
	// Initialize generators from the BLS module
	G1Generator = types.G1Point{CompressedBytes: bls.G1Generator.Marshal()}
	G2Generator = types.G2Point{CompressedBytes: bls.G2Generator.Marshal()}
}

// ScalarMulG1 performs scalar multiplication on G1
func ScalarMulG1(point types.G1Point, scalar *fr.Element) (*types.G1Point, error) {
	// Convert to BLS module point
	g1Point, err := bls.G1PointFromCompressedBytes(point.CompressedBytes)
	if err != nil {
		return nil, err
	}

	// Perform scalar multiplication
	result, err := bls.ScalarMulG1(g1Point, scalar)
	if err != nil {
		return nil, err
	}

	// Convert back to types.G1Point
	return &types.G1Point{CompressedBytes: result.Marshal()}, nil
}

// ScalarMulG2 performs scalar multiplication on G2
func ScalarMulG2(point types.G2Point, scalar *fr.Element) (*types.G2Point, error) {
	// Convert to BLS module point
	g2Point, err := bls.G2PointFromCompressedBytes(point.CompressedBytes)
	if err != nil {
		return nil, err
	}

	// Perform scalar multiplication
	result, err := bls.ScalarMulG2(g2Point, scalar)
	if err != nil {
		return nil, err
	}

	// Convert back to types.G2Point
	return &types.G2Point{CompressedBytes: result.Marshal()}, nil
}

// AddG1 adds two G1 points
// This allows any point as long as it's on the curve and in the subgroup.
func AddG1(a, b types.G1Point) (*types.G1Point, error) {
	// Convert to BLS module points
	// audit: this function is weird, we should probably split it to requiring only x and both x and y.
	//        this function by default will be on curve due to is current working. After checking, check subgroup.
	aPoint, err1 := bls.G1PointFromCompressedBytes(a.CompressedBytes)
	bPoint, err2 := bls.G1PointFromCompressedBytes(b.CompressedBytes)

	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}

	// Perform addition
	result, err := bls.AddG1(aPoint, bPoint)
	if err != nil {
		return nil, err
	}

	// Convert back to types.G1Point
	return &types.G1Point{CompressedBytes: result.Marshal()}, nil
}

// AddG2 adds two G2 points
func AddG2(a, b types.G2Point) (*types.G2Point, error) {
	// Convert to BLS module points
	aPoint, err1 := bls.G2PointFromCompressedBytes(a.CompressedBytes)
	bPoint, err2 := bls.G2PointFromCompressedBytes(b.CompressedBytes)

	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}

	// Perform addition
	result, err := bls.AddG2(aPoint, bPoint)
	if err != nil {
		return nil, err
	}

	// Convert back to types.G2Point
	return &types.G2Point{CompressedBytes: result.Marshal()}, nil
}

// HashToG1 hashes a string to a G1 point using proper hash-to-curve
func HashToG1(appID string) (*types.G1Point, error) {
	g1Point, err := bls.HashToG1([]byte(appID))
	if err != nil {
		return nil, err
	}
	return &types.G1Point{CompressedBytes: g1Point.Marshal()}, nil
}

// HashCommitment hashes commitments
func HashCommitment(commitments []types.G2Point) [32]byte {
	h := sha256.New()
	for _, c := range commitments {
		h.Write(c.CompressedBytes)
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
func RecoverSecret(shares map[int]*fr.Element) (*fr.Element, error) {
	return bls.RecoverSecret(shares)
}

// RecoverAppPrivateKey recovers app private key from partial signatures
func RecoverAppPrivateKey(appID string, partialSigs map[int]types.G1Point, threshold int) (*types.G1Point, error) {
	participants := make([]int, 0, len(partialSigs))
	for id := range partialSigs {
		participants = append(participants, id)
		if len(participants) >= threshold {
			break
		}
	}

	result := types.ZeroG1Point()

	for _, id := range participants {
		lambda := ComputeLagrangeCoefficient(id, participants)
		scaledSig, err := ScalarMulG1(partialSigs[id], lambda)
		if err != nil {
			return nil, err
		}
		result, err = AddG1(*result, *scaledSig)
		if err != nil {
			return nil, err
		}
	}

	if result.IsZero() {
		return nil, errors.New("recovered app private key is zero")
	}

	return result, nil
}

// ComputeMasterPublicKey computes the master public key from commitments
func ComputeMasterPublicKey(allCommitments [][]types.G2Point) *types.G2Point {
	// audit: start with zero point and then check in the end
	masterPK := types.ZeroG2Point()
	for _, commitments := range allCommitments {
		if len(commitments) > 0 {
			masterPK, _ = AddG2(*masterPK, commitments[0])
		}
	}

	return masterPK
}

// VerifyShareWithCommitments verifies a share against polynomial commitments
func VerifyShareWithCommitments(nodeID int, share *fr.Element, commitments []types.G2Point) bool {
	// Convert commitments to BLS module points
	blsCommitments := make([]*bls.G2Point, len(commitments))
	for i, c := range commitments {
		g2Point, err := bls.G2PointFromCompressedBytes(c.CompressedBytes)
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
func GetAppPublicKey(appID string) (*types.G1Point, error) {
	// For IBE, the "public key" is just the hash of the identity to G1
	appHash, err := HashToG1(appID)
	if err != nil {
		return nil, err
	}
	return appHash, nil
}

// ComputeAppPublicKeyFromMaster computes the application's public encryption key
// using the master public key and pairing operations
func ComputeAppPublicKeyFromMaster(appID string, masterPublicKey types.G2Point) (*types.G1Point, error) {
	// In IBE, the app's "public key" for encryption is H_1(app_id)
	// The actual encryption involves pairing with master public key
	// For now, we return the hash-to-G1 result
	appHash, err := HashToG1(appID)
	if err != nil {
		return nil, err
	}
	return appHash, nil
}

// EncryptForApp encrypts data for an application using IBE
// This is a simplified version - full IBE would involve pairings
// TODO(seanmcgary): make this full IBE
func EncryptForApp(appID string, masterPublicKey types.G2Point, plaintext []byte) ([]byte, error) {
	// STUB: Full IBE implementation would be more complex
	// For now, this is a placeholder that demonstrates the concept
	// Real implementation would follow the IBE encryption scheme from the design docs

	// Step 1: Compute Q_ID = H_1(app_id)
	_, err := HashToG1(appID)
	if err != nil {
		return nil, err
	}

	// Step 2-5: Full IBE encryption (simplified for now)
	// In production: Choose random α, compute r = H_3(α, M), etc.

	// For testing, we'll use a simple XOR with the app's hash
	appHash, err := HashToG1(appID + "-encryption-key")
	if err != nil {
		return nil, err
	}
	keyBytes := appHash.CompressedBytes

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
	appHash, err := HashToG1(appID + "-encryption-key")
	if err != nil {
		return nil, err
	}
	keyBytes := appHash.CompressedBytes
	if err != nil {
		return nil, err
	}

	// Simple XOR decryption
	decrypted := make([]byte, len(ciphertext))
	for i, b := range ciphertext {
		decrypted[i] = b ^ keyBytes[i%len(keyBytes)]
	}

	fmt.Printf("IBE decryption for app %s (simplified)\n", appID)
	return decrypted, nil
}

// HashShareForAck creates a keccak256 hash of a share for use in acknowledgements (Phase 3)
// This commits the player to the specific share they received
func HashShareForAck(share *fr.Element) [32]byte {
	// Import keccak256 from ethereum crypto package
	// Need to add this import at the top of the file
	shareBytes := share.Bytes()

	// Use ethereum's Keccak256 for Solidity compatibility
	hash := keccak256Hash(shareBytes[:])
	return hash
}

// HashAcknowledgementForMerkle creates a keccak256 hash of an acknowledgement for merkle leaf (Phase 3)
// The hash format matches the Solidity implementation for cross-validation
// keccak256(abi.encodePacked(playerID, dealerID, epoch, shareHash, commitmentHash))
func HashAcknowledgementForMerkle(ack *types.Acknowledgement) [32]byte {
	// Pack all fields in the same order as Solidity
	// Note: We use playerID and dealerID as integers for now
	// In production, these should be Ethereum addresses

	data := make([]byte, 0, 8+8+32+32+32) // playerID + dealerID + epoch + shareHash + commitmentHash

	// Encode playerID (8 bytes, big endian)
	playerBytes := make([]byte, 8)
	playerBig := big.NewInt(int64(ack.PlayerID))
	playerBig.FillBytes(playerBytes)
	data = append(data, playerBytes...)

	// Encode dealerID (8 bytes, big endian)
	dealerBytes := make([]byte, 8)
	dealerBig := big.NewInt(int64(ack.DealerID))
	dealerBig.FillBytes(dealerBytes)
	data = append(data, dealerBytes...)

	// Encode epoch (32 bytes, big endian)
	epochBytes := make([]byte, 32)
	epochBig := big.NewInt(ack.Epoch)
	epochBig.FillBytes(epochBytes)
	data = append(data, epochBytes...)

	// Append shareHash and commitmentHash
	data = append(data, ack.ShareHash[:]...)
	data = append(data, ack.CommitmentHash[:]...)

	// Compute keccak256 hash
	hash := keccak256Hash(data)
	return hash
}

// keccak256Hash is a helper function that uses ethereum's Keccak256 for Solidity compatibility
func keccak256Hash(data []byte) [32]byte {
	hash := ethcrypto.Keccak256Hash(data)
	return [32]byte(hash)
}
