package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/bls"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/util"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/hkdf"
)

const (
	// IBE ciphertext format constants
	ibeMagic   = "IBE"      // 3-byte magic number for IBE ciphertexts
	ibeVersion = byte(0x01) // Current version of the ciphertext format

	// Key derivation constants
	hkdfSalt = "eigenx-kms-go-ibe-encryption" // Salt for HKDF key derivation

	// Size constants
	magicSize   = 3 // Size of magic bytes
	versionSize = 1 // Size of version byte
	headerSize  = magicSize + versionSize
	g2Size      = 96 // Compressed G2 point size
	nonceSize   = 12 // AES-GCM nonce size (fixed at 12 bytes)
	tagSize     = 16 // AES-GCM tag size

	// Minimum ciphertext size
	minCiphertextSize = headerSize + g2Size + nonceSize + tagSize
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

// PointsEqualG2 checks if two G2 points are equal
func PointsEqualG2(a, b types.G2Point) (bool, error) {
	// Convert to BLS module points
	aPoint, err1 := bls.G2PointFromCompressedBytes(a.CompressedBytes)
	bPoint, err2 := bls.G2PointFromCompressedBytes(b.CompressedBytes)

	if err1 != nil || err2 != nil {
		// If either conversion fails, compare the big ints directly
		return false, fmt.Errorf("failed to convert one of the G2 points to BLS module points")
	}

	return aPoint.Equal(bPoint), nil
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
	if len(partialSigs) < threshold {
		return nil, fmt.Errorf("insufficient partial signatures: got %d, need %d", len(partialSigs), threshold)
	}

	// Collect all participant IDs and sort for deterministic selection
	participants := make([]int, 0, len(partialSigs))
	for id := range partialSigs {
		participants = append(participants, id)
	}

	// Sort participants for deterministic selection (any threshold subset should work)
	sort.Ints(participants)
	// We'll use the first threshold participants after sorting
	if len(participants) > threshold {
		participants = participants[:threshold]
	}

	// start off with zero point as an accumulator
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

	// check if the result is still a zero point
	isZero, err := result.IsZero()
	if err != nil {
		return nil, err
	}
	if isZero {
		return nil, errors.New("recovered app private key is zero")
	}
	return result, nil
}

// ComputeMasterPublicKey computes the master public key from commitments
func ComputeMasterPublicKey(allCommitments [][]types.G2Point) (*types.G2Point, error) {
	masterPK := types.ZeroG2Point()
	for _, commitments := range allCommitments {
		if len(commitments) > 0 {
			masterPK, _ = AddG2(*masterPK, commitments[0])
		}
	}

	isZero, err := masterPK.IsZero()
	if err != nil {
		return nil, err
	}
	if isZero {
		return nil, errors.New("computed master public key is zero")
	}
	return masterPK, nil
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

// EncryptForApp encrypts data for an application using full IBE with AES-GCM
//
// This implements the Boneh-Franklin IBE scheme:
// - Computes Q_ID = H_1(app_id) ∈ G1
// - Chooses random r ∈ Fr
// - Computes C1 = r*P where P is G2 generator
// - Computes g_ID = e(Q_ID, masterPublicKey)^r using pairing
// - Derives AES key from g_ID using HKDF with version-aware domain separation
// - Uses AES-GCM for authenticated encryption with AAD (appID || version || C1)
//
// Ciphertext format (version 1):
//
//	[0:3]     magic ("IBE")
//	[3:4]     version (0x01)
//	[4:100]   C1 (compressed G2 point, 96 bytes)
//	[100:112] nonce (12 bytes)
//	[112:]    encrypted data + GCM tag
func EncryptForApp(appID string, masterPublicKey types.G2Point, plaintext []byte) ([]byte, error) {

	// Validate appID
	if err := util.ValidateAppID(appID); err != nil {
		return nil, err
	}

	// Step 1: Compute QiD = H_1(app_id) ∈ G1
	QiD, err := HashToG1(appID)
	if err != nil {
		return nil, fmt.Errorf("failed to hash app ID: %w", err)
	}

	// Convert Q_ID to G1Affine for pairing
	QiDAffine, err := bls.G1PointFromCompressedBytes(QiD.CompressedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert Q_ID to G1Affine: %w", err)
	}

	// Convert masterPublicKey to G2Affine for pairing
	masterPKAffine, err := bls.G2PointFromCompressedBytes(masterPublicKey.CompressedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert master public key to G2Affine: %w", err)
	}

	// Validate master public key is not zero/infinity point
	if masterPKAffine.IsZero() {
		return nil, errors.New("invalid master public key: zero/infinity point")
	}

	// Step 2: Choose random r ∈ Fr
	r, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random r: %w", err)
	}

	// Step 3: Compute C1 = r*P where P is G2 generator
	c1, err := ScalarMulG2(G2Generator, r)
	if err != nil {
		return nil, fmt.Errorf("failed to compute C1: %w", err)
	}

	// Safety check: Ensure C1 is not infinity (should never happen with valid r)
	c1Check, err := bls.G2PointFromCompressedBytes(c1.CompressedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to validate C1: %w", err)
	}
	if c1Check.IsZero() {
		return nil, errors.New("internal error: C1 is infinity point")
	}

	// Step 4: Compute g_ID = e(Q_ID, masterPublicKey)^r
	// First compute the pairing e(Q_ID, masterPublicKey)
	pairingResult, err := bls12381.Pair(
		[]bls12381.G1Affine{*QiDAffine.ToAffine()},
		[]bls12381.G2Affine{*masterPKAffine.ToAffine()},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to compute pairing: %w", err)
	}

	// CRITICAL: Validate pairing result is not identity element
	// If e(Q_ID, masterPublicKey) = 1_GT, then g_ID = 1^r = 1 for any r
	// This would make all encryptions use the same predictable key!
	if pairingResult.IsOne() {
		return nil, errors.New("invalid pairing result: identity element (possible invalid master public key)")
	}

	// Then raise to the power r: g_ID = pairing^r
	var gID bls12381.GT
	rBigInt := new(big.Int)
	r.BigInt(rBigInt)
	gID.Exp(pairingResult, rBigInt)

	// Validate g_ID is not identity element
	// This is a defensive programming check - the probability is astronomically low (~1/2^255)
	// since it requires r = 0 mod order(GT).
	if gID.IsOne() {
		return nil, errors.New("invalid g_ID: identity element")
	}

	// Step 5: Derive symmetric key from g_ID using HKDF
	// HKDF provides better security properties than raw hashing:
	// - Salt ensures different keys even if g_ID repeats across systems
	// - Info binds the key to its specific purpose, version, and application
	gIDBytes := gID.Bytes()
	keyMaterial, err := deriveKeyMaterial(gIDBytes[:], ibeVersion, appID)
	if err != nil {
		return nil, err
	}

	// Create AES cipher with derived key
	block, err := aes.NewCipher(keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCMWithNonceSize(block, nonceSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Prepare additional authenticated data (AAD)
	// This cryptographically binds the appID, version, and C1 to the ciphertext
	aad := buildAAD(appID, ibeVersion, c1.CompressedBytes)

	// Encrypt plaintext with AAD
	encryptedData := gcm.Seal(nil, nonce, plaintext, aad)

	// Build final ciphertext with version header
	// Format: magic(3) || version(1) || C1(96) || nonce(12) || encrypted_data
	// This allows format detection and future upgrades
	totalLen := headerSize + len(c1.CompressedBytes) + len(nonce) + len(encryptedData)
	finalCiphertext := make([]byte, 0, totalLen)

	// Append header
	finalCiphertext = append(finalCiphertext, ibeMagic...)
	finalCiphertext = append(finalCiphertext, ibeVersion)

	// Append ciphertext components
	finalCiphertext = append(finalCiphertext, c1.CompressedBytes...)
	finalCiphertext = append(finalCiphertext, nonce...)
	finalCiphertext = append(finalCiphertext, encryptedData...)

	return finalCiphertext, nil
}

// DecryptForApp decrypts data using the recovered application private key with AES-GCM
//
// This implements the Boneh-Franklin IBE decryption:
//   - Validates ciphertext format (magic, version)
//   - Extracts C1 from ciphertext
//   - Computes g_ID = e(appPrivateKey, C1) using pairing
//   - Since appPrivateKey = [s]Q_ID and C1 = [r]P:
//     g_ID = e([s]Q_ID, [r]P) = e(Q_ID, P)^(r*s) = e(Q_ID, masterPublicKey)^r
//   - This matches the encryption key, allowing successful decryption
//   - Derives AES key from g_ID using HKDF with version-aware domain separation
//   - Decrypts with AES-GCM and verifies authentication using AAD
//
// Expected ciphertext format matches EncryptForApp output
func DecryptForApp(appID string, appPrivateKey types.G1Point, ciphertext []byte) ([]byte, error) {

	// Validate appID
	if err := util.ValidateAppID(appID); err != nil {
		return nil, err
	}

	// Check for version header
	// Expected format: magic(3) || version(1) || C1(96) || nonce(12) || encrypted_data
	if len(ciphertext) < minCiphertextSize {
		return nil, errors.New("ciphertext too short")
	}

	// Verify magic number
	if !bytes.Equal(ciphertext[:magicSize], []byte(ibeMagic)) {
		return nil, errors.New("invalid ciphertext format: missing or incorrect magic number")
	}

	// Check version
	version := ciphertext[magicSize]
	if version != ibeVersion {
		return nil, fmt.Errorf("unsupported ciphertext version: %d", version)
	}

	// Extract C1 from ciphertext (after header)
	c1Start := headerSize
	c1End := c1Start + g2Size
	c1Bytes := ciphertext[c1Start:c1End]
	c1 := &types.G2Point{CompressedBytes: c1Bytes}

	// Convert appPrivateKey to G1Affine for pairing
	appPrivKeyAffine, err := bls.G1PointFromCompressedBytes(appPrivateKey.CompressedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert app private key to G1Affine: %w", err)
	}

	// Validate appPrivateKey is not zero/infinity point
	if appPrivKeyAffine.IsZero() {
		return nil, errors.New("invalid app private key: zero/infinity point")
	}

	// Convert C1 to G2Affine for pairing
	c1Affine, err := bls.G2PointFromCompressedBytes(c1.CompressedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert C1 to G2Affine: %w", err)
	}

	// CRITICAL: Reject infinity/zero point to prevent forgery attacks
	// With C1 = O (infinity), the pairing e(appPrivateKey, O) = 1_GT (identity)
	// This gives attacker a known decryption key, allowing ciphertext forgery
	if c1Affine.IsZero() {
		return nil, errors.New("invalid ciphertext: C1 is infinity point")
	}

	// Compute g_ID = e(appPrivateKey, C1)
	// This gives us the same value as e(Q_ID, masterPublicKey)^r from encryption
	// because: e([s]Q_ID, [r]P) = e(Q_ID, [s]P)^r = e(Q_ID, masterPublicKey)^r
	gID, err := bls12381.Pair(
		[]bls12381.G1Affine{*appPrivKeyAffine.ToAffine()},
		[]bls12381.G2Affine{*c1Affine.ToAffine()},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to compute pairing: %w", err)
	}

	// Additional security check: Ensure pairing result is not identity
	// This should never happen with valid C1 and appPrivateKey, but check anyway
	if gID.IsOne() {
		return nil, errors.New("invalid pairing result: identity element")
	}

	// Derive symmetric key from g_ID using HKDF (must match encryption exactly)
	// Uses same salt and info structure to ensure decryption works
	// The version from the ciphertext is used to ensure proper version-aware decryption
	gIDBytes := gID.Bytes()
	keyMaterial, err := deriveKeyMaterial(gIDBytes[:], version, appID)
	if err != nil {
		return nil, err
	}

	// Create AES cipher with derived key
	block, err := aes.NewCipher(keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCMWithNonceSize(block, nonceSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce and encrypted data
	nonceStart := headerSize + g2Size
	nonceEnd := nonceStart + nonceSize
	nonce := ciphertext[nonceStart:nonceEnd]
	encryptedData := ciphertext[nonceEnd:]

	// Reconstruct additional authenticated data (AAD)
	// Must match exactly what was used during encryption
	aad := buildAAD(appID, version, c1Bytes)

	// Decrypt with AES-GCM using AAD
	plaintext, err := gcm.Open(nil, nonce, encryptedData, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil

}

// buildAAD constructs the Additional Authenticated Data for AES-GCM
// AAD format: appID || version || C1
// This binds the ciphertext to the application, version, and ephemeral public key
func buildAAD(appID string, version byte, c1Bytes []byte) []byte {
	aadLen := len(appID) + 1 + len(c1Bytes) // appID + version + C1
	aad := make([]byte, 0, aadLen)
	aad = append(aad, []byte(appID)...)
	aad = append(aad, version)
	aad = append(aad, c1Bytes...)
	return aad
}

// deriveKeyMaterial uses HKDF to derive AES-256 key material from g_ID
// The key is bound to the version and appID through the HKDF info parameter
func deriveKeyMaterial(gIDBytes []byte, version byte, appID string) ([]byte, error) {
	salt := []byte(hkdfSalt)
	info := fmt.Appendf(nil, "IBE-encryption|v%d|%s", version, appID)

	hkdfReader := hkdf.New(sha256.New, gIDBytes, salt, info)

	// Derive 32 bytes for AES-256
	keyMaterial := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, keyMaterial); err != nil {
		return nil, fmt.Errorf("failed to derive key using HKDF: %w", err)
	}

	return keyMaterial, nil
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

// keccak256Hash is a helper function that uses ethereum's Keccak256 for Solidity compatibility
func keccak256Hash(data []byte) [32]byte {
	hash := ethcrypto.Keccak256Hash(data)
	return [32]byte(hash)
}
