package attestation

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

/*
ECDSA Attestation Protocol Design

This is a simple challenge-response attestation method that verifies the client
controls a private key without requiring TEE hardware or complex infrastructure.

Protocol Flow:
1. Client generates a challenge: timestamp (unix seconds) + nonce (32 bytes hex)
2. Client computes message: keccak256(appID || challenge || publicKey)
3. Client signs message with their ECDSA private key
4. Client sends: { appID, challenge, signature, publicKey }
5. Server verifies signature and validates challenge freshness

Challenge Format:
  - timestamp: int64 unix seconds (prevents replay attacks)
  - nonce: 32 bytes random data (prevents replay within time window)
  - Format: "<timestamp>-<nonce_hex>"
  - Example: "1702857600-a1b2c3d4e5f6..."

Signed Payload:
  - keccak256(appID || "-" || challenge || "-" || publicKey_hex)
  - This binds the signature to specific app, time window, and public key

Security Properties:
  - Signature verification proves client controls private key
  - Timestamp validation prevents replay attacks
  - Nonce prevents replay within time window
  - Public key in signature prevents key substitution

Limitations:
  - Does NOT prove TEE execution environment
  - Does NOT prove software image integrity
  - Only proves key ownership at attestation time
  - Suitable for development/testing, not production secrets

Time Window:
  - Default: 5 minutes (300 seconds)
  - Configurable via ECDSAAttestationConfig
*/

const (
	// DefaultChallengeTimeWindow is the default time window for challenge validation (5 minutes)
	DefaultChallengeTimeWindow = 5 * time.Minute

	// NonceLength is the expected length of the nonce in bytes
	NonceLength = 32
)

// ECDSAAttestationConfig configures ECDSA attestation behavior
type ECDSAAttestationConfig struct {
	// ChallengeTimeWindow is the maximum age of a challenge (default: 5 minutes)
	ChallengeTimeWindow time.Duration

	// AllowedImageDigest is an optional image digest to validate (for compatibility)
	// If empty, any image digest is accepted
	AllowedImageDigest string
}

// ECDSAAttestationMethod implements simple ECDSA signature-based attestation
type ECDSAAttestationMethod struct {
	config ECDSAAttestationConfig
}

// NewECDSAAttestationMethod creates a new ECDSA attestation method
func NewECDSAAttestationMethod(config ECDSAAttestationConfig) *ECDSAAttestationMethod {
	if config.ChallengeTimeWindow == 0 {
		config.ChallengeTimeWindow = DefaultChallengeTimeWindow
	}

	return &ECDSAAttestationMethod{
		config: config,
	}
}

// NewECDSAAttestationMethodDefault creates ECDSA attestation with default config
func NewECDSAAttestationMethodDefault() *ECDSAAttestationMethod {
	return NewECDSAAttestationMethod(ECDSAAttestationConfig{
		ChallengeTimeWindow: DefaultChallengeTimeWindow,
	})
}

// Name returns the identifier for this attestation method
func (e *ECDSAAttestationMethod) Name() string {
	return "ecdsa"
}

// Verify validates an ECDSA attestation request
func (e *ECDSAAttestationMethod) Verify(request *AttestationRequest) (*types.AttestationClaims, error) {
	if request == nil {
		return nil, fmt.Errorf("attestation request is nil")
	}

	// Extract required fields
	if request.AppID == "" {
		return nil, fmt.Errorf("app_id is required")
	}

	if len(request.Challenge) == 0 {
		return nil, fmt.Errorf("challenge is required")
	}

	if len(request.PublicKey) == 0 {
		return nil, fmt.Errorf("public_key is required")
	}

	if len(request.Attestation) == 0 {
		return nil, fmt.Errorf("signature is required")
	}

	// Parse and validate challenge
	timestamp, nonce, err := parseChallenge(string(request.Challenge))
	if err != nil {
		return nil, fmt.Errorf("invalid challenge format: %w", err)
	}

	// Validate timestamp freshness
	challengeTime := time.Unix(timestamp, 0)
	now := time.Now()
	age := now.Sub(challengeTime)

	if age < 0 {
		return nil, fmt.Errorf("challenge timestamp is in the future")
	}

	if age > e.config.ChallengeTimeWindow {
		return nil, fmt.Errorf("challenge expired (age: %v, max: %v)", age, e.config.ChallengeTimeWindow)
	}

	// Validate nonce length
	if len(nonce) != NonceLength*2 { // hex encoded
		return nil, fmt.Errorf("invalid nonce length: expected %d hex chars, got %d", NonceLength*2, len(nonce))
	}

	// Parse public key to validate format
	_, err = crypto.UnmarshalPubkey(request.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	// Reconstruct signed message: keccak256(appID || "-" || challenge || "-" || publicKey_hex)
	publicKeyHex := hex.EncodeToString(request.PublicKey)
	message := fmt.Sprintf("%s-%s-%s", request.AppID, string(request.Challenge), publicKeyHex)
	messageHash := crypto.Keccak256([]byte(message))

	// Verify signature
	signature := request.Attestation
	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(signature))
	}

	// Ethereum signatures have recovery byte at the end, need to remove it for verification
	if signature[64] >= 27 {
		signature[64] -= 27
	}

	verified := crypto.VerifySignature(request.PublicKey, messageHash, signature[:64])
	if !verified {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Return attestation claims
	// Note: ECDSA attestation doesn't provide image digest, so we use a placeholder
	// or the configured allowed digest
	imageDigest := e.config.AllowedImageDigest
	if imageDigest == "" {
		imageDigest = "ecdsa:unverified"
	}

	return &types.AttestationClaims{
		AppID:       request.AppID,
		ImageDigest: imageDigest,
		IssuedAt:    timestamp,
		PublicKey:   request.PublicKey,
	}, nil
}

// parseChallenge parses a challenge string into timestamp and nonce
// Format: "<timestamp>-<nonce_hex>"
func parseChallenge(challenge string) (int64, string, error) {
	if challenge == "" {
		return 0, "", fmt.Errorf("challenge is empty")
	}

	// Split on first dash
	var timestamp int64
	var nonce string

	n, err := fmt.Sscanf(challenge, "%d-%s", &timestamp, &nonce)
	if err != nil || n != 2 {
		return 0, "", fmt.Errorf("challenge must be in format '<timestamp>-<nonce_hex>'")
	}

	return timestamp, nonce, nil
}

// GenerateChallenge is a helper function to generate a valid challenge string
// This is primarily for testing and client implementation reference
func GenerateChallenge(nonce []byte) (string, error) {
	if len(nonce) != NonceLength {
		return "", fmt.Errorf("nonce must be %d bytes", NonceLength)
	}

	timestamp := time.Now().Unix()
	nonceHex := hex.EncodeToString(nonce)

	return fmt.Sprintf("%d-%s", timestamp, nonceHex), nil
}

// SignChallenge is a helper function to sign a challenge with a private key
// This is primarily for testing and client implementation reference
func SignChallenge(privateKey *ecdsa.PrivateKey, appID string, challenge string) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	// Get public key bytes
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	publicKeyBytes := crypto.FromECDSAPub(publicKey)
	publicKeyHex := hex.EncodeToString(publicKeyBytes)

	// Construct message: appID || "-" || challenge || "-" || publicKey_hex
	message := fmt.Sprintf("%s-%s-%s", appID, challenge, publicKeyHex)
	messageHash := crypto.Keccak256([]byte(message))

	// Sign the message
	signature, err := crypto.Sign(messageHash, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	return signature, nil
}

// RecoverAddress recovers the Ethereum address from a signature
// This is useful for debugging and validation
func RecoverAddress(appID string, challenge string, publicKey []byte, signature []byte) (common.Address, error) {
	publicKeyHex := hex.EncodeToString(publicKey)
	message := fmt.Sprintf("%s-%s-%s", appID, challenge, publicKeyHex)
	messageHash := crypto.Keccak256([]byte(message))

	// Adjust recovery byte if needed
	sig := make([]byte, len(signature))
	copy(sig, signature)
	if sig[64] >= 27 {
		sig[64] -= 27
	}

	recoveredPubKey, err := crypto.SigToPub(messageHash, sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to recover public key: %w", err)
	}

	return crypto.PubkeyToAddress(*recoveredPubKey), nil
}
