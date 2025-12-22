package attestation

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewECDSAAttestationMethod(t *testing.T) {
	method := NewECDSAAttestationMethodDefault()
	assert.NotNil(t, method)
	assert.Equal(t, "ecdsa", method.Name())
	assert.Equal(t, DefaultChallengeTimeWindow, method.config.ChallengeTimeWindow)
}

func TestNewECDSAAttestationMethodWithConfig(t *testing.T) {
	config := ECDSAAttestationConfig{
		ChallengeTimeWindow: 10 * time.Minute,
		AllowedImageDigest:  "sha256:test123",
	}

	method := NewECDSAAttestationMethod(config)
	assert.Equal(t, 10*time.Minute, method.config.ChallengeTimeWindow)
	assert.Equal(t, "sha256:test123", method.config.AllowedImageDigest)
}

func TestGenerateChallenge(t *testing.T) {
	nonce := make([]byte, NonceLength)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	challenge, err := GenerateChallenge(nonce)
	require.NoError(t, err)

	// Verify format
	timestamp, parsedNonce, err := parseChallenge(challenge)
	require.NoError(t, err)

	// Timestamp should be recent
	now := time.Now().Unix()
	assert.InDelta(t, now, timestamp, 2) // Within 2 seconds

	// Nonce should match
	assert.Equal(t, hex.EncodeToString(nonce), parsedNonce)
}

func TestGenerateChallengeInvalidNonce(t *testing.T) {
	tests := []struct {
		name      string
		nonceLen  int
		shouldErr bool
	}{
		{"valid nonce", NonceLength, false},
		{"too short", NonceLength - 1, true},
		{"too long", NonceLength + 1, true},
		{"empty", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce := make([]byte, tt.nonceLen)
			_, err := GenerateChallenge(nonce)

			if tt.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseChallenge(t *testing.T) {
	tests := []struct {
		name          string
		challenge     string
		expectError   bool
		expectedTS    int64
		expectedNonce string
	}{
		{
			name:          "valid challenge",
			challenge:     "1702857600-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
			expectError:   false,
			expectedTS:    1702857600,
			expectedNonce: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		},
		{
			name:        "missing dash",
			challenge:   "1702857600",
			expectError: true,
		},
		{
			name:        "invalid timestamp",
			challenge:   "invalid-a1b2c3d4",
			expectError: true,
		},
		{
			name:        "empty challenge",
			challenge:   "",
			expectError: true,
		},
		{
			name:        "only dash",
			challenge:   "-",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timestamp, nonce, err := parseChallenge(tt.challenge)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedTS, timestamp)
				assert.Equal(t, tt.expectedNonce, nonce)
			}
		})
	}
}

func TestSignAndVerifyChallenge(t *testing.T) {
	// Generate a test private key
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	appID := "test-app"
	nonce := make([]byte, NonceLength)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	challenge, err := GenerateChallenge(nonce)
	require.NoError(t, err)

	// Sign the challenge
	signature, err := SignChallenge(privateKey, appID, challenge)
	require.NoError(t, err)
	assert.Equal(t, 65, len(signature))

	// Verify with ECDSA method
	method := NewECDSAAttestationMethodDefault()

	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)
	request := &AttestationRequest{
		Method:      "ecdsa",
		AppID:       appID,
		Challenge:   []byte(challenge),
		PublicKey:   publicKey,
		Attestation: signature,
	}

	claims, err := method.Verify(request)
	require.NoError(t, err)
	assert.Equal(t, appID, claims.AppID)
	assert.Equal(t, publicKey, claims.PublicKey)
}

func TestECDSAVerifyNilRequest(t *testing.T) {
	method := NewECDSAAttestationMethodDefault()

	_, err := method.Verify(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestECDSAVerifyMissingFields(t *testing.T) {
	method := NewECDSAAttestationMethodDefault()

	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce := make([]byte, NonceLength)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	challenge, err := GenerateChallenge(nonce)
	require.NoError(t, err)

	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)
	signature, err := SignChallenge(privateKey, "test-app", challenge)
	require.NoError(t, err)

	tests := []struct {
		name    string
		request *AttestationRequest
		errMsg  string
	}{
		{
			name: "missing app_id",
			request: &AttestationRequest{
				Challenge:   []byte(challenge),
				PublicKey:   publicKey,
				Attestation: signature,
			},
			errMsg: "app_id",
		},
		{
			name: "missing challenge",
			request: &AttestationRequest{
				AppID:       "test-app",
				PublicKey:   publicKey,
				Attestation: signature,
			},
			errMsg: "challenge",
		},
		{
			name: "missing public key",
			request: &AttestationRequest{
				AppID:       "test-app",
				Challenge:   []byte(challenge),
				Attestation: signature,
			},
			errMsg: "public_key",
		},
		{
			name: "missing signature",
			request: &AttestationRequest{
				AppID:     "test-app",
				Challenge: []byte(challenge),
				PublicKey: publicKey,
			},
			errMsg: "signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := method.Verify(tt.request)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestECDSAVerifyExpiredChallenge(t *testing.T) {
	method := NewECDSAAttestationMethod(ECDSAAttestationConfig{
		ChallengeTimeWindow: 1 * time.Second,
	})

	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	appID := "test-app"

	// Create an expired challenge (2 seconds ago)
	oldTimestamp := time.Now().Unix() - 2
	nonce := make([]byte, NonceLength)
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	challenge := fmt.Sprintf("%d-%s", oldTimestamp, hex.EncodeToString(nonce))

	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)
	signature, err := SignChallenge(privateKey, appID, challenge)
	require.NoError(t, err)

	request := &AttestationRequest{
		AppID:       appID,
		Challenge:   []byte(challenge),
		PublicKey:   publicKey,
		Attestation: signature,
	}

	_, err = method.Verify(request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestECDSAVerifyFutureChallenge(t *testing.T) {
	method := NewECDSAAttestationMethodDefault()

	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	appID := "test-app"

	// Create a future challenge (10 seconds from now)
	futureTimestamp := time.Now().Unix() + 10
	nonce := make([]byte, NonceLength)
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	challenge := fmt.Sprintf("%d-%s", futureTimestamp, hex.EncodeToString(nonce))

	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)
	signature, err := SignChallenge(privateKey, appID, challenge)
	require.NoError(t, err)

	request := &AttestationRequest{
		AppID:       appID,
		Challenge:   []byte(challenge),
		PublicKey:   publicKey,
		Attestation: signature,
	}

	_, err = method.Verify(request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "future")
}

func TestECDSAVerifyInvalidSignature(t *testing.T) {
	method := NewECDSAAttestationMethodDefault()

	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	appID := "test-app"
	nonce := make([]byte, NonceLength)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	challenge, err := GenerateChallenge(nonce)
	require.NoError(t, err)

	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)

	// Create an invalid signature (random bytes)
	invalidSignature := make([]byte, 65)
	_, err = rand.Read(invalidSignature)
	require.NoError(t, err)

	request := &AttestationRequest{
		AppID:       appID,
		Challenge:   []byte(challenge),
		PublicKey:   publicKey,
		Attestation: invalidSignature,
	}

	_, err = method.Verify(request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestECDSAVerifyWrongAppID(t *testing.T) {
	method := NewECDSAAttestationMethodDefault()

	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce := make([]byte, NonceLength)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	challenge, err := GenerateChallenge(nonce)
	require.NoError(t, err)

	// Sign with one app ID
	signature, err := SignChallenge(privateKey, "app-1", challenge)
	require.NoError(t, err)

	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)

	// Verify with different app ID
	request := &AttestationRequest{
		AppID:       "app-2",
		Challenge:   []byte(challenge),
		PublicKey:   publicKey,
		Attestation: signature,
	}

	_, err = method.Verify(request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestECDSAVerifyInvalidPublicKey(t *testing.T) {
	method := NewECDSAAttestationMethodDefault()

	nonce := make([]byte, NonceLength)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	challenge, err := GenerateChallenge(nonce)
	require.NoError(t, err)

	// Invalid public key (too short)
	invalidPubKey := []byte{0x04, 0x01, 0x02}

	request := &AttestationRequest{
		AppID:       "test-app",
		Challenge:   []byte(challenge),
		PublicKey:   invalidPubKey,
		Attestation: make([]byte, 65),
	}

	_, err = method.Verify(request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key")
}

func TestECDSAVerifyInvalidNonceLength(t *testing.T) {
	method := NewECDSAAttestationMethodDefault()

	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	appID := "test-app"

	// Create challenge with invalid nonce length
	shortNonce := "abc123"
	challenge := fmt.Sprintf("%d-%s", time.Now().Unix(), shortNonce)

	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)
	signature, err := SignChallenge(privateKey, appID, challenge)
	require.NoError(t, err)

	request := &AttestationRequest{
		AppID:       appID,
		Challenge:   []byte(challenge),
		PublicKey:   publicKey,
		Attestation: signature,
	}

	_, err = method.Verify(request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce length")
}

func TestECDSAVerifyInvalidSignatureLength(t *testing.T) {
	method := NewECDSAAttestationMethodDefault()

	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	nonce := make([]byte, NonceLength)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	challenge, err := GenerateChallenge(nonce)
	require.NoError(t, err)

	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)

	// Invalid signature length
	invalidSignature := make([]byte, 32)

	request := &AttestationRequest{
		AppID:       "test-app",
		Challenge:   []byte(challenge),
		PublicKey:   publicKey,
		Attestation: invalidSignature,
	}

	_, err = method.Verify(request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature length")
}

func TestECDSAVerifyWithAllowedImageDigest(t *testing.T) {
	config := ECDSAAttestationConfig{
		ChallengeTimeWindow: DefaultChallengeTimeWindow,
		AllowedImageDigest:  "sha256:custom-image",
	}
	method := NewECDSAAttestationMethod(config)

	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	appID := "test-app"
	nonce := make([]byte, NonceLength)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	challenge, err := GenerateChallenge(nonce)
	require.NoError(t, err)

	signature, err := SignChallenge(privateKey, appID, challenge)
	require.NoError(t, err)

	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)
	request := &AttestationRequest{
		AppID:       appID,
		Challenge:   []byte(challenge),
		PublicKey:   publicKey,
		Attestation: signature,
	}

	claims, err := method.Verify(request)
	require.NoError(t, err)
	assert.Equal(t, "sha256:custom-image", claims.ImageDigest)
}

func TestRecoverAddress(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	expectedAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	appID := "test-app"
	nonce := make([]byte, NonceLength)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	challenge, err := GenerateChallenge(nonce)
	require.NoError(t, err)

	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)
	signature, err := SignChallenge(privateKey, appID, challenge)
	require.NoError(t, err)

	recoveredAddress, err := RecoverAddress(appID, challenge, publicKey, signature)
	require.NoError(t, err)

	assert.Equal(t, expectedAddress, recoveredAddress)
}

func TestSignChallengeNilPrivateKey(t *testing.T) {
	_, err := SignChallenge(nil, "test-app", "123-abc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func BenchmarkECDSAVerify(b *testing.B) {
	method := NewECDSAAttestationMethodDefault()

	privateKey, _ := crypto.GenerateKey()
	appID := "bench-app"
	nonce := make([]byte, NonceLength)
	_, _ = rand.Read(nonce)
	challenge, _ := GenerateChallenge(nonce)
	signature, _ := SignChallenge(privateKey, appID, challenge)
	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)

	request := &AttestationRequest{
		AppID:       appID,
		Challenge:   []byte(challenge),
		PublicKey:   publicKey,
		Attestation: signature,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = method.Verify(request)
	}
}
