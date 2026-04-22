package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	kmsTypes "github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPAttestationMethodName(t *testing.T) {
	tests := []struct {
		name     string
		provider AttestationProvider
		expected string
	}{
		{
			name:     "Google Confidential Space",
			provider: GoogleConfidentialSpace,
			expected: "gcp",
		},
		{
			name:     "Intel Trust Authority",
			provider: IntelTrustAuthority,
			expected: "intel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := NewGCPAttestationMethod(nil, tt.provider)
			assert.Equal(t, tt.expected, method.Name())
		})
	}
}

func TestGCPAttestationMethodVerifyNilRequest(t *testing.T) {
	method := NewGCPAttestationMethod(nil, GoogleConfidentialSpace)

	_, err := method.Verify(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestGCPAttestationMethodVerifyEmptyAttestation(t *testing.T) {
	method := NewGCPAttestationMethod(nil, GoogleConfidentialSpace)

	request := &AttestationRequest{
		Attestation: []byte{},
	}

	_, err := method.Verify(request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestGCPAttestationMethodVerifyNoncePropagation(t *testing.T) {
	mockVerifier := NewMockAttestationVerifierInterface(t)
	mockVerifier.EXPECT().
		VerifyAttestation(context.Background(), "test-token", GoogleConfidentialSpace).
		Return(&kmsTypes.AttestationClaims{
			AppID:       "my-app",
			ImageDigest: "sha256:abc",
			Nonce:       "deadbeef",
		}, nil)

	method := &GCPAttestationMethod{verifier: mockVerifier, provider: GoogleConfidentialSpace}
	claims, err := method.Verify(&AttestationRequest{
		AppID:       "my-app",
		Attestation: []byte("test-token"),
	})

	require.NoError(t, err)
	assert.Equal(t, "deadbeef", claims.Nonce)
}

func TestGCPVerify_NonceBindingWithoutExtraData(t *testing.T) {
	rsaKey := []byte("test-rsa-public-key-pem")
	h := sha256.Sum256(rsaKey)
	expectedNonce := hex.EncodeToString(h[:])

	mockVerifier := NewMockAttestationVerifierInterface(t)
	mockVerifier.EXPECT().
		VerifyAttestation(context.Background(), "jwt-token", GoogleConfidentialSpace).
		Return(&kmsTypes.AttestationClaims{
			AppID: "test-app", ImageDigest: "sha256:abc", Nonce: expectedNonce,
		}, nil)

	method := &GCPAttestationMethod{verifier: mockVerifier, provider: GoogleConfidentialSpace}
	claims, err := method.Verify(&AttestationRequest{
		Attestation: []byte("jwt-token"), AppID: "test-app", RSAPubKeyTmp: rsaKey,
	})

	require.NoError(t, err)
	assert.Equal(t, "test-app", claims.AppID)
}

func TestGCPVerify_NonceBindingWithExtraData(t *testing.T) {
	rsaKey := []byte("test-rsa-public-key-pem")
	extraData := []byte("binding-payload")
	var nonceInput []byte
	nonceInput = append(nonceInput, rsaKey...)
	nonceInput = append(nonceInput, extraData...)
	h := sha256.Sum256(nonceInput)
	expectedNonce := hex.EncodeToString(h[:])

	mockVerifier := NewMockAttestationVerifierInterface(t)
	mockVerifier.EXPECT().
		VerifyAttestation(context.Background(), "jwt-token", GoogleConfidentialSpace).
		Return(&kmsTypes.AttestationClaims{
			AppID: "test-app", ImageDigest: "sha256:abc", Nonce: expectedNonce,
		}, nil)

	method := &GCPAttestationMethod{verifier: mockVerifier, provider: GoogleConfidentialSpace}
	claims, err := method.Verify(&AttestationRequest{
		Attestation: []byte("jwt-token"), AppID: "test-app",
		RSAPubKeyTmp: rsaKey, ExtraData: extraData,
	})

	require.NoError(t, err)
	assert.Equal(t, "test-app", claims.AppID)
}

func TestGCPVerify_NonceBindingMismatch(t *testing.T) {
	rsaKey := []byte("test-rsa-public-key-pem")
	h := sha256.Sum256(rsaKey) // nonce computed WITHOUT extra_data
	nonce := hex.EncodeToString(h[:])

	mockVerifier := NewMockAttestationVerifierInterface(t)
	mockVerifier.EXPECT().
		VerifyAttestation(context.Background(), "jwt-token", GoogleConfidentialSpace).
		Return(&kmsTypes.AttestationClaims{
			AppID: "test-app", ImageDigest: "sha256:abc", Nonce: nonce,
		}, nil)

	method := &GCPAttestationMethod{verifier: mockVerifier, provider: GoogleConfidentialSpace}
	_, err := method.Verify(&AttestationRequest{
		Attestation: []byte("jwt-token"), AppID: "test-app",
		RSAPubKeyTmp: rsaKey, ExtraData: []byte("tampered"),
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce mismatch")
}

func TestGCPVerify_EmptyExtraDataSameAsNil(t *testing.T) {
	rsaKey := []byte("test-rsa-public-key-pem")
	h := sha256.Sum256(rsaKey)
	expectedNonce := hex.EncodeToString(h[:])

	mockVerifier := NewMockAttestationVerifierInterface(t)
	mockVerifier.EXPECT().
		VerifyAttestation(context.Background(), "jwt-token", GoogleConfidentialSpace).
		Return(&kmsTypes.AttestationClaims{
			AppID: "test-app", ImageDigest: "sha256:abc", Nonce: expectedNonce,
		}, nil)

	method := &GCPAttestationMethod{verifier: mockVerifier, provider: GoogleConfidentialSpace}
	claims, err := method.Verify(&AttestationRequest{
		Attestation: []byte("jwt-token"), AppID: "test-app",
		RSAPubKeyTmp: rsaKey, ExtraData: []byte{},
	})

	require.NoError(t, err)
	assert.NotNil(t, claims)
}

// Note: Full integration tests with real AttestationVerifier are in attestation_test.go
// These tests focus on the method interface implementation
