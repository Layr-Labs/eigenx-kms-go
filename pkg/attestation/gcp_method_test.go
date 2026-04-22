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
			JTI:         "test-jti-propagation",
		}, nil)

	method := &GCPAttestationMethod{verifier: mockVerifier, provider: GoogleConfidentialSpace}
	claims, err := method.Verify(&AttestationRequest{
		AppID:       "my-app",
		Attestation: []byte("test-token"),
	})

	require.NoError(t, err)
	assert.Equal(t, "deadbeef", claims.Nonce)
}

func TestVerify_NonceBindingAndJTI(t *testing.T) {
	rsaKey := []byte("test-rsa-public-key-pem")

	nonceFrom := func(parts ...[]byte) string {
		var input []byte
		for _, p := range parts {
			input = append(input, p...)
		}
		h := sha256.Sum256(input)
		return hex.EncodeToString(h[:])
	}

	tests := []struct {
		name        string
		provider    AttestationProvider
		rsaPubKey   []byte
		extraData   []byte
		claimNonce  string
		claimJTI    string
		expectErr   bool
		errContains string
	}{
		{
			name:       "GCP: nonce matches rsaKey only",
			provider:   GoogleConfidentialSpace,
			rsaPubKey:  rsaKey,
			claimNonce: nonceFrom(rsaKey),
			claimJTI:   "jti-1",
		},
		{
			name:       "GCP: nonce matches rsaKey + extraData",
			provider:   GoogleConfidentialSpace,
			rsaPubKey:  rsaKey,
			extraData:  []byte("binding-payload"),
			claimNonce: nonceFrom(rsaKey, []byte("binding-payload")),
			claimJTI:   "jti-2",
		},
		{
			name:        "GCP: tampered extraData causes nonce mismatch",
			provider:    GoogleConfidentialSpace,
			rsaPubKey:   rsaKey,
			extraData:   []byte("tampered"),
			claimNonce:  nonceFrom(rsaKey),
			expectErr:   true,
			errContains: "nonce mismatch",
		},
		{
			name:        "Intel: MITM key substitution causes nonce mismatch",
			provider:    IntelTrustAuthority,
			rsaPubKey:   []byte("attacker-rsa-key"),
			claimNonce:  nonceFrom(rsaKey),
			expectErr:   true,
			errContains: "nonce mismatch",
		},
		{
			name:       "GCP: empty extraData same as nil (backward compat)",
			provider:   GoogleConfidentialSpace,
			rsaPubKey:  rsaKey,
			extraData:  []byte{},
			claimNonce: nonceFrom(rsaKey),
			claimJTI:   "jti-3",
		},
		{
			name:        "GCP: missing JTI rejected",
			provider:    GoogleConfidentialSpace,
			rsaPubKey:   rsaKey,
			claimNonce:  nonceFrom(rsaKey),
			claimJTI:    "", // intentionally empty
			expectErr:   true,
			errContains: "missing jti",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockVerifier := NewMockAttestationVerifierInterface(t)
			mockVerifier.EXPECT().
				VerifyAttestation(context.Background(), "jwt-token", tt.provider).
				Return(&kmsTypes.AttestationClaims{
					AppID: "test-app", ImageDigest: "sha256:abc",
					Nonce: tt.claimNonce, JTI: tt.claimJTI,
				}, nil)

			method := &GCPAttestationMethod{verifier: mockVerifier, provider: tt.provider}
			claims, err := method.Verify(&AttestationRequest{
				Attestation:  []byte("jwt-token"),
				AppID:        "test-app",
				RSAPubKeyTmp: tt.rsaPubKey,
				ExtraData:    tt.extraData,
			})

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, claims)
			}
		})
	}
}

// Note: Full integration tests with real AttestationVerifier are in attestation_test.go
// These tests focus on the method interface implementation
