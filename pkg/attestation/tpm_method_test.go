package attestation

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/Layr-Labs/go-tpm-tools/sdk/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockVerifier is a mock BoundAttestationEvidenceVerifier for testing.
type mockVerifier struct {
	result *VerifiedAttestation
	err    error
	// captured args for assertions
	capturedChallenge []byte
}

func (m *mockVerifier) Verify(_ context.Context, _ []byte, challenge []byte) (*VerifiedAttestation, error) {
	m.capturedChallenge = challenge
	return m.result, m.err
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestTPMAttestationMethod_Name(t *testing.T) {
	method := NewTPMAttestationMethodWithVerifier(&mockVerifier{}, testLogger())
	assert.Equal(t, "tpm", method.Name())
}

func TestTPMAttestationMethod_Verify_Success(t *testing.T) {
	mock := &mockVerifier{
		result: &VerifiedAttestation{
			TPMClaims: &attest.TPMClaims{
				Platform: attest.PlatformIntelTDX,
				Hardened: true,
				GCE: &attest.GCEInfo{
					InstanceName: "tee-0xabcdef1234567890",
					ProjectID:    "test-project",
				},
				PCRs: map[uint32][32]byte{4: {}, 8: {}, 9: {}},
			},
			Container: &attest.ContainerInfo{
				ImageDigest:   "sha256:abc123",
				RestartPolicy: "Never",
				Args:          []string{"--flag"},
				EnvVars:       map[string]string{"KEY": "VALUE"},
			},
			Platform: attest.PlatformIntelTDX,
		},
	}

	method := NewTPMAttestationMethodWithVerifier(mock, testLogger())

	rsaPubKey := []byte("test-rsa-public-key")
	request := &AttestationRequest{
		Method:      "tpm",
		AppID:       "0xabcdef1234567890",
		Attestation: []byte("raw-attestation-bytes"),
		Metadata: map[string]interface{}{
			"rsa_pubkey": rsaPubKey,
		},
	}

	claims, err := method.Verify(request)
	require.NoError(t, err)
	assert.Equal(t, "0xabcdef1234567890", claims.AppID)
	assert.Equal(t, "sha256:abc123", claims.ImageDigest)
	assert.Equal(t, "Never", claims.ContainerPolicy.RestartPolicy)
	assert.Equal(t, []string{"--flag"}, claims.ContainerPolicy.Args)
	assert.Equal(t, map[string]string{"KEY": "VALUE"}, claims.ContainerPolicy.Env)

	// Verify challenge was computed correctly
	expectedChallenge := CalculateChallenge(EnvRequestRSAKeyHeader, rsaPubKey)
	assert.Equal(t, expectedChallenge, mock.capturedChallenge)
}

func TestTPMAttestationMethod_Verify_ChallengeFormat(t *testing.T) {
	// Verify the challenge matches SHA256(header || 0x00 || RSAPubKey)
	rsaPubKey := []byte("test-key-data")
	challenge := CalculateChallenge(EnvRequestRSAKeyHeader, rsaPubKey)

	h := sha256.New()
	h.Write(EnvRequestRSAKeyHeader)
	h.Write([]byte{0x00})
	h.Write(rsaPubKey)
	expected := h.Sum(nil)

	assert.Equal(t, expected, challenge)
	assert.Len(t, challenge, 32) // SHA256 output
}

func TestTPMAttestationMethod_Verify_NilRequest(t *testing.T) {
	method := NewTPMAttestationMethodWithVerifier(&mockVerifier{}, testLogger())
	_, err := method.Verify(nil)
	assert.ErrorContains(t, err, "attestation request is nil")
}

func TestTPMAttestationMethod_Verify_EmptyAttestation(t *testing.T) {
	method := NewTPMAttestationMethodWithVerifier(&mockVerifier{}, testLogger())
	_, err := method.Verify(&AttestationRequest{
		Method:      "tpm",
		Attestation: []byte{},
		Metadata:    map[string]interface{}{"rsa_pubkey": []byte("key")},
	})
	assert.ErrorContains(t, err, "empty attestation data")
}

func TestTPMAttestationMethod_Verify_MissingRSAKey(t *testing.T) {
	method := NewTPMAttestationMethodWithVerifier(&mockVerifier{}, testLogger())
	_, err := method.Verify(&AttestationRequest{
		Method:      "tpm",
		Attestation: []byte("data"),
		Metadata:    map[string]interface{}{},
	})
	assert.ErrorContains(t, err, "rsa_pubkey not found in request metadata")
}

func TestTPMAttestationMethod_Verify_NilMetadata(t *testing.T) {
	method := NewTPMAttestationMethodWithVerifier(&mockVerifier{}, testLogger())
	_, err := method.Verify(&AttestationRequest{
		Method:      "tpm",
		Attestation: []byte("data"),
	})
	assert.ErrorContains(t, err, "rsa_pubkey not found in request metadata")
}

func TestTPMAttestationMethod_Verify_WrongRSAKeyType(t *testing.T) {
	method := NewTPMAttestationMethodWithVerifier(&mockVerifier{}, testLogger())
	_, err := method.Verify(&AttestationRequest{
		Method:      "tpm",
		Attestation: []byte("data"),
		Metadata:    map[string]interface{}{"rsa_pubkey": "not-bytes"},
	})
	assert.ErrorContains(t, err, "rsa_pubkey in metadata is not []byte")
}

func TestTPMAttestationMethod_Verify_VerificationFailure(t *testing.T) {
	mock := &mockVerifier{
		err: fmt.Errorf("TPM verification failed"),
	}
	method := NewTPMAttestationMethodWithVerifier(mock, testLogger())

	_, err := method.Verify(&AttestationRequest{
		Method:      "tpm",
		Attestation: []byte("bad-attestation"),
		Metadata:    map[string]interface{}{"rsa_pubkey": []byte("key")},
	})
	assert.ErrorContains(t, err, "TPM attestation verification failed")
}

func TestTPMAttestationMethod_Verify_MissingGCE(t *testing.T) {
	mock := &mockVerifier{
		result: &VerifiedAttestation{
			TPMClaims: &attest.TPMClaims{
				Platform: attest.PlatformIntelTDX,
				// GCE is nil
			},
			Container: &attest.ContainerInfo{ImageDigest: "sha256:abc"},
			Platform:  attest.PlatformIntelTDX,
		},
	}
	method := NewTPMAttestationMethodWithVerifier(mock, testLogger())

	_, err := method.Verify(&AttestationRequest{
		Method:      "tpm",
		Attestation: []byte("data"),
		Metadata:    map[string]interface{}{"rsa_pubkey": []byte("key")},
	})
	assert.ErrorContains(t, err, "GCE instance info not found")
}

func TestTPMAttestationMethod_Verify_MissingContainer(t *testing.T) {
	mock := &mockVerifier{
		result: &VerifiedAttestation{
			TPMClaims: &attest.TPMClaims{
				Platform: attest.PlatformIntelTDX,
				GCE:      &attest.GCEInfo{InstanceName: "tee-0xabc"},
			},
			// Container is nil
			Platform: attest.PlatformIntelTDX,
		},
	}
	method := NewTPMAttestationMethodWithVerifier(mock, testLogger())

	_, err := method.Verify(&AttestationRequest{
		Method:      "tpm",
		Attestation: []byte("data"),
		Metadata:    map[string]interface{}{"rsa_pubkey": []byte("key")},
	})
	assert.ErrorContains(t, err, "container info not found")
}

func TestTPMAttestationMethod_Verify_BadInstanceName(t *testing.T) {
	mock := &mockVerifier{
		result: &VerifiedAttestation{
			TPMClaims: &attest.TPMClaims{
				Platform: attest.PlatformIntelTDX,
				GCE:      &attest.GCEInfo{InstanceName: "nohyphen"},
			},
			Container: &attest.ContainerInfo{ImageDigest: "sha256:abc"},
			Platform:  attest.PlatformIntelTDX,
		},
	}
	method := NewTPMAttestationMethodWithVerifier(mock, testLogger())

	// extractAppIDFromInstanceName expects at least 2 parts split by "-"
	// "nohyphen" has no hyphens, so it should fail
	_, err := method.Verify(&AttestationRequest{
		Method:      "tpm",
		Attestation: []byte("data"),
		Metadata:    map[string]interface{}{"rsa_pubkey": []byte("key")},
	})
	assert.ErrorContains(t, err, "failed to extract app ID")
}

func TestTPMAttestationMethod_ContainerPolicyMapping(t *testing.T) {
	mock := &mockVerifier{
		result: &VerifiedAttestation{
			TPMClaims: &attest.TPMClaims{
				Platform: attest.PlatformIntelTDX,
				GCE:      &attest.GCEInfo{InstanceName: "tee-myapp"},
			},
			Container: &attest.ContainerInfo{
				ImageDigest:   "sha256:def456",
				RestartPolicy: "Always",
				Args:          []string{"--port", "8080"},
				EnvVars:       map[string]string{"PORT": "8080", "ENV": "prod"},
			},
			Platform: attest.PlatformIntelTDX,
		},
	}
	method := NewTPMAttestationMethodWithVerifier(mock, testLogger())

	claims, err := method.Verify(&AttestationRequest{
		Method:      "tpm",
		Attestation: []byte("data"),
		Metadata:    map[string]interface{}{"rsa_pubkey": []byte("key")},
	})
	require.NoError(t, err)

	// Verify ContainerPolicy fields map from ContainerInfo
	assert.Equal(t, []string{"--port", "8080"}, claims.ContainerPolicy.Args)
	assert.Equal(t, map[string]string{"PORT": "8080", "ENV": "prod"}, claims.ContainerPolicy.Env)
	assert.Equal(t, "Always", claims.ContainerPolicy.RestartPolicy)
	// CmdOverride and EnvOverride not available from TPM ContainerInfo
	assert.Nil(t, claims.ContainerPolicy.CmdOverride)
	assert.Nil(t, claims.ContainerPolicy.EnvOverride)
}
