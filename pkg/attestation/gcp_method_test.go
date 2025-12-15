package attestation

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

// Note: Full integration tests with real AttestationVerifier are in attestation_test.go
// These tests focus on the method interface implementation
