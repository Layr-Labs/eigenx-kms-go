package attestation

import (
	"context"
	"testing"

	"github.com/Layr-Labs/go-tpm-tools/sdk/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyPlatform_EmptyMachineType_TDX(t *testing.T) {
	v := &VerifiedAttestation{Platform: attest.PlatformIntelTDX}
	assert.NoError(t, v.VerifyPlatform(""))
}

func TestVerifyPlatform_EmptyMachineType_NonTDX(t *testing.T) {
	v := &VerifiedAttestation{Platform: attest.PlatformAMDSevSnp}
	err := v.VerifyPlatform("")
	assert.ErrorContains(t, err, "platform mismatch")
}

func TestVerifyPlatform_TDXSuffix(t *testing.T) {
	v := &VerifiedAttestation{Platform: attest.PlatformIntelTDX}
	assert.NoError(t, v.VerifyPlatform("n2d-standard-4t"))
}

func TestVerifyPlatform_SEVSuffix(t *testing.T) {
	v := &VerifiedAttestation{Platform: attest.PlatformAMDSevSnp}
	assert.NoError(t, v.VerifyPlatform("n2d-standard-4s"))
}

func TestVerifyPlatform_ShieldedVMSuffix(t *testing.T) {
	v := &VerifiedAttestation{Platform: attest.PlatformGCPShieldedVM}
	assert.NoError(t, v.VerifyPlatform("n2d-standard-4v"))
}

func TestVerifyPlatform_Mismatch(t *testing.T) {
	v := &VerifiedAttestation{Platform: attest.PlatformIntelTDX}
	err := v.VerifyPlatform("n2d-standard-4s") // 's' = SEV-SNP
	assert.ErrorContains(t, err, "platform mismatch")
}

func TestVerifyPlatform_UnknownSuffix(t *testing.T) {
	v := &VerifiedAttestation{Platform: attest.PlatformIntelTDX}
	err := v.VerifyPlatform("n2d-standard-4x") // 'x' = unknown
	assert.ErrorContains(t, err, "unknown machine type suffix")
}

func TestCalculateChallenge(t *testing.T) {
	header := []byte("TEST_HEADER")
	data := []byte("test-data")
	result := CalculateChallenge(header, data)

	assert.Len(t, result, 32) // SHA256 output

	// Same inputs should produce same output
	result2 := CalculateChallenge(header, data)
	assert.Equal(t, result, result2)

	// Different inputs should produce different output
	result3 := CalculateChallenge(header, []byte("different-data"))
	assert.NotEqual(t, result, result3)
}

// Covers the "attestation parsing failed" wrapper and doubles as a
// constructor smoke test — a nil or panicking verifier fails these
// subtests first. Invalid and empty buffers both fall through Parse's
// proto-unmarshal and platform-detection into the same branch.
func TestAttestVerifier_Verify_ParseFailures(t *testing.T) {
	cases := []struct {
		name             string
		attestationBytes []byte
	}{
		{name: "non-protobuf bytes", attestationBytes: []byte("not a protobuf")},
		{name: "empty bytes", attestationBytes: []byte{}},
		{name: "single invalid byte", attestationBytes: []byte{0xFF}},
	}
	v := NewBoundAttestationEvidenceVerifier()
	require.NotNil(t, v)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), tc.attestationBytes, []byte("challenge"))
			require.Error(t, err)
			require.Contains(t, err.Error(), "attestation parsing failed")
		})
	}
}
