package attestation

import (
	"testing"

	"github.com/Layr-Labs/go-tpm-tools/sdk/attest"
	"github.com/stretchr/testify/assert"
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
