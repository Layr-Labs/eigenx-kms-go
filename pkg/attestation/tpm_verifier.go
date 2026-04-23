package attestation

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/Layr-Labs/go-tpm-tools/sdk/attest"
)

var (
	// EnvRequestRSAKeyHeader is the header prefix used to compute the challenge
	// that binds the RSA public key to the TPM attestation's report data.
	// Must match the value used by the eigenx-kms client (EnvClient).
	EnvRequestRSAKeyHeader = []byte("COMPUTE_APP_ENV_REQUEST_RSA_KEY_V1")
)

var machineTypeSuffixToPlatform = map[byte]attest.Platform{
	't': attest.PlatformIntelTDX,
	's': attest.PlatformAMDSevSnp,
	'v': attest.PlatformGCPShieldedVM,
}

// VerifiedAttestation holds the claims extracted from a verified raw TPM attestation.
// TEEClaims is nil for GCP Shielded VM (no TEE binding on that platform).
// Container is nil when the attestation has no canonical event log.
type VerifiedAttestation struct {
	TPMClaims *attest.TPMClaims
	TEEClaims *attest.TEEClaims
	Container *attest.ContainerInfo
	Platform  attest.Platform
}

// VerifyPlatform checks that the machine type suffix matches this attestation's platform.
// An empty machine type defaults to TDX for legacy deployments.
func (v *VerifiedAttestation) VerifyPlatform(machineType string) error {
	if machineType == "" {
		if v.Platform != attest.PlatformIntelTDX {
			return fmt.Errorf("platform mismatch: empty machine type defaults to %s but attestation is %s",
				attest.PlatformIntelTDX.PlatformTag(), v.Platform.PlatformTag())
		}
		return nil
	}
	expected, ok := machineTypeSuffixToPlatform[machineType[len(machineType)-1]]
	if !ok {
		return fmt.Errorf("unknown machine type suffix in %s", machineType)
	}
	if expected != v.Platform {
		return fmt.Errorf("platform mismatch: %s indicates %s but attestation is %s",
			machineType, expected.PlatformTag(), v.Platform.PlatformTag())
	}
	return nil
}

// BoundAttestationEvidenceVerifier verifies raw bound attestation evidence against a
// challenge and returns the extracted TPM and (where applicable) TEE claims.
type BoundAttestationEvidenceVerifier interface {
	Verify(ctx context.Context, attestationBytes, challenge []byte) (*VerifiedAttestation, error)
}

type attestVerifier struct{}

// NewBoundAttestationEvidenceVerifier returns the production BoundAttestationEvidenceVerifier.
func NewBoundAttestationEvidenceVerifier() BoundAttestationEvidenceVerifier {
	return &attestVerifier{}
}

func (v *attestVerifier) Verify(_ context.Context, attestationBytes, challenge []byte) (*VerifiedAttestation, error) {
	a, err := attest.Parse(attestationBytes)
	if err != nil {
		return nil, fmt.Errorf("attestation parsing failed: %w", err)
	}
	verified, err := a.VerifyTPM(challenge, nil)
	if err != nil {
		return nil, fmt.Errorf("TPM verification failed: %w", err)
	}
	claims, err := verified.ExtractTPMClaims(attest.ExtractOptions{PCRIndices: []uint32{4, 8, 9}})
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}
	result := &VerifiedAttestation{TPMClaims: claims, Platform: a.Platform()}

	// Extract container claims from the canonical event log.
	container, err := a.ExtractContainerClaims()
	if err != nil {
		return nil, fmt.Errorf("failed to extract container claims: %w", err)
	}
	result.Container = container

	if a.Platform() != attest.PlatformGCPShieldedVM {
		teeVerified, err := a.VerifyBoundTEE(challenge, nil)
		if err != nil {
			return nil, fmt.Errorf("TEE verification failed: %w", err)
		}
		teeClaims, err := teeVerified.ExtractTEEClaims()
		if err != nil {
			return nil, fmt.Errorf("failed to extract TEE claims: %w", err)
		}
		result.TEEClaims = teeClaims
	}
	return result, nil
}

// CalculateChallenge computes the challenge digest used to bind an RSA public key
// to a TPM attestation. Format: SHA256(header || 0x00 || data).
func CalculateChallenge(header, data []byte) []byte {
	digest := sha256.New()
	digest.Write(header)
	digest.Write([]byte{0x00}) // separator
	digest.Write(data)
	return digest.Sum(nil)
}
