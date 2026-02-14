package attestation

import (
	"context"
	"fmt"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// GCPAttestationMethod implements AttestationMethod for Google Confidential Space attestations
type GCPAttestationMethod struct {
	verifier *AttestationVerifier
	provider AttestationProvider
}

// NewGCPAttestationMethod creates a new GCP attestation method
func NewGCPAttestationMethod(verifier *AttestationVerifier, provider AttestationProvider) *GCPAttestationMethod {
	return &GCPAttestationMethod{
		verifier: verifier,
		provider: provider,
	}
}

// Name returns the identifier for this attestation method
func (g *GCPAttestationMethod) Name() string {
	switch g.provider {
	case GoogleConfidentialSpace:
		return "gcp"
	case IntelTrustAuthority:
		return "intel"
	default:
		return "unknown"
	}
}

// Verify validates a GCP Confidential Space attestation token
func (g *GCPAttestationMethod) Verify(request *AttestationRequest) (*types.AttestationClaims, error) {
	if request == nil {
		return nil, fmt.Errorf("attestation request is nil")
	}

	if len(request.Attestation) == 0 {
		return nil, fmt.Errorf("empty attestation token")
	}

	// Parse attestation as JWT string
	tokenString := string(request.Attestation)

	// Verify the attestation using the production verifier
	ctx := context.Background()
	claims, err := g.verifier.VerifyAttestation(ctx, tokenString, g.provider)
	if err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}

	// Map attestation.AttestationClaims to types.AttestationClaims
	return &types.AttestationClaims{
		AppID:       claims.AppID,
		ImageDigest: claims.ImageDigest,
		IssuedAt:    0,        // Not available in JWT claims
		PublicKey:   []byte{}, // Not available in JWT claims
	}, nil
}
