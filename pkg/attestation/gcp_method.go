package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// GCPAttestationMethod implements AttestationMethod for Google Confidential Space attestations
type GCPAttestationMethod struct {
	verifier AttestationVerifierInterface
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

	// Nonce binding: hex(SHA256(rsaPubKey || extraData)). RSAPubKeyTmp is
	// mandatory — it's the ephemeral key the caller expects the KMS to
	// encrypt the response to, and the nonce is how we prove the
	// attestation token is bound to that exact key. Skipping the check
	// when RSAPubKeyTmp is empty would let any caller that forgot to
	// populate it (a future transport, a misconfigured client) bypass
	// nonce binding silently. The handler also guards against this at
	// the HTTP layer, but Verify() is a public API so it must enforce
	// the invariant itself. Empty ExtraData is fine — appending a nil
	// slice is a no-op, so the nonce just becomes hex(SHA256(rsaPubKey)).
	if len(request.RSAPubKeyTmp) == 0 {
		return nil, fmt.Errorf("RSAPubKeyTmp is required for nonce binding")
	}
	nonceInput := make([]byte, 0, len(request.RSAPubKeyTmp)+len(request.ExtraData))
	nonceInput = append(nonceInput, request.RSAPubKeyTmp...)
	nonceInput = append(nonceInput, request.ExtraData...)
	h := sha256.Sum256(nonceInput)
	expectedNonce := hex.EncodeToString(h[:])
	if strings.ToLower(claims.Nonce) != expectedNonce {
		return nil, fmt.Errorf("nonce mismatch: ephemeral RSA key (and extra_data if present) not bound to attestation token")
	}

	if claims.JTI == "" {
		return nil, fmt.Errorf("attestation token missing jti claim")
	}

	return claims, nil
}
