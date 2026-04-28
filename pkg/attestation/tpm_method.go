package attestation

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// TPMAttestationMethod implements AttestationMethod for raw TPM attestation verification.
// It verifies TPM hardware evidence directly without relying on external JWT issuers.
type TPMAttestationMethod struct {
	verifier BoundAttestationEvidenceVerifier
	logger   *slog.Logger
}

// NewTPMAttestationMethod creates a new TPM attestation method with the production verifier.
func NewTPMAttestationMethod(logger *slog.Logger) *TPMAttestationMethod {
	return &TPMAttestationMethod{
		verifier: NewBoundAttestationEvidenceVerifier(),
		logger:   logger.With("component", "tpm_attestation"),
	}
}

// NewTPMAttestationMethodWithVerifier creates a TPM attestation method with a custom verifier (for testing).
func NewTPMAttestationMethodWithVerifier(verifier BoundAttestationEvidenceVerifier, logger *slog.Logger) *TPMAttestationMethod {
	return &TPMAttestationMethod{
		verifier: verifier,
		logger:   logger.With("component", "tpm_attestation"),
	}
}

// Name returns the identifier for this attestation method.
func (t *TPMAttestationMethod) Name() string {
	return "tpm"
}

// Verify validates a raw TPM attestation and returns the extracted claims.
//
// The RSA public key must be passed via request.Metadata["rsa_pubkey"] ([]byte).
// The challenge is computed as SHA256("COMPUTE_APP_ENV_REQUEST_RSA_KEY_V1" || 0x00 || RSAPubKey)
// and verified against the TPM attestation's report data, binding the RSA key to the attestation.
func (t *TPMAttestationMethod) Verify(request *AttestationRequest) (*types.AttestationClaims, error) {
	if request == nil {
		return nil, fmt.Errorf("attestation request is nil")
	}

	if len(request.Attestation) == 0 {
		return nil, fmt.Errorf("empty attestation data")
	}

	// Extract RSA public key from metadata
	rsaPubKeyRaw, ok := request.Metadata["rsa_pubkey"]
	if !ok {
		return nil, fmt.Errorf("rsa_pubkey not found in request metadata")
	}
	rsaPubKey, ok := rsaPubKeyRaw.([]byte)
	if !ok {
		return nil, fmt.Errorf("rsa_pubkey in metadata is not []byte")
	}
	if len(rsaPubKey) == 0 {
		return nil, fmt.Errorf("empty rsa_pubkey in metadata")
	}

	// Compute challenge: SHA256(header || 0x00 || RSAPubKey)
	challenge := CalculateChallenge(EnvRequestRSAKeyHeader, rsaPubKey)

	// Verify the raw TPM attestation against the challenge
	ctx := context.Background()
	result, err := t.verifier.Verify(ctx, request.Attestation, challenge)
	if err != nil {
		return nil, fmt.Errorf("TPM attestation verification failed: %w", err)
	}

	// Validate required claims
	if result.TPMClaims == nil || result.TPMClaims.GCE == nil {
		return nil, fmt.Errorf("GCE instance info not found in attestation")
	}
	if result.Container == nil {
		return nil, fmt.Errorf("container info not found in attestation")
	}

	// Extract app ID from instance name (reuses existing function in attestation.go)
	appID, err := extractAppIDFromInstanceName(result.TPMClaims.GCE.InstanceName)
	if err != nil {
		return nil, fmt.Errorf("failed to extract app ID from instance name: %w", err)
	}

	// Build container policy from TPM container claims
	containerPolicy := types.ContainerPolicy{
		Args:          result.Container.Args,
		Env:           result.Container.EnvVars,
		RestartPolicy: result.Container.RestartPolicy,
	}

	claims := &types.AttestationClaims{
		AppID:           appID,
		ImageDigest:     result.Container.ImageDigest,
		ContainerPolicy: containerPolicy,
	}

	t.logger.Debug("TPM attestation claims extracted",
		"app_id", appID,
		"image_digest", result.Container.ImageDigest,
		"platform", result.Platform)

	return claims, nil
}
