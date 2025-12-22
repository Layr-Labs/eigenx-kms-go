package attestation

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// Verifier defines the interface for attestation verification
type Verifier interface {
	VerifyAttestation(attestation []byte) (*types.AttestationClaims, error)
}

// ProductionVerifier wraps AttestationVerifier to implement the Verifier interface
type ProductionVerifier struct {
	attestationVerifier *AttestationVerifier
	provider            AttestationProvider
}

// NewProductionVerifier creates a new production verifier
func NewProductionVerifier(attestationVerifier *AttestationVerifier, provider AttestationProvider) *ProductionVerifier {
	return &ProductionVerifier{
		attestationVerifier: attestationVerifier,
		provider:            provider,
	}
}

// VerifyAttestation verifies a TEE attestation JWT token
func (v *ProductionVerifier) VerifyAttestation(attestation []byte) (*types.AttestationClaims, error) {
	// Parse attestation as JWT string
	tokenString := string(attestation)
	if tokenString == "" {
		return nil, fmt.Errorf("empty attestation token")
	}

	// Verify the attestation using the production verifier
	ctx := context.Background()
	claims, err := v.attestationVerifier.VerifyAttestation(ctx, tokenString, v.provider)
	if err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}

	// Map attestation.AttestationClaims to types.AttestationClaims
	// Note: types.AttestationClaims has additional fields (IssuedAt, PublicKey)
	// that aren't in attestation.AttestationClaims, so we leave them empty
	return &types.AttestationClaims{
		AppID:       claims.AppID,
		ImageDigest: claims.ImageDigest,
		IssuedAt:    0,        // Not available in JWT claims
		PublicKey:   []byte{}, // Not available in JWT claims
	}, nil
}

// StubVerifier is a stub implementation for testing
type StubVerifier struct{}

// NewStubVerifier creates a new stub attestation verifier
func NewStubVerifier() *StubVerifier {
	return &StubVerifier{}
}

// VerifyAttestation verifies a TEE attestation (stub implementation)
func (v *StubVerifier) VerifyAttestation(attestation []byte) (*types.AttestationClaims, error) {
	// STUB: In production, this would:
	// 1. Parse the Google Confidential Space attestation
	// 2. Verify the attestation signature
	// 3. Verify the attestation chain back to Google's root
	// 4. Extract claims from the attestation JWT

	// For now, parse as JSON for testing
	var claims types.AttestationClaims
	if err := json.Unmarshal(attestation, &claims); err != nil {
		// If it's not JSON, create a default test claim
		return &types.AttestationClaims{
			AppID:       "test-app",
			ImageDigest: "sha256:test123",
			IssuedAt:    1640995200, // 2022-01-01
			PublicKey:   []byte("test-pubkey"),
		}, nil
	}

	// Basic validation
	if claims.AppID == "" {
		return nil, fmt.Errorf("invalid attestation: missing app_id")
	}

	if claims.ImageDigest == "" {
		return nil, fmt.Errorf("invalid attestation: missing image_digest")
	}

	fmt.Printf("Verified attestation for app_id: %s, image: %s\n", claims.AppID, claims.ImageDigest)
	return &claims, nil
}

// ManagerVerifier adapts AttestationManager to implement the Verifier interface
// for backward compatibility with existing code that uses the Verifier interface.
type ManagerVerifier struct {
	manager    *AttestationManager
	methodName string // Default method to use when verifying
}

// NewManagerVerifier creates a verifier that uses AttestationManager with a default method
func NewManagerVerifier(manager *AttestationManager, defaultMethod string) *ManagerVerifier {
	return &ManagerVerifier{
		manager:    manager,
		methodName: defaultMethod,
	}
}

// VerifyAttestation verifies an attestation using the default method
func (v *ManagerVerifier) VerifyAttestation(attestation []byte) (*types.AttestationClaims, error) {
	request := &AttestationRequest{
		Method:      v.methodName,
		Attestation: attestation,
	}

	return v.manager.VerifyWithMethod(v.methodName, request)
}
