package attestation

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProductionVerifier(t *testing.T) {
	logger := setupLogger()
	projectID := "tee-compute-sepolia-prod"

	jwkSet, privateKey, keyID := createTestJWKS(t)

	// Create attestation verifier with mock JWK set
	attestationVerifier := &AttestationVerifier{
		logger:          logger,
		projectID:       projectID,
		googleJwksCache: jwkSet,
		intelJwksCache:  jwkSet,
		debugMode:       true, // Enable debug mode to skip strict validation
	}

	// Create production verifier wrapper
	prodVerifier := NewProductionVerifier(attestationVerifier, GoogleConfidentialSpace)

	t.Run("successful verification", func(t *testing.T) {
		// Create valid token
		csToken := createProductionCsToken(GoogleConfidentialSpace)
		signedToken := createdSignedJWT(t, privateKey, keyID, csToken)

		// Verify using production verifier
		claims, err := prodVerifier.VerifyAttestation([]byte(signedToken))
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.Equal(t, "0xb69a8c848a4b79f4c1810c31156d80e7eaff874a", claims.AppID)
		require.Equal(t, "sha256:1580f84f1585dbecd84479ae867b6d586de31a19bbc9e551f2fbc20f9df59ec9", claims.ImageDigest)
	})

	t.Run("empty attestation", func(t *testing.T) {
		_, err := prodVerifier.VerifyAttestation([]byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty attestation token")
	})

	t.Run("invalid JWT", func(t *testing.T) {
		_, err := prodVerifier.VerifyAttestation([]byte("not-a-valid-jwt"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "attestation verification failed")
	})

	t.Run("expired token", func(t *testing.T) {
		csToken := createProductionCsToken(GoogleConfidentialSpace)
		csToken.Exp = time.Now().Add(-1 * time.Hour).Unix()
		signedToken := createdSignedJWT(t, privateKey, keyID, csToken)

		_, err := prodVerifier.VerifyAttestation([]byte(signedToken))
		require.Error(t, err)
		require.Contains(t, err.Error(), "token is expired")
	})
}

func TestProductionVerifierWithIntelProvider(t *testing.T) {
	logger := setupLogger()
	projectID := "tee-compute-sepolia-prod"

	jwkSet, privateKey, keyID := createTestJWKS(t)

	// Create attestation verifier with mock JWK set
	attestationVerifier := &AttestationVerifier{
		logger:          logger,
		projectID:       projectID,
		googleJwksCache: jwkSet,
		intelJwksCache:  jwkSet,
		debugMode:       true,
	}

	// Create production verifier for Intel provider
	prodVerifier := NewProductionVerifier(attestationVerifier, IntelTrustAuthority)

	t.Run("successful Intel verification", func(t *testing.T) {
		// Create valid Intel token
		csToken := createProductionCsToken(IntelTrustAuthority)
		signedToken := createdSignedJWT(t, privateKey, keyID, csToken)

		// Verify using production verifier
		claims, err := prodVerifier.VerifyAttestation([]byte(signedToken))
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.Equal(t, "0xb69a8c848a4b79f4c1810c31156d80e7eaff874a", claims.AppID)
		require.Equal(t, "sha256:1580f84f1585dbecd84479ae867b6d586de31a19bbc9e551f2fbc20f9df59ec9", claims.ImageDigest)
	})
}

func TestProductionVerifierIntegration(t *testing.T) {
	// Integration test with real JWKS URLs
	ctx := context.Background()
	logger := setupLogger()
	projectID := "tee-compute-sepolia-prod"

	// Create real attestation verifier (fetches real JWKs)
	attestationVerifier, err := NewAttestationVerifier(ctx, logger, projectID, time.Minute, true)
	require.NoError(t, err)

	// Create production verifier
	prodVerifier := NewProductionVerifier(attestationVerifier, GoogleConfidentialSpace)

	t.Run("invalid token with real JWKS", func(t *testing.T) {
		// Try to verify an obviously invalid token
		_, err := prodVerifier.VerifyAttestation([]byte("definitely-not-a-valid-jwt-token"))
		require.Error(t, err)
		// Should fail at JWT parsing stage
		require.Contains(t, err.Error(), "attestation verification failed")
	})
}
