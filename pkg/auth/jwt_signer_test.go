package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/go-tpm-tools/sdk/attest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestRSAKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	return string(pemBlock)
}

func testVerifiedAttestation() *attestation.VerifiedAttestation {
	return &attestation.VerifiedAttestation{
		TPMClaims: &attest.TPMClaims{
			Platform: attest.PlatformIntelTDX,
			Hardened: true,
			GCE: &attest.GCEInfo{
				ProjectID:     "test-project",
				ProjectNumber: 12345,
				Zone:          "us-central1-a",
				InstanceName:  "tee-0xabc123",
				InstanceID:    67890,
			},
		},
		Container: &attest.ContainerInfo{
			ImageReference: "gcr.io/test/image:latest",
			ImageDigest:    "sha256:deadbeef",
			ImageID:        "sha256:imageid",
			RestartPolicy:  "Never",
		},
		TEEClaims: &attest.TEEClaims{
			TDX: &attest.TDXClaims{
				MRTD: [48]byte{0x01, 0x02, 0x03},
			},
		},
		Platform: attest.PlatformIntelTDX,
	}
}

func parseAndVerifyToken(t *testing.T, tokenStr string, signer *JWTSigner) jwt.Token {
	t.Helper()
	token, err := jwt.Parse([]byte(tokenStr), jwt.WithKey(jwa.RS256(), signer.PublicKey()))
	require.NoError(t, err)
	return token
}

func getStringClaim(t *testing.T, token jwt.Token, key string) string {
	t.Helper()
	var v string
	require.NoError(t, token.Get(key, &v))
	return v
}

func getBoolClaim(t *testing.T, token jwt.Token, key string) bool {
	t.Helper()
	var v bool
	require.NoError(t, token.Get(key, &v))
	return v
}

func TestNewJWTSigner(t *testing.T) {
	pemKey := generateTestRSAKeyPEM(t)
	signer, err := NewJWTSigner(pemKey, time.Hour)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.PublicKey())
}

func TestNewJWTSigner_InvalidKey(t *testing.T) {
	_, err := NewJWTSigner("not-a-pem-key", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block found")
}

func TestSignAttestationJWT_Basic(t *testing.T) {
	pemKey := generateTestRSAKeyPEM(t)
	signer, err := NewJWTSigner(pemKey, time.Hour)
	require.NoError(t, err)

	verified := testVerifiedAttestation()
	tokenStr, err := signer.SignAttestationJWT("0xabc123", verified, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, tokenStr)

	token := parseAndVerifyToken(t, tokenStr, signer)

	// Verify standard claims
	issuer, ok := token.Issuer()
	require.True(t, ok)
	assert.Equal(t, "eigenx-kms", issuer)

	subject, ok := token.Subject()
	require.True(t, ok)
	assert.Equal(t, "0xabc123", subject)

	issuedAt, ok := token.IssuedAt()
	require.True(t, ok)
	assert.False(t, issuedAt.IsZero())

	expiration, ok := token.Expiration()
	require.True(t, ok)
	assert.True(t, expiration.After(issuedAt))

	// No audience set
	_, hasAud := token.Audience()
	assert.False(t, hasAud)

	// Verify custom claims
	assert.Equal(t, "0xabc123", getStringClaim(t, token, "app_id"))
	assert.Equal(t, "GCP_INTEL_TDX", getStringClaim(t, token, "hwmodel"))
	assert.True(t, getBoolClaim(t, token, "hardened"))
	assert.True(t, getBoolClaim(t, token, "secboot"))
}

func TestSignAttestationJWT_WithAudience(t *testing.T) {
	pemKey := generateTestRSAKeyPEM(t)
	signer, err := NewJWTSigner(pemKey, time.Hour)
	require.NoError(t, err)

	verified := testVerifiedAttestation()
	tokenStr, err := signer.SignAttestationJWT("0xabc123", verified, "my-llm-proxy", "")
	require.NoError(t, err)

	token := parseAndVerifyToken(t, tokenStr, signer)

	aud, ok := token.Audience()
	require.True(t, ok)
	require.Len(t, aud, 1)
	assert.Equal(t, "my-llm-proxy", aud[0])
}

func TestSignAttestationJWT_WithExtraData(t *testing.T) {
	pemKey := generateTestRSAKeyPEM(t)
	signer, err := NewJWTSigner(pemKey, time.Hour)
	require.NoError(t, err)

	verified := testVerifiedAttestation()
	tokenStr, err := signer.SignAttestationJWT("0xabc123", verified, "", "dGVzdC1leHRyYS1kYXRh")
	require.NoError(t, err)

	token := parseAndVerifyToken(t, tokenStr, signer)

	assert.Equal(t, "dGVzdC1leHRyYS1kYXRh", getStringClaim(t, token, "extra_data"))
}

func TestSignAttestationJWT_NoExtraData(t *testing.T) {
	pemKey := generateTestRSAKeyPEM(t)
	signer, err := NewJWTSigner(pemKey, time.Hour)
	require.NoError(t, err)

	verified := testVerifiedAttestation()
	tokenStr, err := signer.SignAttestationJWT("0xabc123", verified, "", "")
	require.NoError(t, err)

	token := parseAndVerifyToken(t, tokenStr, signer)

	var v string
	err = token.Get("extra_data", &v)
	assert.Error(t, err) // extra_data should not be present
}

func TestSignAttestationJWT_Expiration(t *testing.T) {
	pemKey := generateTestRSAKeyPEM(t)
	signer, err := NewJWTSigner(pemKey, 30*time.Minute)
	require.NoError(t, err)

	verified := testVerifiedAttestation()
	tokenStr, err := signer.SignAttestationJWT("0xabc123", verified, "", "")
	require.NoError(t, err)

	token := parseAndVerifyToken(t, tokenStr, signer)

	issuedAt, ok := token.IssuedAt()
	require.True(t, ok)
	expiration, ok := token.Expiration()
	require.True(t, ok)

	diff := expiration.Sub(issuedAt)
	assert.InDelta(t, 30*time.Minute, diff, float64(5*time.Second))
}

func TestSignAttestationJWT_TDXClaims(t *testing.T) {
	pemKey := generateTestRSAKeyPEM(t)
	signer, err := NewJWTSigner(pemKey, time.Hour)
	require.NoError(t, err)

	verified := testVerifiedAttestation()
	tokenStr, err := signer.SignAttestationJWT("0xabc123", verified, "", "")
	require.NoError(t, err)

	token := parseAndVerifyToken(t, tokenStr, signer)

	var tdx map[string]interface{}
	err = token.Get("tdx", &tdx)
	require.NoError(t, err)
	require.NotNil(t, tdx)
	assert.Contains(t, tdx, "mrtd")
}
