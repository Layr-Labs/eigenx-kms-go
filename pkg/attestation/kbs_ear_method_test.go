package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testKBSIssuer   = "CoCo-Attestation-Service"
	testKBSAudience = "test-kms"
	testKBSKeyID    = "test-kbs-key"
)

// kbsTestEnv bundles the keys + JWKS used by KBS-EAR tests.
type kbsTestEnv struct {
	privateKey *ecdsa.PrivateKey
	jwks       jwk.Set
}

func newKBSTestEnv(t *testing.T) *kbsTestEnv {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubJWK, err := jwk.Import(&priv.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pubJWK.Set(jwk.KeyIDKey, testKBSKeyID))
	require.NoError(t, pubJWK.Set(jwk.AlgorithmKey, jwa.ES256()))
	require.NoError(t, pubJWK.Set(jwk.KeyUsageKey, "sig"))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubJWK))

	return &kbsTestEnv{privateKey: priv, jwks: set}
}

// signEARToken builds an EAR-shaped JWT from the supplied claim map and signs
// it with the test private key. Use overrides to omit/replace claims for
// negative tests.
func (env *kbsTestEnv) signEARToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	tok := jwt.New()
	for k, v := range claims {
		require.NoError(t, tok.Set(k, v))
	}

	signKey, err := jwk.Import(env.privateKey)
	require.NoError(t, err)
	require.NoError(t, signKey.Set(jwk.KeyIDKey, testKBSKeyID))
	require.NoError(t, signKey.Set(jwk.AlgorithmKey, jwa.ES256()))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), signKey))
	require.NoError(t, err)
	return string(signed)
}

// validClaims returns a baseline EAR claim map matching the real Trustee
// shape: submods.cpu0["ear.veraison.annotated-evidence"].init_data. Per-test
// overrides can mutate/delete entries before signing.
func validClaims(initDataHex, eatNonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":       testKBSIssuer,
		"aud":       testKBSAudience,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
		"jti":       "test-jti-" + initDataHex[:8],
		"eat_nonce": eatNonce,
		"submods": map[string]any{
			"cpu0": map[string]any{
				"ear.veraison.annotated-evidence": map[string]any{
					"init_data": initDataHex,
				},
			},
		},
	}
}

func nonceFor(parts ...[]byte) string {
	var input []byte
	for _, p := range parts {
		input = append(input, p...)
	}
	h := sha256.Sum256(input)
	return hex.EncodeToString(h[:])
}

func newKBSMethod(env *kbsTestEnv, audience string) *KBSEARAttestationMethod {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewKBSEARAttestationMethod(env.jwks, testKBSIssuer, audience, logger)
}

func TestKBSEARMethodName(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, "")
	assert.Equal(t, "kbs-ear", method.Name())
}

func TestKBSEARVerify_ValidToken(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, testKBSAudience)

	rsaKey := []byte("test-rsa-public-key-pem")
	extraData := []byte("binding-payload")
	expectedNonce := nonceFor(rsaKey, extraData)

	digest := sha256.Sum256([]byte("init-data-bytes-padded-to-32"))
	initData := hex.EncodeToString(digest[:])

	token := env.signEARToken(t, validClaims(initData, expectedNonce))

	claims, err := method.Verify(&AttestationRequest{
		Method:       "kbs-ear",
		AppID:        "my-app",
		Attestation:  []byte(token),
		RSAPubKeyTmp: rsaKey,
		ExtraData:    extraData,
	})

	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, "my-app", claims.AppID, "AppID must come from the request, not the EAR")
	assert.Equal(t, "init-data:"+initData, claims.ImageDigest)
	assert.Equal(t, expectedNonce, claims.Nonce)
	assert.NotEmpty(t, claims.JTI)
	assert.NotZero(t, claims.IssuedAt)
	assert.NotZero(t, claims.ExpiresAt)
}

func TestKBSEARVerify_NoAudienceConfigured_SkipsCheck(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, "") // empty -> skip

	rsaKey := []byte("rsa-key")
	expectedNonce := nonceFor(rsaKey)

	initData := "00" + hex.EncodeToString(make([]byte, 31))
	claims := validClaims(initData, expectedNonce)
	claims["aud"] = "any-audience-because-we-skip"

	token := env.signEARToken(t, claims)

	got, err := method.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte(token),
		RSAPubKeyTmp: rsaKey,
	})
	require.NoError(t, err)
	assert.Equal(t, "init-data:"+initData, got.ImageDigest)
}

func TestKBSEARVerify_TopLevelInitDataFallback(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, "")

	rsaKey := []byte("rsa-key")
	expectedNonce := nonceFor(rsaKey)
	initData := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	claims := map[string]any{
		"iss":       testKBSIssuer,
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(5 * time.Minute).Unix(),
		"jti":       "jti-top-level",
		"eat_nonce": expectedNonce,
		"init_data": initData,
		// no submods
	}
	token := env.signEARToken(t, claims)

	got, err := method.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte(token),
		RSAPubKeyTmp: rsaKey,
	})
	require.NoError(t, err)
	assert.Equal(t, "init-data:"+initData, got.ImageDigest)
}

func TestKBSEARVerify_WrongSigningKey(t *testing.T) {
	env := newKBSTestEnv(t)
	otherEnv := newKBSTestEnv(t)
	// Use otherEnv's key to sign, but verify against env's JWKS.
	method := newKBSMethod(env, "")

	rsaKey := []byte("rsa-key")
	expectedNonce := nonceFor(rsaKey)
	token := otherEnv.signEARToken(t, validClaims("aa"+hex.EncodeToString(make([]byte, 31)), expectedNonce))

	_, err := method.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte(token),
		RSAPubKeyTmp: rsaKey,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestKBSEARVerify_WrongIssuer(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, "")

	rsaKey := []byte("rsa-key")
	expectedNonce := nonceFor(rsaKey)
	claims := validClaims("aa"+hex.EncodeToString(make([]byte, 31)), expectedNonce)
	claims["iss"] = "evil-issuer"

	token := env.signEARToken(t, claims)
	_, err := method.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte(token),
		RSAPubKeyTmp: rsaKey,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid issuer")
}

func TestKBSEARVerify_WrongAudience(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, testKBSAudience) // audience required

	rsaKey := []byte("rsa-key")
	expectedNonce := nonceFor(rsaKey)
	claims := validClaims("aa"+hex.EncodeToString(make([]byte, 31)), expectedNonce)
	claims["aud"] = "wrong-aud"

	token := env.signEARToken(t, claims)
	_, err := method.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte(token),
		RSAPubKeyTmp: rsaKey,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid audience")
}

func TestKBSEARVerify_ExpiredToken(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, "")

	rsaKey := []byte("rsa-key")
	expectedNonce := nonceFor(rsaKey)
	past := time.Now().Add(-1 * time.Hour)
	claims := validClaims("aa"+hex.EncodeToString(make([]byte, 31)), expectedNonce)
	claims["iat"] = past.Unix()
	claims["nbf"] = past.Unix()
	claims["exp"] = past.Add(time.Minute).Unix() // expired 59 min ago

	token := env.signEARToken(t, claims)
	_, err := method.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte(token),
		RSAPubKeyTmp: rsaKey,
	})
	require.Error(t, err)
	// jwt.WithValidate(true) wraps expiry errors under our parse failure prefix.
	assert.Contains(t, err.Error(), "token parsing/verification failed")
}

func TestKBSEARVerify_WrongNonce(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, "")

	rsaKey := []byte("rsa-key")
	// claim nonce is bound to a different RSA key — MITM substitution attempt
	claimNonce := nonceFor([]byte("attacker-rsa-key"))
	claims := validClaims("aa"+hex.EncodeToString(make([]byte, 31)), claimNonce)

	token := env.signEARToken(t, claims)
	_, err := method.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte(token),
		RSAPubKeyTmp: rsaKey,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce mismatch")
}

func TestKBSEARVerify_MissingInitData(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, "")

	rsaKey := []byte("rsa-key")
	expectedNonce := nonceFor(rsaKey)

	claims := map[string]any{
		"iss":       testKBSIssuer,
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(5 * time.Minute).Unix(),
		"jti":       "jti-no-init",
		"eat_nonce": expectedNonce,
		"submods": map[string]any{
			"cpu0": map[string]any{
				"ear.veraison.annotated-evidence": map[string]any{
					// no init_data here
					"measurement": "abc",
				},
			},
		},
	}
	token := env.signEARToken(t, claims)

	_, err := method.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte(token),
		RSAPubKeyTmp: rsaKey,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "init_data")
}

func TestKBSEARVerify_MissingEatNonce(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, "")

	rsaKey := []byte("rsa-key")
	claims := map[string]any{
		"iss": testKBSIssuer,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"jti": "jti-no-nonce",
		"submods": map[string]any{
			"cpu0": map[string]any{
				"ear.veraison.annotated-evidence": map[string]any{
					"init_data": "00" + hex.EncodeToString(make([]byte, 31)),
				},
			},
		},
	}
	token := env.signEARToken(t, claims)

	_, err := method.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte(token),
		RSAPubKeyTmp: rsaKey,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "eat_nonce")
}

func TestKBSEARVerify_MissingJTI(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, "")

	rsaKey := []byte("rsa-key")
	expectedNonce := nonceFor(rsaKey)
	claims := validClaims("aa"+hex.EncodeToString(make([]byte, 31)), expectedNonce)
	delete(claims, "jti")

	token := env.signEARToken(t, claims)
	_, err := method.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte(token),
		RSAPubKeyTmp: rsaKey,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jti")
}

func TestKBSEARVerify_NilRequest(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, "")

	_, err := method.Verify(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestKBSEARVerify_EmptyAttestation(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, "")

	_, err := method.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  nil,
		RSAPubKeyTmp: []byte("rsa-key"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty attestation")
}

func TestKBSEARVerify_EmptyRSAPubKeyTmp(t *testing.T) {
	env := newKBSTestEnv(t)
	method := newKBSMethod(env, "")

	rsaKey := []byte("rsa-key")
	expectedNonce := nonceFor(rsaKey)
	token := env.signEARToken(t, validClaims("aa"+hex.EncodeToString(make([]byte, 31)), expectedNonce))

	_, err := method.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte(token),
		RSAPubKeyTmp: nil,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RSAPubKeyTmp is required")
}
