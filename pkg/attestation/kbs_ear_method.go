package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	// DefaultKBSExpectedIssuer is the default `iss` claim emitted by Trustee's
	// attestation-service when `Config::default()` is used. See
	// confidential-containers/trustee:attestation-service/src/ear_token/broker.rs.
	DefaultKBSExpectedIssuer = "CoCo-Attestation-Service"
)

// KBSEARAttestationMethod implements AttestationMethod for EAR (Entity Attestation
// Result) tokens issued by CoCo Trustee/KBS attestation-service.
//
// Trustee performs the AMD signature verification on the raw SEV-SNP report and
// emits an EAR JWT (ES256) signed with its own ECDSA P-256 key. This KMS only
// sees and verifies the EAR JWT — it never inspects the AMD signature directly.
//
// The token's `init_data` claim carries the SEV-SNP HOST_DATA value (a 32-byte
// hash of the cc_init_data document) and is used as the workload-identity check:
// `claims.ImageDigest = "init-data:" + hex(init_data)` is compared against the
// on-chain release.ImageDigest by the existing handler logic.
type KBSEARAttestationMethod struct {
	jwksCache        jwk.Set
	expectedIssuer   string
	expectedAudience string // optional; "" means skip audience check
	logger           *slog.Logger
}

// NewKBSEARAttestationMethod constructs a KBS-EAR attestation method.
//
// The JWKS cache must already be initialised against the KBS signing-key URL
// (use NewJWKCache from attestation.go). expectedIssuer must be non-empty and
// should match the Trustee's `Config::token_issuer_name`. expectedAudience is
// optional — pass "" to skip audience validation.
func NewKBSEARAttestationMethod(
	jwksCache jwk.Set,
	expectedIssuer string,
	expectedAudience string,
	logger *slog.Logger,
) *KBSEARAttestationMethod {
	return &KBSEARAttestationMethod{
		jwksCache:        jwksCache,
		expectedIssuer:   expectedIssuer,
		expectedAudience: expectedAudience,
		logger:           logger.With("component", "kbs_ear_attestation"),
	}
}

// Name returns the identifier for this attestation method.
func (k *KBSEARAttestationMethod) Name() string {
	return "kbs-ear"
}

// Verify validates a KBS-issued EAR JWT and returns the extracted claims.
//
// The flow mirrors GCPAttestationMethod.Verify: parse the JWT, verify the
// signature against the cached JWKS, validate iss/aud/exp, then enforce nonce
// binding (hex(SHA256(rsaPubKey || extraData)) == eat_nonce), require a jti,
// and project the EAR-specific fields (init_data, eat_nonce) into the unified
// AttestationClaims struct.
func (k *KBSEARAttestationMethod) Verify(request *AttestationRequest) (*types.AttestationClaims, error) {
	if request == nil {
		return nil, fmt.Errorf("attestation request is nil")
	}
	if len(request.Attestation) == 0 {
		return nil, fmt.Errorf("empty attestation token")
	}
	// RSAPubKeyTmp is mandatory for nonce binding — same rationale as
	// GCPAttestationMethod.Verify: skipping the check when it's empty would
	// silently bypass nonce binding for any caller that forgot to populate it.
	if len(request.RSAPubKeyTmp) == 0 {
		return nil, fmt.Errorf("RSAPubKeyTmp is required for nonce binding")
	}

	tokenString := string(request.Attestation)

	// Filter JWKS by token algorithm (mirrors attestation.go behaviour).
	filteredKeySet, err := getFilteredKeySetForToken(tokenString, k.jwksCache, k.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to filter JWKS: %w", err)
	}

	// Parse and verify the token. WithValidate(true) enforces exp/nbf/iat per RFC 7519.
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(filteredKeySet),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("token parsing/verification failed: %w", err)
	}

	// Validate issuer.
	issuer, ok := token.Issuer()
	if !ok {
		return nil, fmt.Errorf("issuer claim not found in token")
	}
	if issuer != k.expectedIssuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", k.expectedIssuer, issuer)
	}

	// Validate audience if expected audience configured. EAR's `aud` is optional.
	if k.expectedAudience != "" {
		audiences, ok := token.Audience()
		if !ok {
			return nil, fmt.Errorf("audience claim not found in token")
		}
		matched := false
		for _, a := range audiences {
			if a == k.expectedAudience {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("invalid audience: expected %s, got %v", k.expectedAudience, audiences)
		}
	}

	// Marshal the token into a generic map so we can navigate EAR-specific
	// claims (eat_nonce, init_data, submods.<tee>.init_data) without modelling
	// the full EAR schema. EAR is just structured JSON inside the JWT payload.
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token to JSON: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(tokenBytes, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token JSON: %w", err)
	}

	// Extract eat_nonce.
	eatNonceRaw, ok := raw["eat_nonce"]
	if !ok {
		return nil, fmt.Errorf("eat_nonce claim not found in token")
	}
	eatNonce, err := extractNonce(eatNonceRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract eat_nonce: %w", err)
	}
	if eatNonce == "" {
		return nil, fmt.Errorf("eat_nonce claim is empty")
	}

	// Nonce binding: expected = hex(SHA256(rsaPubKey || extraData)).
	nonceInput := make([]byte, 0, len(request.RSAPubKeyTmp)+len(request.ExtraData))
	nonceInput = append(nonceInput, request.RSAPubKeyTmp...)
	nonceInput = append(nonceInput, request.ExtraData...)
	h := sha256.Sum256(nonceInput)
	expectedNonce := hex.EncodeToString(h[:])
	if strings.ToLower(eatNonce) != expectedNonce {
		return nil, fmt.Errorf("nonce mismatch: ephemeral RSA key (and extra_data if present) not bound to attestation token")
	}

	// Extract init_data: EAR places per-device appraisals under `submods`. Try
	// each submod first, then fall back to a top-level `init_data` claim for
	// flexibility against future Trustee versions.
	initDataHex, err := extractEARInitData(raw)
	if err != nil {
		return nil, err
	}

	// Extract jti for replay protection.
	jti, ok := token.JwtID()
	if !ok || jti == "" {
		return nil, fmt.Errorf("attestation token missing jti claim")
	}

	// Pull iat/exp via typed accessors (Unix seconds).
	var iat, exp int64
	if t, ok := token.IssuedAt(); ok {
		iat = t.Unix()
	}
	if t, ok := token.Expiration(); ok {
		exp = t.Unix()
	} else {
		// EAR tokens always carry exp (default 5min). Missing exp would mean
		// jwt.WithValidate(true) above couldn't enforce expiry — fail closed.
		return nil, fmt.Errorf("expiration claim not found in token")
	}

	claims := &types.AttestationClaims{
		AppID:       request.AppID,
		ImageDigest: "init-data:" + initDataHex,
		Nonce:       eatNonce,
		JTI:         jti,
		IssuedAt:    iat,
		ExpiresAt:   exp,
	}

	k.logger.Debug("KBS-EAR claims extracted",
		"app_id", claims.AppID,
		"image_digest", claims.ImageDigest,
		"nonce", claims.Nonce,
		"jti", claims.JTI,
		"iat", time.Unix(iat, 0),
		"exp", time.Unix(exp, 0))
	return claims, nil
}

// extractEARInitData walks the EAR payload to find the SEV-SNP HOST_DATA value.
// Real Trustee tokens surface it as
//
//	submods.{tee_class}{idx}["ear.veraison.annotated-evidence"].init_data
//
// e.g. `submods.cpu0["ear.veraison.annotated-evidence"].init_data`. Submod names
// are formed from the tee_class plus a counter (broker.rs:313). We also fall
// back to a direct `submods.<name>.init_data` for non-Veraison emitters and to a
// token-top-level `init_data` for forward-compat.
//
// When multiple submods carry init_data, the values must agree (they all derive
// from the same boot-time HOST_DATA). Iteration is in sorted key order so the
// returned value is deterministic.
//
// Returns the lowercase hex string for comparison against the on-chain
// "init-data:<hex>" value.
func extractEARInitData(raw map[string]any) (string, error) {
	// Top-level fallback first — cheapest path.
	if v, ok := raw["init_data"]; ok {
		s, err := initDataAsHex(v)
		if err != nil {
			return "", fmt.Errorf("invalid top-level init_data: %w", err)
		}
		if s != "" {
			return s, nil
		}
	}

	submodsRaw, ok := raw["submods"]
	if !ok {
		return "", fmt.Errorf("init_data claim not found (no submods, no top-level init_data)")
	}
	submods, ok := submodsRaw.(map[string]any)
	if !ok {
		return "", fmt.Errorf("submods claim has unexpected type %T", submodsRaw)
	}

	// Iterate submods in sorted order so a multi-TEE EAR yields a deterministic
	// result. If two submods disagree on init_data (shouldn't happen — same boot
	// context — but the proto allows it), surface as an error rather than picking
	// silently.
	names := make([]string, 0, len(submods))
	for n := range submods {
		names = append(names, n)
	}
	sort.Strings(names)

	var found string
	var foundIn string
	for _, name := range names {
		mod, ok := submods[name].(map[string]any)
		if !ok {
			continue
		}
		// Real Trustee EAR shape: init_data lives inside the
		// "ear.veraison.annotated-evidence" wrapper.
		v, vok := lookupInitDataInSubmod(mod)
		if !vok {
			continue
		}
		s, err := initDataAsHex(v)
		if err != nil {
			return "", fmt.Errorf("invalid submods.%s init_data: %w", name, err)
		}
		if s == "" {
			continue
		}
		if found != "" && found != s {
			return "", fmt.Errorf("conflicting init_data across submods: %s=%s vs %s=%s",
				foundIn, found, name, s)
		}
		found = s
		foundIn = name
	}
	if found != "" {
		return found, nil
	}
	return "", fmt.Errorf("init_data claim not found in any submod or at token top level")
}

// lookupInitDataInSubmod returns the init_data value for an EAR submod,
// preferring the standard "ear.veraison.annotated-evidence" wrapper but
// falling back to the bare submod for non-Veraison brokers.
func lookupInitDataInSubmod(mod map[string]any) (any, bool) {
	if wrapperRaw, ok := mod["ear.veraison.annotated-evidence"]; ok {
		if wrapper, wok := wrapperRaw.(map[string]any); wok {
			if v, vok := wrapper["init_data"]; vok {
				return v, true
			}
		}
	}
	if v, ok := mod["init_data"]; ok {
		return v, true
	}
	return nil, false
}

// initDataAsHex normalises an init_data claim value to a lowercase hex string.
// Trustee emits init_data as a hex string today; tolerate the JSON-array byte
// form too in case a future broker swaps encodings.
func initDataAsHex(v any) (string, error) {
	switch val := v.(type) {
	case string:
		// Trustee's encoding is per-verifier: the pure SEV-SNP verifier emits hex
		// (deps/verifier/src/snp/mod.rs), but az-snp-vtpm emits standard-base64
		// (deps/verifier/src/az_snp_vtpm/mod.rs). Try hex first (our primary path),
		// then base64. Normalize to lowercase hex either way so callers compare
		// against the on-chain "init-data:<hex>" representation.
		if b, err := hex.DecodeString(val); err == nil {
			return hex.EncodeToString(b), nil
		}
		if b, err := base64.StdEncoding.DecodeString(val); err == nil {
			return hex.EncodeToString(b), nil
		}
		return "", fmt.Errorf("init_data string is neither hex nor standard-base64")
	case []any:
		buf := make([]byte, 0, len(val))
		for i, b := range val {
			f, ok := b.(float64) // JSON numbers decode to float64
			if !ok {
				return "", fmt.Errorf("init_data array element %d is not a number (got %T)", i, b)
			}
			if f < 0 || f > 255 || f != float64(byte(f)) {
				return "", fmt.Errorf("init_data array element %d is not a byte: %v", i, f)
			}
			buf = append(buf, byte(f))
		}
		return hex.EncodeToString(buf), nil
	default:
		return "", fmt.Errorf("unsupported init_data type %T", v)
	}
}

// NewKBSJWKCache is a thin wrapper around NewJWKCache that exists purely to
// document the calling convention at the registration site (cmd/kmsServer).
func NewKBSJWKCache(ctx context.Context, jwkURL string, refreshInterval time.Duration) (jwk.Set, error) {
	return NewJWKCache(ctx, jwkURL, refreshInterval)
}
