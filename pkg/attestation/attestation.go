package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	instanceNameDelimiter     = "-"
	confidentialSpaceJWKURL   = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
	intelTrustAuthorityJWKURL = "https://portal.trustauthority.intel.com/certs"
	googleIssuer              = "https://confidentialcomputing.googleapis.com"
	intelIssuer               = "https://portal.trustauthority.intel.com"
	googleAudience            = "https://sts.googleapis.com"
)

// AttestationProvider specifies which attestation service to use for verification
type AttestationProvider int

const (
	GoogleConfidentialSpace AttestationProvider = iota
	IntelTrustAuthority
)

type AttestationVerifierInterface interface {
	VerifyAttestation(ctx context.Context, tokenString string, provider AttestationProvider) (*AttestationClaims, error)
}

type AttestationClaims struct {
	AppID       string `json:"app_id"`
	ImageDigest string `json:"image_digest"`
	Nonce       string `json:"nonce"`
}

// Structured types for attestation token parsing
type ConfidentialSpaceToken struct {
	Issuer      string     `json:"iss"`
	Audience    any        `json:"aud"`
	Exp         int64      `json:"exp"`
	Nbf         int64      `json:"nbf"`
	EatNonce    any        `json:"eat_nonce,omitempty"` // string for Google, []string for Intel
	SwName      string     `json:"swname"`
	AttesterTCB []string   `json:"attester_tcb,omitempty"` // Only in Google CS
	HwModel     string     `json:"hwmodel"`
	DbgStat     string     `json:"dbgstat"`
	SwVersion   []string   `json:"swversion"`
	SubMods     SubMods    `json:"submods"`
	TDXSubMods  TDXSubMods `json:"tdx,omitempty"` // Only in Intel
}

type SubMods struct {
	Container         Container         `json:"container"`
	GCE               GCE               `json:"gce"`
	ConfidentialSpace ConfidentialSpace `json:"confidential_space"`
}

type TDXSubMods struct {
	GcpAttesterTcbStatus string `json:"gcp_attester_tcb_status"`
	GcpAttesterTcbDate   string `json:"gcp_attester_tcb_date"`
}

type ConfidentialSpace struct {
	SupportAttributes []string `json:"support_attributes"`
}

type Container struct {
	ImageDigest string `json:"image_digest"`
}

type GCE struct {
	Zone         string `json:"zone"`
	ProjectID    string `json:"project_id"`
	InstanceName string `json:"instance_name"`
}

type AttestationVerifier struct {
	logger          *slog.Logger
	googleJwksCache jwk.Set
	intelJwksCache  jwk.Set
	projectID       string
	debugMode       bool
}

func NewAttestationVerifier(ctx context.Context, logger *slog.Logger, projectID string, refreshInterval time.Duration, debugMode bool) (*AttestationVerifier, error) {
	avLogger := logger.With("component", "attestation_verifier")
	avLogger.Debug("Initializing attestation verifier", "project_id", projectID, "refresh_interval", refreshInterval)

	avLogger.Debug("Creating Google Confidential Space JWK cache", "jwk_url", confidentialSpaceJWKURL)
	googleJwksCache, err := NewJWKCache(ctx, confidentialSpaceJWKURL, refreshInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to create Google JWK cache: %w", err)
	}

	avLogger.Debug("Creating Intel Trust Authority JWK cache", "jwk_url", intelTrustAuthorityJWKURL)
	intelJwksCache, err := NewJWKCache(ctx, intelTrustAuthorityJWKURL, refreshInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to create Intel JWK cache: %w", err)
	}

	avLogger.Info("Attestation verifier initialized successfully", "project_id", projectID)

	return &AttestationVerifier{
		logger:          avLogger,
		projectID:       projectID,
		googleJwksCache: googleJwksCache,
		intelJwksCache:  intelJwksCache,
		debugMode:       debugMode,
	}, nil
}

func (av *AttestationVerifier) VerifyAttestation(ctx context.Context, tokenString string, provider AttestationProvider) (*AttestationClaims, error) {
	av.logger.Debug("Starting attestation verification", "token_length", len(tokenString), "provider", provider)

	// Get provider-specific configuration
	var jwksCache jwk.Set
	var expectedIssuer string
	var validateFunc func(*ConfidentialSpaceToken) error

	switch provider {
	case GoogleConfidentialSpace:
		jwksCache = av.googleJwksCache
		expectedIssuer = googleIssuer
		validateFunc = av.validateConfidentialSpaceToken
	case IntelTrustAuthority:
		jwksCache = av.intelJwksCache
		expectedIssuer = intelIssuer
		validateFunc = av.validateIntelTrustAuthorityToken
	default:
		return nil, fmt.Errorf("unknown attestation provider: %d", provider)
	}

	// Filter JWKS by token algorithm to handle duplicate key IDs
	filteredKeySet, err := getFilteredKeySetForToken(tokenString, jwksCache, av.logger)
	if err != nil {
		return nil, err
	}

	// Parse and verify the token with the filtered key set
	av.logger.Debug("Parsing and verifying JWT token", "provider", provider)
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(filteredKeySet),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("token parsing/verification failed: %w", err)
	}

	// Validate issuer
	issuer, ok := token.Issuer()
	if !ok {
		return nil, fmt.Errorf("issuer claim not found in token")
	}
	if issuer != expectedIssuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", expectedIssuer, issuer)
	}

	// Validate audience - accept either Google STS or EigenX KMS audience
	audiences, ok := token.Audience()
	if !ok {
		return nil, fmt.Errorf("audience claim not found in token")
	}
	if len(audiences) != 1 {
		return nil, fmt.Errorf("audience must contain exactly one value, got %d", len(audiences))
	}
	audStr := audiences[0]
	if audStr != googleAudience && audStr != types.KMSJWTAudience {
		return nil, fmt.Errorf("invalid audience: expected %s or %s, got %s", googleAudience, types.KMSJWTAudience, audStr)
	}

	// Parse token into structured format
	csToken := &ConfidentialSpaceToken{}
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token to JSON: %w", err)
	}
	if err := json.Unmarshal(tokenBytes, csToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token JSON to ConfidentialSpaceToken: %w", err)
	}

	// Validate provider-specific claims
	if err := validateFunc(csToken); err != nil {
		return nil, err
	}

	// Extract app ID from instance name
	appID, err := extractAppIDFromInstanceName(csToken.SubMods.GCE.InstanceName)
	if err != nil {
		return nil, fmt.Errorf("failed to extract app ID from instance name: %w", err)
	}

	// Extract nonce using helper
	nonce, err := extractNonce(csToken.EatNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to extract nonce: %w", err)
	}

	result := &AttestationClaims{
		AppID:       appID,
		ImageDigest: csToken.SubMods.Container.ImageDigest,
		Nonce:       nonce,
	}

	av.logger.Debug("Attestation claims extracted", "app_id", appID, "image_digest", csToken.SubMods.Container.ImageDigest, "nonce", nonce)
	return result, nil
}

// validationConfig holds provider-specific validation rules
type validationConfig struct {
	expectedHwModel     string
	requireAttesterTCB  bool
	requiredSupportAttr string // "STABLE" for Google, "EXPERIMENTAL" for Intel
	requireTDXSubmods   bool
}

var (
	googleValidationConfig = validationConfig{
		expectedHwModel:     "GCP_INTEL_TDX",
		requireAttesterTCB:  true,
		requiredSupportAttr: "STABLE",
		requireTDXSubmods:   false,
	}

	intelValidationConfig = validationConfig{
		expectedHwModel:     "INTEL_TDX",
		requireAttesterTCB:  false,
		requiredSupportAttr: "EXPERIMENTAL",
		requireTDXSubmods:   true,
	}
)

// extractNonce extracts the nonce from the eat_nonce field, handling both string and array formats
func extractNonce(eatNonce any) (string, error) {
	if eatNonce == nil {
		return "", nil
	}

	// Try as string first
	if s, ok := eatNonce.(string); ok {
		return s, nil
	}

	// Try as array (Intel format)
	if arr, ok := eatNonce.([]any); ok {
		if len(arr) == 1 {
			if s, ok := arr[0].(string); ok {
				return s, nil
			}
		}
		return "", fmt.Errorf("eat_nonce array must contain exactly one string element, got %d elements", len(arr))
	}

	return "", fmt.Errorf("eat_nonce must be a string or array of strings, got %T", eatNonce)
}

// validateToken validates the business logic of the token claims using provider-specific configuration
func (av *AttestationVerifier) validateToken(csToken *ConfidentialSpaceToken, cfg validationConfig) error {
	// Validate software name
	if csToken.SwName != "CONFIDENTIAL_SPACE" {
		return fmt.Errorf("invalid software name: %s. Expected CONFIDENTIAL_SPACE", csToken.SwName)
	}
	av.logger.Debug("Software name validated", "sw_name", csToken.SwName)

	// Validate attester TCB (Google only)
	if cfg.requireAttesterTCB {
		if len(csToken.AttesterTCB) != 1 || csToken.AttesterTCB[0] != "INTEL" {
			return fmt.Errorf("invalid attester_tcb: %v. Expected [\"INTEL\"]", csToken.AttesterTCB)
		}
		av.logger.Debug("Attester TCB validated", "attester_tcb", csToken.AttesterTCB)
	}

	// Validate hardware model
	if csToken.HwModel != cfg.expectedHwModel {
		return fmt.Errorf("invalid hwmodel: %s. Expected %s", csToken.HwModel, cfg.expectedHwModel)
	}
	av.logger.Debug("Hardware model validated", "hwmodel", csToken.HwModel)

	// Validate software version (must be >= 250300 for TDX support)
	if len(csToken.SwVersion) == 0 {
		return fmt.Errorf("empty swversion array")
	}
	var swVersionInt int64
	if _, err := fmt.Sscanf(csToken.SwVersion[0], "%d", &swVersionInt); err != nil {
		return fmt.Errorf("failed to parse swversion: %w", err)
	}
	if swVersionInt < 250300 {
		return fmt.Errorf("invalid swversion: %d. Expected >= 250300 for TDX support", swVersionInt)
	}
	av.logger.Debug("Software version validated", "swversion", swVersionInt)

	// Validate TDX submods (Intel only)
	if cfg.requireTDXSubmods {
		if csToken.TDXSubMods.GcpAttesterTcbStatus == "" {
			return fmt.Errorf("tdx submods not found in Intel Trust Authority token")
		}
		if csToken.TDXSubMods.GcpAttesterTcbStatus != "UpToDate" {
			return fmt.Errorf("invalid tdx.gcp_attester_tcb_status: %s. Expected UpToDate", csToken.TDXSubMods.GcpAttesterTcbStatus)
		}
		av.logger.Debug("TDX TCB status validated", "gcp_attester_tcb_status", csToken.TDXSubMods.GcpAttesterTcbStatus)
	}

	// Validate debug status and support attributes - only check in production (non-debug) mode
	if !av.debugMode {
		if csToken.DbgStat != "disabled-since-boot" {
			return fmt.Errorf("invalid dbgstat: %s. Expected disabled-since-boot", csToken.DbgStat)
		}
		supportAttrs := csToken.SubMods.ConfidentialSpace.SupportAttributes
		if !slices.Contains(supportAttrs, cfg.requiredSupportAttr) {
			return fmt.Errorf("invalid confidential_space.support_attributes: %v. Expected to contain %s", supportAttrs, cfg.requiredSupportAttr)
		}
		av.logger.Debug("Confidential space support attributes validated", "support_attributes", supportAttrs, "required", cfg.requiredSupportAttr)
	} else {
		av.logger.Debug("Debug mode enabled, skipping support and debug status validation")
	}

	// Validate project ID
	projectID := csToken.SubMods.GCE.ProjectID
	if projectID != av.projectID {
		return fmt.Errorf("invalid project_id: %s. Expected %s", projectID, av.projectID)
	}
	av.logger.Debug("Project ID validated", "project_id", projectID)

	return nil
}

// validateConfidentialSpaceToken validates Google Confidential Space token claims
func (av *AttestationVerifier) validateConfidentialSpaceToken(csToken *ConfidentialSpaceToken) error {
	return av.validateToken(csToken, googleValidationConfig)
}

// validateIntelTrustAuthorityToken validates Intel Trust Authority token claims
func (av *AttestationVerifier) validateIntelTrustAuthorityToken(csToken *ConfidentialSpaceToken) error {
	return av.validateToken(csToken, intelValidationConfig)
}

func extractAppIDFromInstanceName(instanceName string) (string, error) {
	instanceNameParts := strings.Split(instanceName, instanceNameDelimiter)
	if len(instanceNameParts) < 2 {
		return "", fmt.Errorf("invalid instance name: %s. Expected at least %d parts", instanceName, 2)
	}
	return instanceNameParts[len(instanceNameParts)-1], nil
}

func NewJWKCache(ctx context.Context, jwkUrl string, refreshInterval time.Duration) (jwk.Set, error) {
	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("failed to create jwk cache: %w", err)
	}

	// register a constant refresh interval for this URL.
	err = cache.Register(ctx, jwkUrl, jwk.WithConstantInterval(refreshInterval))
	if err != nil {
		return nil, fmt.Errorf("failed to register jwk location: %w", err)
	}

	// fetch once on application startup
	_, err = cache.Refresh(ctx, jwkUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch on startup: %w", err)
	}

	// create the cached key set
	return cache.CachedSet(jwkUrl)
}

// getFilteredKeySetForToken parses the token header and filters the JWKS to only include keys
// matching the token's algorithm. This works around Intel's JWKS having duplicate key IDs
// with different algorithms.
func getFilteredKeySetForToken(tokenString string, jwksCache jwk.Set, logger *slog.Logger) (jwk.Set, error) {
	// Parse JWS message to extract header
	msg, err := jws.Parse([]byte(tokenString))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS message: %w", err)
	}

	// Get the first signature's header (there should only be one)
	if len(msg.Signatures()) == 0 {
		return nil, fmt.Errorf("token has no signatures")
	}
	header := msg.Signatures()[0].ProtectedHeaders()

	// Get the algorithm and key ID from the header
	tokenAlg, ok := header.Algorithm()
	if !ok {
		return nil, fmt.Errorf("token does not specify an algorithm")
	}
	keyID, ok := header.KeyID()
	if !ok || keyID == "" {
		return nil, fmt.Errorf("token does not specify a key ID")
	}
	logger.Debug("Token requirements", "kid", keyID, "algorithm", tokenAlg)

	// Filter JWKS to only include keys with matching algorithm
	filteredKeySet := jwk.NewSet()
	for i := 0; i < jwksCache.Len(); i++ {
		key, ok := jwksCache.Key(i)
		if !ok {
			continue
		}
		// Only add keys where the algorithm matches the token's algorithm
		if keyAlg, ok := key.Algorithm(); ok && keyAlg == tokenAlg {
			if kid, ok := key.KeyID(); ok {
				logger.Debug("Added key to filtered set", "kid", kid, "algorithm", keyAlg)
			}
			_ = filteredKeySet.AddKey(key)
		}
	}

	if filteredKeySet.Len() == 0 {
		return nil, fmt.Errorf("no keys found in JWKS matching algorithm %s", tokenAlg)
	}
	logger.Debug("Filtered JWKS", "original_count", jwksCache.Len(), "filtered_count", filteredKeySet.Len())

	return filteredKeySet, nil
}
