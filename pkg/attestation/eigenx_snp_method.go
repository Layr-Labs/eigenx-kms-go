package attestation

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	tomlv2 "github.com/pelletier/go-toml/v2"
)

// EigenXSNPMethodName is the registered identifier for this attestation method.
const EigenXSNPMethodName = "eigenx-snp"

// snpReportSize is the fixed AMD SEV-SNP attestation report size (0x4A0 bytes).
// Same constant lives in go-sev-guest/abi.ReportSize but inlined for clarity.
const snpReportSize = abi.ReportSize

// snpReportDataSize is the size of the REPORT_DATA field in the SEV-SNP report.
const snpReportDataSize = 64

// initDataPolicyKey is the TOML key under [data] that carries the rego policy
// document. CoCo's init-data convention places the rego under
// [data]."policy.rego" — see confidential-containers/guest-components.
const initDataPolicyKey = "policy.rego"

// imageRefRegex matches the first OCI image reference inside a rego policy
// (e.g. ghcr.io/example/app@sha256:abc...). Capture group 1 is the registry +
// repo (anything up to '@'); group 2 is the lowercase hex digest.
var imageRefRegex = regexp.MustCompile(`(\S+)@sha256:([a-f0-9]{64})`)

// SnpAttestationVerifier abstracts the go-sev-guest entrypoint used to validate
// the AMD certificate chain and the report signature. Refactored into an
// interface so tests can stub the network/cert-chain dependency without
// fabricating real AMD-signed reports.
type SnpAttestationVerifier interface {
	SnpAttestation(attestation *spb.Attestation, options *verify.Options) error
}

// snpAttestationVerifierFunc is a thin adapter that lets a bare function
// satisfy SnpAttestationVerifier. The default implementation forwards to
// verify.SnpAttestation, the highest-level go-sev-guest entrypoint that takes
// the full {Report, CertificateChain} proto and returns success/error after
// validating the AMD chain and the report's ECDSA-P384/SHA-384 signature.
type snpAttestationVerifierFunc func(attestation *spb.Attestation, options *verify.Options) error

func (f snpAttestationVerifierFunc) SnpAttestation(a *spb.Attestation, o *verify.Options) error {
	return f(a, o)
}

// EigenXSNPAttestationMethod implements AttestationMethod for raw AMD SEV-SNP
// evidence collected from the in-pod CoCo Attestation Agent (AA).
//
// Unlike the KBS-EAR method (which trusts a Trustee JWT for chain validation),
// this method verifies the AMD certificate chain and SEV-SNP report signature
// directly via go-sev-guest, then enforces:
//
//  1. Nonce binding: REPORT_DATA[0..32] == SHA-256(rsaPubKey || extraData).
//  2. Workload-identity binding: REPORT_DATA[32..64] == SHA-384(cc_init_data)[0..32].
//  3. cc_init_data integrity: parse [data]."policy.rego" and extract the OCI
//     image ref, surfacing claims.Registry (defense-in-depth) and
//     claims.ImageDigest = "sha256:<hex>" for the existing release-match check
//     in pkg/node/handlers.go.
type EigenXSNPAttestationMethod struct {
	verifier SnpAttestationVerifier
	options  *verify.Options
	logger   *slog.Logger
}

// NewEigenXSNPAttestationMethod constructs the eigenx-snp method using the
// default verify.SnpAttestation entrypoint. Pass options==nil to use
// verify.DefaultOptions(), which fetches missing AMD certs from KDS over the
// network. For air-gapped operators, supply a pre-populated Options with
// TrustedRoots set and DisableCertFetching=true.
func NewEigenXSNPAttestationMethod(options *verify.Options, logger *slog.Logger) *EigenXSNPAttestationMethod {
	return newEigenXSNPMethod(snpAttestationVerifierFunc(verify.SnpAttestation), options, logger)
}

// newEigenXSNPMethod is the internal constructor used by tests to inject a
// fake verifier. Production callers should use NewEigenXSNPAttestationMethod.
func newEigenXSNPMethod(v SnpAttestationVerifier, options *verify.Options, logger *slog.Logger) *EigenXSNPAttestationMethod {
	if options == nil {
		options = verify.DefaultOptions()
	}
	return &EigenXSNPAttestationMethod{
		verifier: v,
		options:  options,
		logger:   logger.With("component", "eigenx_snp_attestation"),
	}
}

// Name returns the identifier for this attestation method.
func (m *EigenXSNPAttestationMethod) Name() string {
	return EigenXSNPMethodName
}

// Verify validates raw AMD SEV-SNP evidence and the cc_init_data document.
//
// Wire contract (see brief):
//
//	request.Attestation = base64(JSON {"attestation_report": <base64 raw report>,
//	                                   "cert_chain":         [<PEM cert>, ...]})
//	request.CCInitData  = base64(TOML init-data document bytes)
//
// Steps:
//  1. base64-decode Attestation, parse the inner JSON.
//  2. Hand {Report, CertificateChain} to go-sev-guest for AMD-chain + signature
//     verification.
//  3. Pull REPORT_DATA from the parsed report, recompute both halves, and
//     compare via subtle.ConstantTimeCompare.
//  4. Parse cc_init_data as TOML, extract [data]."policy.rego", regex-match
//     the first OCI image ref to populate claims.Registry / claims.ImageDigest.
func (m *EigenXSNPAttestationMethod) Verify(request *AttestationRequest) (*types.AttestationClaims, error) {
	if request == nil {
		return nil, fmt.Errorf("attestation request is nil")
	}
	if len(request.Attestation) == 0 {
		return nil, fmt.Errorf("empty attestation evidence")
	}
	if len(request.RSAPubKeyTmp) == 0 {
		// Mirrors KBS-EAR / GCP behaviour — empty RSAPubKeyTmp would silently
		// disable nonce binding for any caller that forgot to populate it.
		return nil, fmt.Errorf("RSAPubKeyTmp is required for nonce binding")
	}
	if len(request.CCInitData) == 0 {
		return nil, fmt.Errorf("CCInitData is required for eigenx-snp attestation method")
	}

	// Step 1: base64-decode the outer wrapper, then JSON-decode the inner
	// {attestation_report, cert_chain}. Tolerate both standard and url-safe,
	// padded and unpadded base64 — the brief specifies "<base64 of raw SNP
	// evidence JSON>" without committing to a variant.
	evidenceJSON, err := decodeBase64Lenient(request.Attestation)
	if err != nil {
		return nil, fmt.Errorf("decode attestation base64: %w", err)
	}
	var ev rawSNPEvidence
	if err := json.Unmarshal(evidenceJSON, &ev); err != nil {
		return nil, fmt.Errorf("parse SNP evidence JSON: %w", err)
	}
	if len(ev.AttestationReport) < snpReportSize {
		return nil, fmt.Errorf("attestation_report too short: got %d bytes, want >=%d", len(ev.AttestationReport), snpReportSize)
	}

	// Step 2: parse report + cert chain into go-sev-guest's proto types and
	// run AMD chain + signature verification.
	reportProto, err := abi.ReportToProto(ev.AttestationReport[:snpReportSize])
	if err != nil {
		return nil, fmt.Errorf("parse SEV-SNP report: %w", err)
	}
	certChain, err := buildCertChain(ev.CertChain)
	if err != nil {
		return nil, fmt.Errorf("parse cert_chain: %w", err)
	}
	att := &spb.Attestation{
		Report:           reportProto,
		CertificateChain: certChain,
	}
	if err := m.verifier.SnpAttestation(att, m.options); err != nil {
		return nil, fmt.Errorf("AMD SEV-SNP attestation verification failed: %w", err)
	}

	// Step 3: enforce REPORT_DATA bindings. AMD specifies REPORT_DATA as a
	// 64-byte field; we split it into a SHA-256 nonce half and a SHA-384[:32]
	// init-data half exactly the way kmsCDHHelper composes it on the workload
	// side (see cmd/kmsCDHHelper/main.go::buildReportData).
	reportData := reportProto.GetReportData()
	if len(reportData) != snpReportDataSize {
		return nil, fmt.Errorf("unexpected REPORT_DATA size: got %d, want %d", len(reportData), snpReportDataSize)
	}

	// Lower 32: nonce binding mirrors KBS-EAR / GCP.
	nonceInput := make([]byte, 0, len(request.RSAPubKeyTmp)+len(request.ExtraData))
	nonceInput = append(nonceInput, request.RSAPubKeyTmp...)
	nonceInput = append(nonceInput, request.ExtraData...)
	nonceLower := sha256.Sum256(nonceInput)

	// Upper 32: SHA-384(cc_init_data)[:32]. SEV-SNP HOST_DATA is 32 bytes, so
	// the upper half of REPORT_DATA carries the truncated SHA-384 of the
	// init-data document — the workload-identity binding.
	initDigest := sha512.Sum384(request.CCInitData)
	var expected [snpReportDataSize]byte
	copy(expected[0:32], nonceLower[:])
	copy(expected[32:64], initDigest[:32])

	if subtle.ConstantTimeCompare(reportData, expected[:]) != 1 {
		return nil, fmt.Errorf("REPORT_DATA mismatch: rsa_pubkey/extra_data/cc_init_data not bound to attestation report")
	}

	// Step 4: parse cc_init_data TOML and extract registry+digest from the
	// embedded rego. The rego is the workload-identity policy that CoCo's
	// agent enforces on the running container; matching the OCI ref here is
	// what lets the KMS link the AMD-attested HOST_DATA to a concrete image.
	registry, digestHex, err := parseInitDataPolicy(request.CCInitData)
	if err != nil {
		return nil, fmt.Errorf("parse cc_init_data: %w", err)
	}

	claims := &types.AttestationClaims{
		AppID:       request.AppID,
		ImageDigest: "sha256:" + digestHex,
		Registry:    registry,
		Nonce:       hex.EncodeToString(nonceLower[:]),
		ExtraData:   request.ExtraData,
		// SEV-SNP reports do not carry iat/exp/jti — the freshness guarantee
		// comes from the random ephemeral RSA key bound into REPORT_DATA, not
		// from a token timestamp. Leaving JTI empty disables the replay-cache
		// check in handlers.go (which is keyed on JTI presence).
	}

	m.logger.Debug("eigenx-snp claims extracted",
		"app_id", claims.AppID,
		"image_digest", claims.ImageDigest,
		"registry", claims.Registry,
	)
	return claims, nil
}

// rawSNPEvidence is the AA-emitted evidence wrapper. attestation_report is
// the raw 0x4A0 SEV-SNP report bytes (Go decodes JSON base64 strings into
// []byte automatically); cert_chain is an array of PEM-encoded AMD certs
// (ARK, ASK, VCEK) — order is not assumed, identification is by Subject CN.
type rawSNPEvidence struct {
	AttestationReport []byte   `json:"attestation_report"`
	CertChain         []string `json:"cert_chain"`
}

// buildCertChain identifies ARK / ASK / VCEK / VLEK certs by subject
// CommonName and packages them into spb.CertificateChain in the DER form
// go-sev-guest expects. Per AMD KDS, ARK CN = "ARK-<product>", ASK CN =
// "SEV-<product>" or "SEV-VLEK-<product>", VCEK CN = "SEV-VCEK", VLEK CN =
// "SEV-VLEK". Anything else is dropped; missing certs are left empty and
// fillInAttestation will fetch them from KDS unless DisableCertFetching is
// set.
func buildCertChain(pemCerts []string) (*spb.CertificateChain, error) {
	chain := &spb.CertificateChain{}
	for i, raw := range pemCerts {
		der, err := decodeCert(raw)
		if err != nil {
			return nil, fmt.Errorf("cert_chain[%d]: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("cert_chain[%d]: parse x509: %w", i, err)
		}
		cn := cert.Subject.CommonName
		switch {
		case strings.HasPrefix(cn, "ARK-"):
			chain.ArkCert = der
		case cn == "SEV-VCEK":
			chain.VcekCert = der
		case cn == "SEV-VLEK":
			chain.VlekCert = der
		case strings.HasPrefix(cn, "SEV-VLEK-"):
			// Intermediate ASVK (signs VLEKs).
			// go-sev-guest looks at chain.AskCert for both VCEK and VLEK paths
			// when ASVK isn't present; for VLEK paths the same field is
			// repurposed via the ASVK lookup. Set ArkCert/AskCert per CN
			// prefix and let fillInAttestation route by SignerInfo.
			chain.AskCert = der
		case strings.HasPrefix(cn, "SEV-"):
			// Intermediate ASK (signs VCEKs): SEV-Milan, SEV-Genoa, SEV-Turin, ...
			chain.AskCert = der
		}
	}
	return chain, nil
}

// decodeCert tolerates either PEM-wrapped or bare base64-encoded DER. AA's
// evidence shape is not standardised across versions, so accept both rather
// than fail closed on one variant.
func decodeCert(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "-----BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, fmt.Errorf("PEM block not found")
		}
		return block.Bytes, nil
	}
	if der, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return der, nil
	}
	if der, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
		return der, nil
	}
	if der, err := base64.URLEncoding.DecodeString(raw); err == nil {
		return der, nil
	}
	if der, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
		return der, nil
	}
	return nil, fmt.Errorf("cert is neither PEM nor any recognised base64 variant")
}

// decodeBase64Lenient decodes data tolerating standard/url-safe and
// padded/unpadded variants. As a last resort it returns the input unchanged
// (the brief locks "<base64 of raw SNP evidence JSON>" but legacy/test
// callers occasionally hand us the JSON directly).
func decodeBase64Lenient(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		if b, err := dec(s); err == nil {
			// A double-base64 corner case: if the decoded bytes don't look
			// like JSON ('{' or '[') but the input did, prefer the input.
			if len(b) > 0 && (b[0] == '{' || b[0] == '[') {
				return b, nil
			}
		}
	}
	// Fall back to the input bytes if they already parse as JSON.
	if len(s) > 0 && (s[0] == '{' || s[0] == '[') {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("attestation evidence is neither base64 nor raw JSON")
}

// initDataDoc mirrors the CoCo init-data TOML schema we care about. CoCo's
// real schema has more fields (algorithm, version, ...) but only [data] is
// load-bearing here. Use map[string]any so the policy.rego key with its dot
// (which TOML treats as a path otherwise) round-trips cleanly.
type initDataDoc struct {
	Data map[string]any `toml:"data"`
}

// parseInitDataPolicy extracts the OCI registry+digest from cc_init_data.
//
// Returns (registry, digestHex) where registry is everything before '@' in the
// matched OCI ref (e.g. "ghcr.io/example/app") and digestHex is the lowercase
// 64-char hex string after "@sha256:". Returns an error if no ref is found —
// this is fail-closed: a workload that doesn't pin its image in the rego must
// not pass the workload-identity check.
func parseInitDataPolicy(ccInitData []byte) (string, string, error) {
	var doc initDataDoc
	if err := tomlv2.Unmarshal(ccInitData, &doc); err != nil {
		return "", "", fmt.Errorf("decode TOML: %w", err)
	}
	rawRego, ok := doc.Data[initDataPolicyKey]
	if !ok {
		return "", "", fmt.Errorf("[data].%q not found in cc_init_data", initDataPolicyKey)
	}
	regoStr, ok := rawRego.(string)
	if !ok {
		return "", "", fmt.Errorf("[data].%q is %T, want string", initDataPolicyKey, rawRego)
	}
	match := imageRefRegex.FindStringSubmatch(regoStr)
	if match == nil {
		return "", "", fmt.Errorf("no `<registry>@sha256:<hex>` reference found in policy.rego")
	}
	// match[1] = registry+repo (e.g. ghcr.io/example/app), match[2] = digest hex.
	return strings.TrimFunc(match[1], func(r rune) bool {
		// Strip any quoting characters the rego string used around the ref —
		// rego literals are double-quoted, but the policy.rego value we get
		// here is the dequoted TOML string, so this is mostly defensive
		// against backtick/single-quote rego variants.
		return r == '"' || r == '\'' || r == '`'
	}), match[2], nil
}
