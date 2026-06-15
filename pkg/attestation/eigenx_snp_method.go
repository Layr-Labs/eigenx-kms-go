package attestation

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
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
//
// Note for operators authoring init-data documents: TOML treats `.` as a
// path separator in bare keys, so the key MUST be double-quoted in the
// document (`"policy.rego" = """..."""`). We avoid the issue on the parse
// side by using `map[string]any` for [data], which preserves the literal
// string "policy.rego" as-is regardless of how the document quoted it.
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
// default verify.SnpAttestation entrypoint.
//
// When options==nil, we default to verify.DefaultOptions() with
// DisableCertFetching=true. This is deliberate: callers MUST ship a complete
// AMD certificate chain (ARK + ASK + VCEK or VLEK) inside the evidence JSON.
// Letting go-sev-guest fetch missing certs from AMD KDS would expose this
// handler to a goroutine-flood DoS — every /secrets request with an empty
// cert_chain would block on the AMD network round-trip with no per-request
// timeout. Operators that genuinely need KDS lookup (e.g. testing) can pass
// an Options with DisableCertFetching=false explicitly.
func NewEigenXSNPAttestationMethod(options *verify.Options, logger *slog.Logger) *EigenXSNPAttestationMethod {
	return newEigenXSNPMethod(snpAttestationVerifierFunc(verify.SnpAttestation), options, logger)
}

// newEigenXSNPMethod is the internal constructor used by tests to inject a
// fake verifier. Production callers should use NewEigenXSNPAttestationMethod.
func newEigenXSNPMethod(v SnpAttestationVerifier, options *verify.Options, logger *slog.Logger) *EigenXSNPAttestationMethod {
	if options == nil {
		options = verify.DefaultOptions()
		options.DisableCertFetching = true
	}
	// Always pre-load the embedded VLEK ASVK chain for every supported
	// AMD product line when the caller didn't supply trusted roots.
	// go-sev-guest's embedded DefaultRootCerts only carry the VCEK ASK
	// chain (init() in trust.go), so VLEK-signed reports fail closed
	// with "missing intermediate certificate authority". CSPs (AWS,
	// GCP, Azure) sign with VLEK on shared instances. Done outside the
	// `options == nil` branch so callers passing a custom Options
	// (e.g. fakeKMS with --snp-allow-amd-kds-fetch) still get the VLEK
	// roots without having to know to populate TrustedRoots themselves.
	if options.TrustedRoots == nil {
		options.TrustedRoots = embeddedVLEKTrustedRoots(logger)
	}
	return &EigenXSNPAttestationMethod{
		verifier: v,
		options:  options,
		logger:   logger.With("component", "eigenx_snp_attestation"),
	}
}

// embeddedVLEKTrustedRoots loads go-sev-guest's `//go:embed`'d ASVK+ARK
// bundles for every AMD product line we expect to see on cloud SEV-SNP
// hosts. The map is keyed by productLine ("Milan", "Genoa", "Turin")
// matching kds.ProductLineFromFms. decodeCerts() picks the entry by
// product line at verify time, so an unknown line falls through to
// "no roots" → fall back to GetDefaultRootCerts (which is VCEK-only and
// will still fail closed for VLEK on that line — but that's a host we
// don't recognise yet, and adding a new line is one constant away).
func embeddedVLEKTrustedRoots(logger *slog.Logger) map[string][]*trust.AMDRootCerts {
	roots := map[string][]*trust.AMDRootCerts{}
	for _, line := range []struct {
		product string
		bundle  []byte
	}{
		{"Milan", trust.AskArkMilanVlekBytes},
		{"Genoa", trust.AskArkGenoaVlekBytes},
		{"Turin", trust.AskArkTurinVlekBytes},
	} {
		if len(line.bundle) == 0 {
			continue
		}
		root := trust.AMDRootCertsProduct(line.product)
		if err := root.FromKDSCertBytes(line.bundle); err != nil {
			// trust.go's init() panics on equivalent failures for VCEK; we
			// log+skip here so a single broken bundle (release regression)
			// doesn't take the whole KMS down.
			logger.Warn("failed to load embedded VLEK trusted root",
				"product_line", line.product, "error", err)
			continue
		}
		// Diagnostic: confirm Asvk is what got parsed (Decode routes by
		// CN prefix). If the embedded bundle is regenerated as a VCEK
		// chain by mistake the cert lands in r.ProductCerts.Ask and
		// VLEK verification still fails closed — surface that here.
		var asvkCN, askCN, arkCN string
		if root.ProductCerts != nil {
			if root.ProductCerts.Asvk != nil {
				asvkCN = root.ProductCerts.Asvk.Subject.CommonName
			}
			if root.ProductCerts.Ask != nil {
				askCN = root.ProductCerts.Ask.Subject.CommonName
			}
			if root.ProductCerts.Ark != nil {
				arkCN = root.ProductCerts.Ark.Subject.CommonName
			}
		}
		logger.Info("loaded VLEK trusted root",
			"product_line", line.product,
			"asvk_cn", asvkCN, "ask_cn", askCN, "ark_cn", arkCN)
		roots[line.product] = append(roots[line.product], root)
	}
	return roots
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

	// Diagnostic: surface the launch-set / launch-measured report fields. This
	// is how we confirm empirically that HOST_DATA is all-zero on managed-CSP
	// (AWS) SEV-SNP — the launch chain that would set HOST_DATA=digest(initdata)
	// lives in the QEMU/SNP_LAUNCH_FINISH path, which AWS does not use, so the
	// field stays zero. That is why cc_init_data is bound via guest-chosen
	// REPORT_DATA below rather than HOST_DATA. MEASUREMENT (launch-measured by
	// AMD-SP, guest-immutable) IS populated and is the field that must be
	// allowlisted to anchor the guest to authorized code.
	hostData := reportProto.GetHostData()
	hostDataZero := true
	for _, b := range hostData {
		if b != 0 {
			hostDataZero = false
			break
		}
	}
	m.logger.Info("eigenx-snp report fields",
		"app_id", request.AppID,
		"host_data_hex", hex.EncodeToString(hostData),
		"host_data_all_zero", hostDataZero,
		"measurement_hex", hex.EncodeToString(reportProto.GetMeasurement()),
		"policy", reportProto.GetPolicy(),
		"vmpl", reportProto.GetVmpl(),
	)

	certChain, droppedCNs, err := buildCertChain(ev.CertChain)
	if err != nil {
		return nil, fmt.Errorf("parse cert_chain: %w", err)
	}
	if len(droppedCNs) > 0 {
		m.logger.Warn("dropped cert_chain entries with unrecognised AMD CN",
			"dropped_cns", droppedCNs,
			"app_id", request.AppID,
		)
	}
	att := &spb.Attestation{
		Report:           reportProto,
		CertificateChain: certChain,
	}
	if err := m.verifier.SnpAttestation(att, m.options); err != nil {
		return nil, fmt.Errorf("AMD SEV-SNP attestation verification failed: %w", err)
	}

	// Step 3: enforce REPORT_DATA bindings. AMD's REPORT_DATA is a 64-byte
	// slot; we encode it as 64 ASCII hex characters split in half to keep the
	// content UTF-8 safe (see cmd/kmsCDHHelper/main.go::buildReportData for
	// the upstream-pin transport constraint that motivates this).
	//
	//   bytes  0..32 = hex(SHA-256(rsaPubKeyTmp || extraData)[:16])
	//   bytes 32..64 = hex(SHA-384(cc_init_data)[:16])
	reportData := reportProto.GetReportData()
	if len(reportData) != snpReportDataSize {
		return nil, fmt.Errorf("unexpected REPORT_DATA size: got %d, want %d", len(reportData), snpReportDataSize)
	}

	// Lower half: nonce binding (mirrors KBS-EAR / GCP). Incremental hash
	// matches the helper to keep the two implementations aligned and to
	// sidestep the CodeQL warning about len(a)+len(b) on pre-allocation.
	nonceHash := sha256.New()
	nonceHash.Write(request.RSAPubKeyTmp)
	nonceHash.Write(request.ExtraData)
	nonceFull := nonceHash.Sum(nil)
	nonceLowerHex := hex.EncodeToString(nonceFull[:16])

	// Upper half: SHA-384(cc_init_data)[:16] hex-encoded. The full 32-byte
	// SHA-384 still binds cc_init_data to SEV-SNP's HOST_DATA upper field
	// (see go-sev-guest invariants); the hex restriction here is purely
	// about REPORT_DATA wire transport via api-server-rest.
	initDigest := sha512.Sum384(request.CCInitData)
	upperHex := hex.EncodeToString(initDigest[:16])

	var expected [snpReportDataSize]byte
	copy(expected[0:32], nonceLowerHex)
	copy(expected[32:64], upperHex)

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
		Nonce:       nonceLowerHex,
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
// maxCertChainLen caps how many PEM/base64 entries we'll parse out of a single
// AA evidence document. Real AMD chains carry at most 4 certs (ARK + ASK + VCEK
// or VLEK + optional ASVK); anything beyond that is either client error or an
// attempt to exhaust CPU in x509.ParseCertificate before the AMD verifier runs.
const maxCertChainLen = 10

// buildCertChain returns the parsed chain plus the list of cert CNs that
// were dropped because they didn't match any AMD pattern. Caller logs the
// dropped CNs so a future AMD product whose CN convention we don't yet
// recognise produces a diagnostic instead of a silent verification failure.
func buildCertChain(pemCerts []string) (*spb.CertificateChain, []string, error) {
	if len(pemCerts) > maxCertChainLen {
		return nil, nil, fmt.Errorf("cert_chain too long: %d (max %d)", len(pemCerts), maxCertChainLen)
	}
	chain := &spb.CertificateChain{}
	var droppedCNs []string
	for i, raw := range pemCerts {
		der, err := decodeCert(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("cert_chain[%d]: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("cert_chain[%d]: parse x509: %w", i, err)
		}
		cn := cert.Subject.CommonName
		switch {
		case strings.HasPrefix(cn, "ARK-"):
			// Don't overwrite an ARK cert already placed by an earlier
			// chain entry. A crafted chain with two ARK-<product> certs
			// could otherwise swap out the trusted root after the first
			// is set; first-wins keeps the originally-presented root.
			if chain.ArkCert == nil {
				chain.ArkCert = der
			}
		case cn == "SEV-VCEK":
			if chain.VcekCert == nil {
				chain.VcekCert = der
			}
		case cn == "SEV-VLEK":
			if chain.VlekCert == nil {
				chain.VlekCert = der
			}
		case strings.HasPrefix(cn, "SEV-VLEK-"):
			// Intermediate ASVK (signs VLEKs).
			// go-sev-guest looks at chain.AskCert for both VCEK and VLEK paths
			// when ASVK isn't present; for VLEK paths the same field is
			// repurposed via the ASVK lookup. Set ArkCert/AskCert per CN
			// prefix and let fillInAttestation route by SignerInfo.
			// First-wins (same reason as ARK above).
			if chain.AskCert == nil {
				chain.AskCert = der
			}
		case strings.HasPrefix(cn, "SEV-"):
			// Intermediate ASK (signs VCEKs): SEV-Milan, SEV-Genoa, SEV-Turin, ...
			// Don't overwrite an ASVK already placed in AskCert by the
			// SEV-VLEK- branch above — both prefixes target the same field
			// in spb.CertificateChain, so a mixed chain would silently lose
			// the first cert otherwise.
			if chain.AskCert == nil {
				chain.AskCert = der
			} else {
				// A second ASK/ASVK cert for the same field — first-wins, but
				// surface it (consistent with droppedCNs) so a malformed or
				// mixed CA set doesn't silently lose a cert.
				droppedCNs = append(droppedCNs, cn)
			}
		default:
			// Unknown CN — don't fail (forward-compatibility with future AMD
			// product CNs) but surface it so the operator can investigate
			// rather than scratch their head over an opaque chain failure.
			droppedCNs = append(droppedCNs, cn)
		}
	}
	return chain, droppedCNs, nil
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
// padded/unpadded variants.
//
// Disambiguation: the brief locks the wire format to base64-of-JSON, but a
// few legitimate callers (kmsClient round-trips, tests) hand us the JSON
// directly because Go's encoding/json marshals []byte as standard base64
// already. We pick a path up front based on the first byte rather than
// trying decoders in turn — silently dropping a successful base64 decode
// because it doesn't start with '{' would be a confusion attack surface.
func decodeBase64Lenient(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	if len(s) == 0 {
		return nil, fmt.Errorf("attestation evidence is empty")
	}
	// Raw-JSON path: input starts with '{' or '['. Return as-is; a JSON
	// document is never a valid base64 string in practice (the '{'/'}' and
	// '['/']' chars aren't in any base64 alphabet).
	if s[0] == '{' || s[0] == '[' {
		return []byte(s), nil
	}
	// Otherwise try base64 variants in priority order. First successful
	// decode wins — we don't second-guess content. If a caller hands us
	// base64 of non-JSON bytes, the JSON parser downstream will fail with
	// a clear error; we don't try to mask that here.
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		if b, err := dec(s); err == nil {
			return b, nil
		}
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
	tomlBytes, err := decodeInitDataWire(ccInitData)
	if err != nil {
		return "", "", fmt.Errorf("decode wire format: %w", err)
	}
	var doc initDataDoc
	if err := tomlv2.Unmarshal(tomlBytes, &doc); err != nil {
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
	// Strip rego comment lines before matching the image ref. Rego uses
	// `#` for line comments. Without this filter, a stale OCI ref left
	// in a `# OLD: ...` comment matches before the active rule's ref —
	// silently binding the workload's identity to the deprecated image.
	// Strip whole-line comments; an inline `# ...` after a rule still
	// has the active ref ahead of it, so the regex picks the right one.
	stripped := stripRegoComments(regoStr)
	match := imageRefRegex.FindStringSubmatch(stripped)
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

// stripRegoComments returns rego with all whole-line `#` comments
// removed. This is intentionally narrow — only lines whose first
// non-whitespace character is `#`. We do NOT try to strip inline
// trailing `# ...` comments because the active OCI ref always appears
// before any trailing comment on the same line, so the regex picks the
// right one anyway, and writing a regex-safe inline-comment stripper
// requires understanding rego string-literal escaping (which we
// don't).
func stripRegoComments(rego string) string {
	lines := strings.Split(rego, "\n")
	kept := lines[:0]
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimLeft(l, " \t"), "#") {
			continue
		}
		kept = append(kept, l)
	}
	return strings.Join(kept, "\n")
}

// decodeInitDataWire accepts cc_init_data in either of two shapes — raw TOML
// (the legacy wire and what unit tests use) or base64(gzip(toml)) (production:
// what kata-shim writes from the cc_init_data pod annotation, what
// CAA's process-user-data.service reads inside the podVM, and what the
// helper reads from /run/peerpod/initdata and forwards verbatim to us).
//
// Sniff by magic prefix: a base64-encoded gzip blob starts with "H4sI" (gzip's
// 0x1f 0x8b base64-encoded). Raw TOML never does. SHA-384(ccInitData) on the
// REPORT_DATA upper half is computed over the bytes-as-received in both
// cases, so the integrity binding is independent of which shape we get —
// this helper is purely about getting at the parseable TOML inside.
func decodeInitDataWire(in []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(in)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty cc_init_data")
	}
	if !bytes.HasPrefix(trimmed, []byte("H4sI")) {
		return trimmed, nil
	}
	// Tolerate base64 with or without `=` padding. kata-shim emits
	// unpadded base64 in some cloud-provider configurations (GKE, AKS);
	// the AWS-shaped CAA path uses padded. base64.StdEncoding rejects
	// the unpadded form (`unexpected EOF` mid-stream once gzip starts
	// reading), and base64.RawStdEncoding rejects the padded form. Strip
	// the trailing `=` and always use RawStdEncoding — both shapes
	// round-trip.
	stripped := bytes.TrimRight(trimmed, "=")
	b64Reader := base64.NewDecoder(base64.RawStdEncoding, bytes.NewReader(stripped))
	gzReader, err := gzip.NewReader(b64Reader)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer func() { _ = gzReader.Close() }()
	// Cap the decompressed size to bound memory regardless of how large
	// a gzip bomb is wrapped in the H4sI prefix. The handler caps
	// cc_init_data at 1 MiB compressed; valid CoCo init-data documents
	// are kilobytes, so 8 MiB decompressed is generous headroom while
	// still preventing a multi-GB bomb. Returns an explicit error
	// instead of silently truncating.
	const maxDecompressedInitData = 8 << 20 // 8 MiB
	limited := io.LimitReader(gzReader, maxDecompressedInitData+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read decompressed cc_init_data: %w", err)
	}
	if len(out) > maxDecompressedInitData {
		return nil, fmt.Errorf("decompressed cc_init_data exceeds %d bytes", maxDecompressedInitData)
	}
	return out, nil
}
