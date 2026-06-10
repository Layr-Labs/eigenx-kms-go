package attestation

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSNPVerifier short-circuits go-sev-guest's AMD chain validation so the
// tests can cover the eigenx-snp method's logic (REPORT_DATA binding, TOML
// parsing, regex extraction) without crafting a real AMD-signed report. The
// integration with verify.SnpAttestation is exercised by go-sev-guest's own
// test suite — duplicating it here would just couple us to AMD's KDS.
type fakeSNPVerifier struct {
	err     error // non-nil to simulate AMD chain failure
	gotAtt  *spb.Attestation
	gotOpts *verify.Options
}

func (f *fakeSNPVerifier) SnpAttestation(att *spb.Attestation, opts *verify.Options) error {
	f.gotAtt = att
	f.gotOpts = opts
	return f.err
}

// buildSNPReport returns a 0x4A0-byte SEV-SNP report with the requested
// REPORT_DATA. Other report fields are left zero — go-sev-guest will reject
// signatures, but we replace the verifier with fakeSNPVerifier so it never
// gets that far. This mirrors the helper test.CreateRawReport but is local
// so we don't pull go-sev-guest's testing package as a runtime dep.
func buildSNPReport(reportData [64]byte) []byte {
	r := make([]byte, abi.ReportSize)
	binary.LittleEndian.PutUint32(r[0x00:0x04], 2)                                                // version
	binary.LittleEndian.PutUint64(r[0x08:0x10], abi.SnpPolicyToBytes(abi.SnpPolicy{Debug: true})) // policy
	binary.LittleEndian.PutUint32(r[0x34:0x38], 1)                                                // signature_algo (ECDSA P-384 SHA-384)
	copy(r[0x50:0x90], reportData[:])                                                             // report_data
	return r
}

// buildEvidenceJSON wraps a raw report as the AA-shaped evidence JSON. The
// outer base64 wrapper required by the wire contract is added at the call
// site — keeping JSON construction separate makes the negative tests
// (malformed JSON, short report, etc.) easier to write.
func buildEvidenceJSON(t *testing.T, report []byte, certChainPEM []string) []byte {
	t.Helper()
	if certChainPEM == nil {
		certChainPEM = []string{}
	}
	b, err := json.Marshal(rawSNPEvidence{
		AttestationReport: report,
		CertChain:         certChainPEM,
	})
	require.NoError(t, err)
	return b
}

// b64 returns the lock-step "base64 of <bytes>" the wire contract expects
// the caller to produce. Using StdEncoding everywhere keeps tests easy to
// read; the production decoder accepts any of the four base64 variants.
func b64(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}

// expectedReportData composes the 64-byte REPORT_DATA the workload-side
// helper writes (kmsCDHHelper.buildReportData). Must be kept in sync — the
// whole point of this test is to assert that the server recomputes the
// exact same value from the AttestationRequest fields.
//
// Format: 64 ASCII hex characters,
//
//	bytes  0..32 = hex(SHA-256(rsaPubKey || extraData)[:16])
//	bytes 32..64 = hex(SHA-384(ccInitData)[:16])
func expectedReportData(rsaPubKey, extraData, ccInitData []byte) [64]byte {
	h := sha256.New()
	h.Write(rsaPubKey)
	h.Write(extraData)
	lower := h.Sum(nil)
	upperFull := sha512.Sum384(ccInitData)

	lowerHex := hex.EncodeToString(lower[:16])
	upperHex := hex.EncodeToString(upperFull[:16])

	var out [64]byte
	copy(out[:32], lowerHex)
	copy(out[32:], upperHex)
	return out
}

// validInitDataTOML returns a CoCo init-data document that pins the given OCI
// image. The rego embeds the standard `image_ref @ sha256:<hex>` shape AA
// uses today; the parseInitDataPolicy regex matches the first occurrence.
func validInitDataTOML(t *testing.T, registry, digestHex string) []byte {
	t.Helper()
	doc := fmt.Sprintf(`algorithm = "sha384"
version = "0.1.0"

[data]
"policy.rego" = """
package agent_policy

default allow = false

allow {
  input.image == "%s@sha256:%s"
}
"""
`, registry, digestHex)
	return []byte(doc)
}

func newSNPMethodWithFake(t *testing.T, fake *fakeSNPVerifier) *EigenXSNPAttestationMethod {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	// Pass nil options — they're forwarded to fakeSNPVerifier and inspected,
	// not used. NewEigenXSNPAttestationMethod's default fills them in.
	return newEigenXSNPMethod(fake, nil, logger)
}

func TestEigenXSNPMethodName(t *testing.T) {
	m := newSNPMethodWithFake(t, &fakeSNPVerifier{})
	assert.Equal(t, "eigenx-snp", m.Name())
}

func TestEigenXSNPVerify_ValidEvidence(t *testing.T) {
	rsaKey := []byte("test-rsa-public-key-pem")
	extraData := []byte("binding-payload")
	digestHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	registry := "ghcr.io/example/app"
	ccInitData := validInitDataTOML(t, registry, digestHex)

	rd := expectedReportData(rsaKey, extraData, ccInitData)
	report := buildSNPReport(rd)
	evidence := buildEvidenceJSON(t, report, nil)

	fake := &fakeSNPVerifier{}
	m := newSNPMethodWithFake(t, fake)

	claims, err := m.Verify(&AttestationRequest{
		Method:       "eigenx-snp",
		AppID:        "my-app",
		Attestation:  b64(evidence),
		RSAPubKeyTmp: rsaKey,
		ExtraData:    extraData,
		CCInitData:   ccInitData,
	})
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, "my-app", claims.AppID, "AppID must come from the request, not the SNP report")
	assert.Equal(t, "sha256:"+digestHex, claims.ImageDigest)
	assert.Equal(t, registry, claims.Registry)
	// Lower 32 of REPORT_DATA = hex(SHA-256(rsa || extra)[:16]). claims.Nonce
	// surfaces that hex string directly (no double encoding) so logs on both
	// sides correlate.
	expectedNonce := string(rd[:32])
	assert.Equal(t, expectedNonce, claims.Nonce)
	assert.Equal(t, extraData, claims.ExtraData)
	// SNP attestations carry no JTI; replay protection comes from the
	// ephemeral RSA pubkey bound into REPORT_DATA. handlers.go skips the JTI
	// cache lookup when this is empty.
	assert.Empty(t, claims.JTI)

	// Sanity-check the evidence reached the verifier with both halves.
	require.NotNil(t, fake.gotAtt)
	require.NotNil(t, fake.gotAtt.Report)
	require.NotNil(t, fake.gotAtt.CertificateChain)
}

func TestEigenXSNPVerify_NilRequest(t *testing.T) {
	m := newSNPMethodWithFake(t, &fakeSNPVerifier{})
	_, err := m.Verify(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestEigenXSNPVerify_EmptyEvidence(t *testing.T) {
	m := newSNPMethodWithFake(t, &fakeSNPVerifier{})
	_, err := m.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  nil,
		RSAPubKeyTmp: []byte("rsa"),
		CCInitData:   []byte("init"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty attestation")
}

func TestEigenXSNPVerify_MissingRSAPubKey(t *testing.T) {
	m := newSNPMethodWithFake(t, &fakeSNPVerifier{})
	_, err := m.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte("anything"),
		RSAPubKeyTmp: nil,
		CCInitData:   []byte("init"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RSAPubKeyTmp")
}

func TestEigenXSNPVerify_MissingCCInitData(t *testing.T) {
	m := newSNPMethodWithFake(t, &fakeSNPVerifier{})
	_, err := m.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  []byte("anything"),
		RSAPubKeyTmp: []byte("rsa"),
		CCInitData:   nil,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CCInitData")
}

func TestEigenXSNPVerify_MalformedEvidence(t *testing.T) {
	m := newSNPMethodWithFake(t, &fakeSNPVerifier{})
	_, err := m.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  b64([]byte("not-json")),
		RSAPubKeyTmp: []byte("rsa"),
		CCInitData:   []byte("init"),
	})
	require.Error(t, err)
}

func TestEigenXSNPVerify_ShortReport(t *testing.T) {
	m := newSNPMethodWithFake(t, &fakeSNPVerifier{})
	short := buildEvidenceJSON(t, []byte{0x01, 0x02, 0x03}, nil)
	_, err := m.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  b64(short),
		RSAPubKeyTmp: []byte("rsa"),
		CCInitData:   []byte("init"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attestation_report too short")
}

func TestEigenXSNPVerify_AMDChainFailure(t *testing.T) {
	rsaKey := []byte("rsa")
	digestHex := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	ccInitData := validInitDataTOML(t, "ghcr.io/x/y", digestHex)
	rd := expectedReportData(rsaKey, nil, ccInitData)
	report := buildSNPReport(rd)
	evidence := buildEvidenceJSON(t, report, nil)

	fake := &fakeSNPVerifier{err: fmt.Errorf("synthetic VCEK chain failure")}
	m := newSNPMethodWithFake(t, fake)

	_, err := m.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  b64(evidence),
		RSAPubKeyTmp: rsaKey,
		CCInitData:   ccInitData,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AMD SEV-SNP attestation verification failed")
	assert.Contains(t, err.Error(), "synthetic VCEK chain failure")
}

func TestEigenXSNPVerify_NonceMismatch(t *testing.T) {
	rsaKey := []byte("real-rsa-key")
	digestHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	ccInitData := validInitDataTOML(t, "ghcr.io/x/y", digestHex)

	// Build REPORT_DATA bound to a *different* RSA key — MITM substitution.
	rd := expectedReportData([]byte("attacker-rsa-key"), nil, ccInitData)
	report := buildSNPReport(rd)
	evidence := buildEvidenceJSON(t, report, nil)

	fake := &fakeSNPVerifier{}
	m := newSNPMethodWithFake(t, fake)

	_, err := m.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  b64(evidence),
		RSAPubKeyTmp: rsaKey,
		CCInitData:   ccInitData,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "REPORT_DATA mismatch")
}

func TestEigenXSNPVerify_CCInitDataMismatch(t *testing.T) {
	rsaKey := []byte("rsa")
	digestHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	attestedInit := validInitDataTOML(t, "ghcr.io/x/y", digestHex)
	requestInit := validInitDataTOML(t, "ghcr.io/x/y", digestHex)
	requestInit = append(requestInit, []byte("\n# tampered")...) // change the bytes after attest

	rd := expectedReportData(rsaKey, nil, attestedInit)
	report := buildSNPReport(rd)
	evidence := buildEvidenceJSON(t, report, nil)

	m := newSNPMethodWithFake(t, &fakeSNPVerifier{})
	_, err := m.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  b64(evidence),
		RSAPubKeyTmp: rsaKey,
		CCInitData:   requestInit,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "REPORT_DATA mismatch")
}

func TestEigenXSNPVerify_MissingPolicyRego(t *testing.T) {
	rsaKey := []byte("rsa")
	// init-data with a [data] section but no policy.rego key — should fail
	// closed rather than return empty registry/digest.
	noRego := []byte(`algorithm = "sha384"
version = "0.1.0"

[data]
something_else = "value"
`)

	rd := expectedReportData(rsaKey, nil, noRego)
	report := buildSNPReport(rd)
	evidence := buildEvidenceJSON(t, report, nil)

	m := newSNPMethodWithFake(t, &fakeSNPVerifier{})
	_, err := m.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  b64(evidence),
		RSAPubKeyTmp: rsaKey,
		CCInitData:   noRego,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy.rego")
}

func TestEigenXSNPVerify_NoImageRefInPolicy(t *testing.T) {
	rsaKey := []byte("rsa")
	regoNoRef := []byte(`algorithm = "sha384"
version = "0.1.0"

[data]
"policy.rego" = """
package agent_policy
default allow = false
"""
`)

	rd := expectedReportData(rsaKey, nil, regoNoRef)
	report := buildSNPReport(rd)
	evidence := buildEvidenceJSON(t, report, nil)

	m := newSNPMethodWithFake(t, &fakeSNPVerifier{})
	_, err := m.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  b64(evidence),
		RSAPubKeyTmp: rsaKey,
		CCInitData:   regoNoRef,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no `<registry>@sha256:<hex>`")
}

func TestEigenXSNPVerify_EvidenceAcceptsRawJSON(t *testing.T) {
	// Forward-compat: tolerate callers that send raw JSON instead of base64.
	// The wire contract specifies base64 but the decoder is lenient.
	rsaKey := []byte("rsa")
	digestHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	ccInitData := validInitDataTOML(t, "ghcr.io/x/y", digestHex)
	rd := expectedReportData(rsaKey, nil, ccInitData)
	report := buildSNPReport(rd)
	evidence := buildEvidenceJSON(t, report, nil)

	m := newSNPMethodWithFake(t, &fakeSNPVerifier{})
	claims, err := m.Verify(&AttestationRequest{
		AppID:        "app",
		Attestation:  evidence, // raw JSON, not base64
		RSAPubKeyTmp: rsaKey,
		CCInitData:   ccInitData,
	})
	require.NoError(t, err)
	assert.Equal(t, "sha256:"+digestHex, claims.ImageDigest)
}

func TestParseInitDataPolicy_FirstMatchWins(t *testing.T) {
	// When policy.rego pins multiple images (rare but legal), the first
	// match defines (Registry, ImageDigest). This documents that contract
	// so a future changeset doesn't accidentally start picking last-wins.
	digest1 := "1111111111111111111111111111111111111111111111111111111111111111"
	digest2 := "2222222222222222222222222222222222222222222222222222222222222222"
	doc := []byte(fmt.Sprintf(`[data]
"policy.rego" = """
input.image == "ghcr.io/first/app@sha256:%s"
input.image == "ghcr.io/second/app@sha256:%s"
"""
`, digest1, digest2))

	registry, digest, err := parseInitDataPolicy(doc)
	require.NoError(t, err)
	assert.Equal(t, "ghcr.io/first/app", registry)
	assert.Equal(t, digest1, digest)
}

// gzipBase64 is the production wire format for /run/peerpod/initdata —
// what kata-shim writes from the cc_init_data pod annotation, what
// CAA's process-user-data.service reads, and what the helper forwards
// verbatim to the KMS. Tests below exercise the full Verify path
// through this shape, which is otherwise only exercised in cluster
// smoke tests.
func gzipBase64(t *testing.T, raw []byte, encoding *base64.Encoding) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return []byte(encoding.EncodeToString(buf.Bytes()))
}

// TestParseInitDataPolicy_GzipBase64 covers the production wire shape:
// raw cc_init_data → gzip → base64. Both StdEncoding (padded) and
// RawStdEncoding (unpadded) must round-trip. Without this test, a
// regression in decodeInitDataWire (wrong base64 alphabet, missing
// gzip path, size limit too tight) ships green and only surfaces on
// the cluster.
func TestParseInitDataPolicy_GzipBase64(t *testing.T) {
	digestHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	rawTOML := validInitDataTOML(t, "ghcr.io/example/app", digestHex)

	for _, tc := range []struct {
		name string
		enc  *base64.Encoding
	}{
		{"padded", base64.StdEncoding},
		{"raw_unpadded", base64.RawStdEncoding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := gzipBase64(t, rawTOML, tc.enc)
			require.True(t, bytes.HasPrefix(wire, []byte("H4sI")),
				"gzip+base64 must start with H4sI; if this fails the heuristic is wrong")

			registry, digest, err := parseInitDataPolicy(wire)
			require.NoError(t, err)
			assert.Equal(t, "ghcr.io/example/app", registry)
			assert.Equal(t, digestHex, digest)
		})
	}
}

// TestParseInitDataPolicy_GzipBomb covers the decompression-bomb
// guard. A small gzip blob expanding to >maxDecompressedInitData must
// be rejected before tomlv2.Unmarshal sees the bytes — otherwise a
// caller can OOM the KMS node with a few hundred KB of gzip payload.
func TestParseInitDataPolicy_GzipBomb(t *testing.T) {
	// 16 MiB of zeros compresses to ~16 KiB. The decoder caps decompressed
	// output at 8 MiB; this should be rejected.
	bomb := make([]byte, 16<<20)
	wire := gzipBase64(t, bomb, base64.StdEncoding)

	_, _, err := parseInitDataPolicy(wire)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

// TestParseInitDataPolicy_RegoCommentBypass guards against the
// stale-image-in-comment attack: if the regex picks the first match
// in the rego string, a deprecated digest in a `#`-prefixed line
// outranks the active rule's ref. stripRegoComments must drop those
// lines so the active rule wins.
func TestParseInitDataPolicy_RegoCommentBypass(t *testing.T) {
	staleDigest := "1111111111111111111111111111111111111111111111111111111111111111"
	activeDigest := "2222222222222222222222222222222222222222222222222222222222222222"
	doc := []byte(fmt.Sprintf(`algorithm = "sha384"
version = "0.1.0"

[data]
"policy.rego" = """
package agent_policy

# OLD: registry.internal/deprecated/app@sha256:%s
default allow = false
allow {
  input.image == "ghcr.io/real/app@sha256:%s"
}
"""
`, staleDigest, activeDigest))

	registry, digest, err := parseInitDataPolicy(doc)
	require.NoError(t, err)
	assert.Equal(t, "ghcr.io/real/app", registry,
		"image binding must come from the active rule, not the # comment")
	assert.Equal(t, activeDigest, digest)
}

// TestStripRegoComments documents the contract: only whole-line `#`
// comments are stripped, and only when `#` is the first non-whitespace
// character. Inline trailing comments are preserved (the active OCI
// ref always appears before any trailing `#` on the same line, so the
// regex picks the right one anyway).
func TestStripRegoComments(t *testing.T) {
	in := strings.Join([]string{
		`# top-level comment line`,
		`  # indented comment line`,
		`allow {`,
		`  input.image == "ghcr.io/x/y@sha256:abc"  # trailing comment`,
		`}`,
	}, "\n")
	out := stripRegoComments(in)
	assert.NotContains(t, out, "top-level comment line")
	assert.NotContains(t, out, "indented comment line")
	assert.Contains(t, out, `input.image == "ghcr.io/x/y@sha256:abc"`)
	assert.Contains(t, out, "# trailing comment", "inline comments preserved")
}
