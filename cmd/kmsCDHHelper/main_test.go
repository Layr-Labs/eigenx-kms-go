package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-sev-guest/abi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadRequest_HappyPath(t *testing.T) {
	in := Request{
		KMSURL:        "https://kms.example/secrets",
		AVSAddress:    "0xabc",
		OperatorSetID: 0,
		RPCURL:        "https://eth.example/v2/key",
		AppID:         "app-id",
		CiphertextHex: "deadbeef",
	}
	body, err := json.Marshal(in)
	require.NoError(t, err)

	got, err := readRequest(bytes.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, in.KMSURL, got.KMSURL)
	assert.Equal(t, in.AVSAddress, got.AVSAddress)
	assert.Equal(t, in.OperatorSetID, got.OperatorSetID)
	assert.Equal(t, in.RPCURL, got.RPCURL)
	assert.Equal(t, in.AppID, got.AppID)
	assert.Equal(t, in.CiphertextHex, got.CiphertextHex)
}

func TestReadRequest_MissingFields(t *testing.T) {
	// Per-secret fields stay required at stdin parse time. KMS-coord fields
	// (avs_address, rpc_url, kms_url, operator_set_id) used to be enforced
	// here; they're now validated against cc_init_data in applyInitdataKMSConfig.
	tests := []struct {
		name        string
		req         Request
		expectedErr string
	}{
		{
			name: "missing app_id",
			req: Request{
				AVSAddress:    "0xabc",
				RPCURL:        "https://eth.example",
				CiphertextHex: "00",
			},
			expectedErr: "app_id is required",
		},
		{
			name: "missing ciphertext_hex",
			req: Request{
				AVSAddress: "0xabc",
				RPCURL:     "https://eth.example",
				AppID:      "x",
			},
			expectedErr: "ciphertext_hex is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.req)
			require.NoError(t, err)
			_, err = readRequest(bytes.NewReader(body))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

// TestApplyInitdataKMSConfig covers the two valid sources of KMS coords:
// stdin-supplied (legacy) and cc_init_data-supplied (preferred). Stdin wins
// when both are present.
func TestApplyInitdataKMSConfig(t *testing.T) {
	t.Run("initdata fills empty fields", func(t *testing.T) {
		req := &Request{AppID: "x", CiphertextHex: "00"}
		cfg := &initdataKMSConfig{
			KMSURL: "http://kms.example", AVSAddress: "0xabc",
			OperatorSetID: 7, RPCURL: "http://rpc.example",
		}
		require.NoError(t, applyInitdataKMSConfig(req, cfg))
		assert.Equal(t, "http://kms.example", req.KMSURL)
		assert.Equal(t, "0xabc", req.AVSAddress)
		assert.Equal(t, uint32(7), req.OperatorSetID)
		assert.Equal(t, "http://rpc.example", req.RPCURL)
	})
	t.Run("stdin wins over initdata", func(t *testing.T) {
		req := &Request{
			AppID: "x", CiphertextHex: "00",
			AVSAddress: "0xstdin", RPCURL: "http://stdin",
		}
		cfg := &initdataKMSConfig{AVSAddress: "0xinit", RPCURL: "http://init"}
		require.NoError(t, applyInitdataKMSConfig(req, cfg))
		assert.Equal(t, "0xstdin", req.AVSAddress)
		assert.Equal(t, "http://stdin", req.RPCURL)
	})
	t.Run("missing avs_address fails", func(t *testing.T) {
		req := &Request{AppID: "x", CiphertextHex: "00"}
		err := applyInitdataKMSConfig(req, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "avs_address")
	})
	t.Run("missing rpc_url and kms_url fails", func(t *testing.T) {
		req := &Request{AppID: "x", CiphertextHex: "00", AVSAddress: "0xabc"}
		err := applyInitdataKMSConfig(req, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rpc_url or kms_url")
	})
}

// TestParseInitdataKMSConfig round-trips the schema we expect inside
// cc_init_data's [data]."eigenx.toml".
func TestParseInitdataKMSConfig(t *testing.T) {
	doc := `algorithm = "sha384"
version = "0.1.0"

[data]
"eigenx.toml" = '''
kms_url = "http://kms.example:8000"
avs_address = "0xabc"
operator_set_id = 0
rpc_url = "http://rpc.example"
'''
`
	cfg, err := parseInitdataKMSConfig([]byte(doc))
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "http://kms.example:8000", cfg.KMSURL)
	assert.Equal(t, "0xabc", cfg.AVSAddress)
	assert.Equal(t, "http://rpc.example", cfg.RPCURL)

	t.Run("absent key returns nil", func(t *testing.T) {
		minimal := `algorithm = "sha384"
version = "0.1.0"
[data]
"aa.toml" = '''
'''
`
		got, err := parseInitdataKMSConfig([]byte(minimal))
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}

func TestReadRequest_InvalidJSON(t *testing.T) {
	_, err := readRequest(strings.NewReader("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode JSON")
}

func TestBuildReportData_Composition(t *testing.T) {
	rsaPub := []byte("-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----")
	extraData := []byte("extra")
	initData := []byte("initdata-document-bytes")

	got := buildReportData(rsaPub, extraData, initData)

	// must be exactly 64 bytes (the SEV-SNP REPORT_DATA field width)
	assert.Equal(t, 64, len(got))

	// lower 32 = hex(SHA-256(rsaPub || extraData)[:16]) — see commentary in
	// buildReportData for why the bytes have to land as printable ASCII.
	h := sha256.New()
	h.Write(rsaPub)
	h.Write(extraData)
	want := hex.EncodeToString(h.Sum(nil)[:16])
	assert.Equal(t, want, string(got[:32]))

	// upper 32 = hex(SHA-384(initData)[:16])
	full := sha512.Sum384(initData)
	wantUpper := hex.EncodeToString(full[:16])
	assert.Equal(t, wantUpper, string(got[32:]))
}

func TestBuildReportData_EmptyExtraData(t *testing.T) {
	rsaPub := []byte("pub")
	initData := []byte("init")

	got := buildReportData(rsaPub, nil, initData)
	wantBytes := sha256.Sum256(rsaPub)
	want := hex.EncodeToString(wantBytes[:16])
	assert.Equal(t, want, string(got[:32]))
}

func TestReportData_Base64URLRoundTrip(t *testing.T) {
	rsaPub := []byte("pub")
	extraData := []byte("ed")
	initData := []byte("init")

	rd := buildReportData(rsaPub, extraData, initData)
	encoded := base64.RawURLEncoding.EncodeToString(rd[:])
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, rd[:], decoded)
}

// TestTransformAAEvidence_PreservesReportData asserts the bridge from AA's
// nested-JSON SNP evidence to the legacy {raw bytes, [PEM strings]} wire
// shape preserves the field that matters most for this helper —
// REPORT_DATA. The KMS server-side eigenx-snp method recomputes REPORT_DATA
// and constant-time compares against the bytes inside the raw report.
//
// We don't try to assert byte-exact equality of the full 1184-byte report
// here: that would require fabricating a Milan-generation TCB layout and
// every reserved-byte the AMD wire format zeroes. abi.ReportToProto on the
// server side and abi.ReportToAbiBytes on our side use the same offsets,
// so the round-trip is structurally correct as long as REPORT_DATA lands
// at offset 0x50..0x90 (which is what we check).
func TestTransformAAEvidence_PreservesReportData(t *testing.T) {
	var rd [64]byte
	for i := range rd {
		rd[i] = byte(i + 1) // non-zero pattern so a copy bug shows up
	}

	ev := aaSnpEvidence{
		AttestationReport: aaAttestationReport{
			Version: 2,
			// Policy bit 17 is reserved-and-must-be-1 per the AMD SEV-SNP
			// ABI; abi.ReportToAbiBytes rejects anything else. Real reports
			// always have it set. (1 << 17) = 0x20000.
			Policy:          0x20000,
			SigAlgo:         1,
			FamilyId:        make([]byte, 16),
			ImageId:         make([]byte, 16),
			ReportData:      rd[:],
			Measurement:     make([]byte, 48),
			HostData:        make([]byte, 32),
			IdKeyDigest:     make([]byte, 48),
			AuthorKeyDigest: make([]byte, 48),
			ReportId:        make([]byte, 32),
			ReportIdMa:      make([]byte, 32),
			ChipId:          make([]byte, 64),
			Signature: aaSignature{
				R: make([]byte, 72),
				S: make([]byte, 72),
			},
		},
		CertChain: []aaCertEntry{},
	}
	raw, err := json.Marshal(ev)
	require.NoError(t, err)

	out, err := transformAAEvidence(raw)
	require.NoError(t, err)

	var legacy legacyEvidence
	require.NoError(t, json.Unmarshal(out, &legacy))
	require.Len(t, legacy.AttestationReport, abi.ReportSize)

	// REPORT_DATA lives at 0x50..0x90 in the AMD wire format. If we lost it
	// in the AA-struct → pb.Report conversion, the server's binding check
	// will fail with the same opaque "REPORT_DATA mismatch" we'd hit in
	// production; assert the byte-for-byte landing here.
	assert.Equal(t, rd[:], legacy.AttestationReport[0x50:0x90])

	// Sanity: ReportToProto on the round-tripped bytes recovers the same
	// REPORT_DATA + Policy + Version we put in.
	gotProto, err := abi.ReportToProto(legacy.AttestationReport)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), gotProto.GetVersion())
	assert.Equal(t, uint64(0x20000), gotProto.GetPolicy())
	assert.Equal(t, rd[:], gotProto.GetReportData())
}

// TestTransformAAEvidence_CertChainPEM verifies the {cert_type, data:[u8]}
// → PEM string conversion. We don't have a real AMD cert bytes here, but
// any DER-shaped blob round-trips: PEM-wrap → strip header → exact bytes.
// The server's buildCertChain identifies certs by Subject CN, so it doesn't
// care about cert_type ordering on our side.
func TestTransformAAEvidence_CertChainPEM(t *testing.T) {
	// Minimal report so transformAAEvidence reaches the cert-chain branch.
	// Policy bit 17 is reserved-must-be-1 (see TestTransformAAEvidence_PreservesReportData).
	ev := aaSnpEvidence{
		AttestationReport: aaAttestationReport{
			Version:         2,
			Policy:          0x20000,
			FamilyId:        make([]byte, 16),
			ImageId:         make([]byte, 16),
			ReportData:      make([]byte, 64),
			Measurement:     make([]byte, 48),
			HostData:        make([]byte, 32),
			IdKeyDigest:     make([]byte, 48),
			AuthorKeyDigest: make([]byte, 48),
			ReportId:        make([]byte, 32),
			ReportIdMa:      make([]byte, 32),
			ChipId:          make([]byte, 64),
			Signature: aaSignature{
				R: make([]byte, 72),
				S: make([]byte, 72),
			},
		},
		CertChain: []aaCertEntry{
			{CertType: "VLEK", Data: []byte{0x30, 0x82, 0x01, 0x02}}, // arbitrary DER-shaped bytes
			{CertType: "ARK", Data: []byte{0x30, 0x82, 0x03, 0x04}},
		},
	}
	raw, err := json.Marshal(ev)
	require.NoError(t, err)

	out, err := transformAAEvidence(raw)
	require.NoError(t, err)

	var legacy legacyEvidence
	require.NoError(t, json.Unmarshal(out, &legacy))
	require.Len(t, legacy.CertChain, 2)

	// Each PEM block must round-trip back to the original DER bytes.
	for i, expected := range [][]byte{
		{0x30, 0x82, 0x01, 0x02},
		{0x30, 0x82, 0x03, 0x04},
	} {
		assert.Contains(t, legacy.CertChain[i], "-----BEGIN CERTIFICATE-----")
		assert.Contains(t, legacy.CertChain[i], "-----END CERTIFICATE-----")
		// PEM is base64 of DER between the headers; assert by extracting
		// the body and base64-decoding it.
		pemStr := legacy.CertChain[i]
		start := strings.Index(pemStr, "-----BEGIN CERTIFICATE-----")
		end := strings.Index(pemStr, "-----END CERTIFICATE-----")
		require.GreaterOrEqual(t, start, 0)
		require.Greater(t, end, start)
		body := strings.TrimSpace(pemStr[start+len("-----BEGIN CERTIFICATE-----") : end])
		body = strings.ReplaceAll(body, "\n", "")
		got, err := base64.StdEncoding.DecodeString(body)
		require.NoError(t, err)
		assert.Equal(t, expected, got)
	}
}
