package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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
		Key:           "DB_PASSWORD",
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
	assert.Equal(t, in.Key, got.Key)
}

func TestReadRequest_IgnoresUnknownFields(t *testing.T) {
	// The CDH plugin and helper are versioned independently, so readRequest
	// must tolerate stdin keys it doesn't model (no DisallowUnknownFields)
	// and still parse the fields it needs.
	body := []byte(`{"app_id":"x","key":"K","some_future_field":"deadbeef"}`)
	got, err := readRequest(bytes.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "x", got.AppID)
	assert.Equal(t, "K", got.Key)
}

func TestReadRequest_MissingFields(t *testing.T) {
	// app_id and key are the required stdin fields; the values come from the
	// KMS's release env, not the caller. KMS-coord fields are validated
	// against cc_init_data in applyInitdataKMSConfig.
	tests := []struct {
		name        string
		req         Request
		expectedErr string
	}{
		{
			name: "missing app_id",
			req: Request{
				AVSAddress: "0xabc",
				RPCURL:     "https://eth.example",
				Key:        "K",
			},
			expectedErr: "app_id is required",
		},
		{
			name: "missing key",
			req: Request{
				AppID: "app-id",
			},
			expectedErr: "key is required",
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

// TestApplyInitdataKMSConfig pins the SNP-bound contract: KMS coords
// MUST come from cc_init_data, stdin overrides are ignored. See the
// SSRF rationale in applyInitdataKMSConfig's comment.
func TestApplyInitdataKMSConfig(t *testing.T) {
	// These subtests exercise URL validation + the SSRF guard with a kms_url
	// present, which is the single-operator path. Opt into it for the whole
	// function; the gate itself is covered separately below.
	t.Setenv(envAllowSingleOperatorKMS, "1")

	t.Run("initdata populates empty request", func(t *testing.T) {
		req := &Request{AppID: "x"}
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
	t.Run("initdata wins over stdin (SSRF guard)", func(t *testing.T) {
		// stdin pretends to redirect to an attacker-controlled KMS;
		// initdata is SNP-bound and authoritative.
		req := &Request{
			AppID:         "x",
			KMSURL:        "http://attacker.example",
			AVSAddress:    "0xattacker",
			OperatorSetID: 99,
			RPCURL:        "http://attacker.example",
		}
		cfg := &initdataKMSConfig{
			KMSURL: "http://kms.example", AVSAddress: "0xabc",
			OperatorSetID: 7, RPCURL: "http://rpc.example",
		}
		require.NoError(t, applyInitdataKMSConfig(req, cfg))
		assert.Equal(t, "http://kms.example", req.KMSURL,
			"stdin must NOT override initdata kms_url")
		assert.Equal(t, "0xabc", req.AVSAddress,
			"stdin must NOT override initdata avs_address")
		assert.Equal(t, uint32(7), req.OperatorSetID,
			"stdin must NOT override initdata operator_set_id")
		assert.Equal(t, "http://rpc.example", req.RPCURL,
			"stdin must NOT override initdata rpc_url")
	})
	t.Run("nil cfg fails closed", func(t *testing.T) {
		req := &Request{AppID: "x"}
		err := applyInitdataKMSConfig(req, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "eigenx.toml")
	})
	t.Run("missing avs_address fails", func(t *testing.T) {
		cfg := &initdataKMSConfig{KMSURL: "http://kms.example"}
		err := applyInitdataKMSConfig(&Request{AppID: "x"}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "avs_address")
	})
	t.Run("missing rpc_url and kms_url fails", func(t *testing.T) {
		cfg := &initdataKMSConfig{AVSAddress: "0xabc"}
		err := applyInitdataKMSConfig(&Request{AppID: "x"}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "kms_url or rpc_url")
	})
	t.Run("non-http kms_url scheme rejected", func(t *testing.T) {
		cfg := &initdataKMSConfig{
			KMSURL: "file:///etc/passwd", AVSAddress: "0xabc",
		}
		err := applyInitdataKMSConfig(&Request{AppID: "x"}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scheme")
	})
	t.Run("gopher rpc_url scheme rejected", func(t *testing.T) {
		cfg := &initdataKMSConfig{
			AVSAddress: "0xabc", RPCURL: "gopher://internal.example/",
		}
		err := applyInitdataKMSConfig(&Request{AppID: "x"}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scheme")
	})
	t.Run("missing host rejected", func(t *testing.T) {
		cfg := &initdataKMSConfig{
			KMSURL: "http:///path", AVSAddress: "0xabc",
		}
		err := applyInitdataKMSConfig(&Request{AppID: "x"}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "host")
	})
}

// TestApplyInitdataKMSConfig_SingleOperatorGate pins that the single-operator
// (threshold-1) path a kms_url selects is OFF unless explicitly opted in,
// while the production on-chain path (rpc_url, no kms_url) is unaffected.
func TestApplyInitdataKMSConfig_SingleOperatorGate(t *testing.T) {
	t.Run("kms_url without opt-in fails closed", func(t *testing.T) {
		// env var unset (default production posture)
		cfg := &initdataKMSConfig{
			KMSURL: "http://kms.example", AVSAddress: "0xabc",
		}
		err := applyInitdataKMSConfig(&Request{AppID: "x"}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), envAllowSingleOperatorKMS)
		assert.Contains(t, err.Error(), "trust downgrade")
	})

	t.Run("kms_url with opt-in succeeds", func(t *testing.T) {
		t.Setenv(envAllowSingleOperatorKMS, "1")
		req := &Request{AppID: "x"}
		cfg := &initdataKMSConfig{
			KMSURL: "http://kms.example", AVSAddress: "0xabc",
		}
		require.NoError(t, applyInitdataKMSConfig(req, cfg))
		assert.Equal(t, "http://kms.example", req.KMSURL)
	})

	t.Run("production rpc_url path needs no opt-in", func(t *testing.T) {
		// env var unset; rpc_url only, no kms_url → on-chain discovery path.
		req := &Request{AppID: "x"}
		cfg := &initdataKMSConfig{
			RPCURL: "http://rpc.example", AVSAddress: "0xabc",
		}
		require.NoError(t, applyInitdataKMSConfig(req, cfg))
		assert.Equal(t, "http://rpc.example", req.RPCURL)
		assert.Empty(t, req.KMSURL)
	})

	t.Run("opt-in set to something other than 1 still fails closed", func(t *testing.T) {
		t.Setenv(envAllowSingleOperatorKMS, "true")
		cfg := &initdataKMSConfig{
			KMSURL: "http://kms.example", AVSAddress: "0xabc",
		}
		err := applyInitdataKMSConfig(&Request{AppID: "x"}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), envAllowSingleOperatorKMS)
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

// gzipBase64Helper produces the production wire shape of
// /run/peerpod/initdata: gzip(toml) → base64. Used to exercise
// decodeInitdata's gzip path through parseInitdataKMSConfig — the
// shape kata-shim writes from the cc_init_data pod annotation, which
// the unit tests otherwise never exercise.
func gzipBase64Helper(t *testing.T, raw []byte, encoding *base64.Encoding) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return []byte(encoding.EncodeToString(buf.Bytes()))
}

// TestParseInitdataKMSConfig_GzipBase64 covers the production wire
// format path: parseInitdataKMSConfig must handle base64(gzip(toml)),
// not just raw TOML. Both padded and unpadded base64 must round-trip
// (kata-shim emits unpadded in some cloud-provider configurations).
func TestParseInitdataKMSConfig_GzipBase64(t *testing.T) {
	rawTOML := []byte(`algorithm = "sha384"
version = "0.1.0"

[data]
"eigenx.toml" = '''
kms_url = "http://kms.example:8000"
avs_address = "0xabc"
operator_set_id = 7
rpc_url = "http://rpc.example"
'''
`)
	for _, tc := range []struct {
		name string
		enc  *base64.Encoding
	}{
		{"padded", base64.StdEncoding},
		{"raw_unpadded", base64.RawStdEncoding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := gzipBase64Helper(t, rawTOML, tc.enc)
			require.True(t, bytes.HasPrefix(wire, []byte("H4sI")))
			cfg, err := parseInitdataKMSConfig(wire)
			require.NoError(t, err)
			require.NotNil(t, cfg)
			assert.Equal(t, "http://kms.example:8000", cfg.KMSURL)
			assert.Equal(t, "0xabc", cfg.AVSAddress)
			assert.Equal(t, uint32(7), cfg.OperatorSetID)
			assert.Equal(t, "http://rpc.example", cfg.RPCURL)
		})
	}
}

// TestParseInitdataKMSConfig_GzipBomb defends the helper against an
// initdata blob that decompresses to a memory-exhaustion size. The
// helper runs in the workload's TEE but a compromised K8s control
// plane could feed it a malicious initdata; failing closed beats
// OOMing the kata-agent host process.
func TestParseInitdataKMSConfig_GzipBomb(t *testing.T) {
	bomb := make([]byte, 16<<20)
	wire := gzipBase64Helper(t, bomb, base64.StdEncoding)
	_, err := parseInitdataKMSConfig(wire)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

// TestRSAKeypairRoundTripsThroughEncryption locks the PEM-format contract
// between the helper and the KMS client's RSA layer. generateRSAKeypair
// emits the public key as PKIX/"PUBLIC KEY" and retrieveAndDecrypt marshals
// the private key as PKCS#1/"RSA PRIVATE KEY". pkg/encryption.RSAEncryption
// must accept both, or the eigenx-snp flow fails at runtime with an opaque
// key-format error instead of here. This catches a future regression in
// either marshaler without standing up the full e2e.
func TestRSAKeypairRoundTripsThroughEncryption(t *testing.T) {
	priv, pubPEM, err := generateRSAKeypair()
	require.NoError(t, err)

	// Private key PEM exactly as retrieveAndDecrypt builds it (PKCS#1).
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	rsaEnc := encryption.NewRSAEncryption()
	plaintext := []byte("partial-signature-blob-stand-in")

	ciphertext, err := rsaEnc.Encrypt(plaintext, pubPEM)
	require.NoError(t, err, "Encrypt must accept the PKIX PUBLIC KEY PEM generateRSAKeypair emits")

	got, err := rsaEnc.Decrypt(ciphertext, privPEM)
	require.NoError(t, err, "Decrypt must accept the PKCS#1 RSA PRIVATE KEY PEM the helper hands the client")
	assert.Equal(t, plaintext, got)
}

func TestAssembleEnvFromSecrets_RoundTrip(t *testing.T) {
	const stackID = "stack-xyz"

	// Build a synthetic master key + the app-private-key threshold recovery
	// would yield for this stackID (mirrors pkg/crypto/ibe_test.go:259-272).
	masterSecret, err := new(fr.Element).SetRandom()
	require.NoError(t, err)
	masterPubKey, err := crypto.ScalarMulG2(crypto.G2Generator, masterSecret)
	require.NoError(t, err)
	appHash, err := crypto.HashToG1(stackID)
	require.NoError(t, err)
	appPrivateKey, err := crypto.ScalarMulG1(*appHash, masterSecret)
	require.NoError(t, err)

	// Seal two secrets the way the ecloud CLI does: EncryptForApp(stackID, master, v).
	ct1, err := crypto.EncryptForApp(stackID, *masterPubKey, []byte("hunter2"))
	require.NoError(t, err)
	ct2, err := crypto.EncryptForApp(stackID, *masterPubKey, []byte("token-abc"))
	require.NoError(t, err)

	env, err := assembleEnvFromSecrets(stackID, *appPrivateKey, []stackSecret{
		{Name: "DB_PASSWORD", Value: ct1},
		{Name: "API_KEY", Value: ct2},
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"DB_PASSWORD": "hunter2", "API_KEY": "token-abc"}, env)
}

func TestAssembleEnvFromSecrets_EmptyList(t *testing.T) {
	appHash, err := crypto.HashToG1("stack-1")
	require.NoError(t, err)
	masterSecret, err := new(fr.Element).SetRandom()
	require.NoError(t, err)
	appPrivateKey, err := crypto.ScalarMulG1(*appHash, masterSecret)
	require.NoError(t, err)

	env, err := assembleEnvFromSecrets("stack-1", *appPrivateKey, nil)
	require.NoError(t, err)
	assert.Empty(t, env)
}

func TestAssembleEnvFromSecrets_UndecryptableValueFailsClosed(t *testing.T) {
	// A value sealed to a DIFFERENT identity must fail — a sealed value we
	// can't open is a real fault, not an empty secret.
	const stackID = "stack-real"
	masterSecret, err := new(fr.Element).SetRandom()
	require.NoError(t, err)
	masterPubKey, err := crypto.ScalarMulG2(crypto.G2Generator, masterSecret)
	require.NoError(t, err)
	appHash, err := crypto.HashToG1(stackID)
	require.NoError(t, err)
	appPrivateKey, err := crypto.ScalarMulG1(*appHash, masterSecret)
	require.NoError(t, err)

	// Sealed to "other-stack", not stackID.
	wrongCT, err := crypto.EncryptForApp("other-stack", *masterPubKey, []byte("v"))
	require.NoError(t, err)

	_, err = assembleEnvFromSecrets(stackID, *appPrivateKey, []stackSecret{{Name: "X", Value: wrongCT}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "X")
}
