// kmsCDHHelper is a stdin/stdout child binary spawned by the CDH (Confidential
// Data Hub) plugin running inside a SEV-SNP peer-pod. It drives the eigenx-snp
// attestation flow against the EigenX threshold KMS and writes the IBE-decrypted
// plaintext to stdout.
//
// Wire contract:
//   - stdin: JSON Request (see Request struct)
//   - stdout: raw plaintext bytes on success
//   - stderr: log lines on failure
//   - exit code: 0 on success, non-zero on any error (with diagnostic on stderr)
//
// The helper:
//  1. Generates an ephemeral RSA-2048 keypair (binds attestation to this run).
//  2. Composes report_data: lower 32 = SHA256(rsaPubPEM || extraData),
//     upper 32 = SHA384(cc_init_data)[:32]. Lower-32 layout mirrors the existing
//     KBS-EAR nonce so KMS server-side nonce binding is identical.
//  3. Fetches raw SEV-SNP evidence from the in-pod AA at 127.0.0.1:8006.
//  4. Calls RetrieveSecretsWithOptions with attestation_method=eigenx-snp; the
//     KMS client returns the recovered AppPrivateKey (no IBE-decrypt on its own).
//  5. IBE-decrypts the user-supplied ciphertext_hex with crypto.DecryptForApp.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	tomlv2 "github.com/pelletier/go-toml/v2"
)

// singleOperatorContractCaller is a stub kmsClient.ContractCaller that
// advertises exactly one operator at a fixed URL — used for the fakeKMS
// e2e shim where the helper bypasses on-chain operator discovery. See
// retrieveAndDecrypt for the activation condition (kms_url non-empty).
type singleOperatorContractCaller struct {
	socketAddress string
}

func newSingleOperatorContractCaller(socketAddress string) *singleOperatorContractCaller {
	return &singleOperatorContractCaller{socketAddress: socketAddress}
}

func (s *singleOperatorContractCaller) GetOperatorSetMembersWithPeering(avsAddress string, operatorSetID uint32) (*peering.OperatorSetPeers, error) {
	// Operator address must match what fakeKMS advertises in /pubkey
	// responses. Both sides default to 0x...0001 in the fakeKMS deployment.
	return &peering.OperatorSetPeers{
		OperatorSetId: operatorSetID,
		AVSAddress:    common.HexToAddress(avsAddress),
		Peers: []*peering.OperatorSetPeer{
			{
				OperatorAddress: common.HexToAddress("0x0000000000000000000000000000000000000001"),
				SocketAddress:   s.socketAddress,
			},
		},
	}, nil
}

// Request is the JSON payload read from stdin from CDH's eigenx plugin.
//
// As of the cc_init_data-binding refactor, KMS coordinates (kms_url,
// avs_address, operator_set_id, rpc_url) are sourced from the SNP-bound
// /run/peerpod/initdata document instead of the per-call request, so they
// carry the same integrity guarantees as the policy.rego image-digest
// binding. The plugin and downstream callers should pass only the per-secret
// fields (app_id, ciphertext_hex). Legacy callers that still send the KMS
// fields on stdin override the initdata-sourced values for backwards
// compatibility, but new code should not rely on this.
type Request struct {
	KMSURL        string `json:"kms_url,omitempty"`
	AVSAddress    string `json:"avs_address,omitempty"`
	OperatorSetID uint32 `json:"operator_set_id,omitempty"`
	RPCURL        string `json:"rpc_url,omitempty"`
	AppID         string `json:"app_id"`
	CiphertextHex string `json:"ciphertext_hex"`
}

// initdataKMSConfig is the schema we expect under cc_init_data's
// [data]."eigenx.toml" key. The values are SNP-bound: an attacker tampering
// with cc_init_data invalidates SHA-384(initdata) which is folded into the
// SEV-SNP report's REPORT_DATA upper 32 bytes.
type initdataKMSConfig struct {
	KMSURL        string `toml:"kms_url"`
	AVSAddress    string `toml:"avs_address"`
	OperatorSetID uint32 `toml:"operator_set_id"`
	RPCURL        string `toml:"rpc_url"`
}

const (
	aaEvidenceURL    = "http://127.0.0.1:8006/aa/evidence"
	aaTimeout        = 30 * time.Second
	aaMaxBodyBytes   = 1 << 20 // 1 MiB cap on AA response body
	rsaKeyBits       = 2048
	reportDataLength = 64
)

func main() {
	if err := run(); err != nil {
		log.Printf("kmsCDHHelper: %v", err)
		os.Exit(1)
	}
}

func run() error {
	req, err := readRequest(os.Stdin)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}

	rsaPriv, rsaPubPEM, err := generateRSAKeypair()
	if err != nil {
		return fmt.Errorf("generate RSA keypair: %w", err)
	}

	// CDH plugin loads /run/peerpod/initdata before spawning us; the bytes are
	// supplied via stdin in a future revision. For now we read it here so the
	// helper is self-contained.
	ccInitData, err := os.ReadFile("/run/peerpod/initdata")
	if err != nil {
		return fmt.Errorf("read /run/peerpod/initdata: %w", err)
	}

	// Pull KMS coordinates (kms_url/avs_address/operator_set_id/rpc_url) from
	// cc_init_data's [data]."eigenx.toml" key when the caller didn't include
	// them on stdin. cc_init_data is SNP-bound (folded into REPORT_DATA upper
	// 32 via SHA-384), so values sourced from there can't be tampered with by
	// the K8s control plane.
	if cfg, perr := parseInitdataKMSConfig(ccInitData); perr != nil {
		return fmt.Errorf("parse cc_init_data KMS config: %w", perr)
	} else if perr = applyInitdataKMSConfig(req, cfg); perr != nil {
		return perr
	}

	// extraData is currently empty; reserved for the CDH plugin to bind extra
	// runtime context into the attestation nonce in a later revision.
	var extraData []byte
	reportData := buildReportData(rsaPubPEM, extraData, ccInitData)

	rawAAEvidence, err := fetchAAEvidence(reportData)
	if err != nil {
		return fmt.Errorf("fetch AA evidence: %w", err)
	}

	// AA's evidence at the upstream pin we ship serializes the SEV-SNP report
	// as a nested JSON object (Rust's serde-derive on sev::AttestationReport)
	// with cert_chain entries shaped {cert_type, data:[u8...]}. The KMS
	// server's eigenx-snp method consumes the legacy raw-bytes shape — see
	// pkg/attestation/eigenx_snp_method.go::rawSNPEvidence. Bridge the two
	// here so the server stays the authoritative parser of its own contract.
	evidence, err := transformAAEvidence(rawAAEvidence)
	if err != nil {
		return fmt.Errorf("transform AA evidence: %w", err)
	}

	plaintext, err := retrieveAndDecrypt(req, evidence, ccInitData, rsaPubPEM, rsaPriv)
	if err != nil {
		return fmt.Errorf("retrieve and decrypt: %w", err)
	}

	if _, err := os.Stdout.Write(plaintext); err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	return nil
}

// readRequest parses the stdin JSON request. KMS-coord fields are NOT
// validated here; they're filled in from cc_init_data later (see
// applyInitdataKMSConfig). app_id + ciphertext_hex must be present in the
// stdin request — those are per-secret and travel with the call.
func readRequest(r io.Reader) (*Request, error) {
	var req Request
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	if req.AppID == "" {
		return nil, fmt.Errorf("app_id is required")
	}
	if req.CiphertextHex == "" {
		return nil, fmt.Errorf("ciphertext_hex is required")
	}
	return &req, nil
}

// parseInitdataKMSConfig parses cc_init_data's [data]."eigenx.toml" key into
// the KMS-coord struct.
//
// The on-disk file at /run/peerpod/initdata is the *raw* annotation that
// kata-shim handed to the podVM via cloud user-data — base64(gzip(toml)).
// CAA's process-user-data parses this in-memory but does NOT rewrite the
// file with the decoded TOML, so we have to undo the same encoding here.
// Match what initdata.Parse does in cloud-api-adaptor's pkg/initdata.
func parseInitdataKMSConfig(ccInitData []byte) (*initdataKMSConfig, error) {
	tomlBytes, err := decodeInitdata(ccInitData)
	if err != nil {
		return nil, fmt.Errorf("decode cc_init_data wire format: %w", err)
	}
	var doc struct {
		Data map[string]any `toml:"data"`
	}
	if err := tomlv2.Unmarshal(tomlBytes, &doc); err != nil {
		return nil, fmt.Errorf("parse cc_init_data TOML: %w", err)
	}
	raw, ok := doc.Data["eigenx.toml"].(string)
	if !ok {
		// Field absent — caller must have supplied KMS coords on stdin.
		return nil, nil
	}
	var cfg initdataKMSConfig
	if err := tomlv2.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("parse [data].\"eigenx.toml\": %w", err)
	}
	return &cfg, nil
}

// decodeInitdata accepts /run/peerpod/initdata in either of two shapes —
// raw TOML (legacy / unit tests) or base64(gzip(toml)) (production: what
// kata-shim writes from the cc_init_data pod annotation, what
// process-user-data reads). We sniff by attempting base64+gzip first; on
// failure, fall back to treating the input as raw TOML.
func decodeInitdata(in []byte) ([]byte, error) {
	// Trim whitespace because kata-shim sometimes appends a trailing newline
	// and base64 doesn't tolerate trailing whitespace inside the alphabet.
	trimmed := bytes.TrimSpace(in)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty initdata")
	}
	// Quick heuristic: a valid base64(gzip(...)) blob starts with 'H4sI'
	// (the magic 0x1f 0x8b for gzip → base64). Raw TOML doesn't.
	if bytes.HasPrefix(trimmed, []byte("H4sI")) {
		b64Reader := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(trimmed))
		gzipReader, err := gzip.NewReader(b64Reader)
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer gzipReader.Close()
		return io.ReadAll(gzipReader)
	}
	// Treat as raw TOML.
	return trimmed, nil
}

// applyInitdataKMSConfig fills request KMS-coord fields from cc_init_data
// when stdin didn't already carry them. Stdin values win for backwards
// compatibility with legacy callers; new callers leave them empty and rely
// on the SNP-bound initdata values exclusively.
func applyInitdataKMSConfig(req *Request, cfg *initdataKMSConfig) error {
	if cfg != nil {
		if req.KMSURL == "" {
			req.KMSURL = cfg.KMSURL
		}
		if req.AVSAddress == "" {
			req.AVSAddress = cfg.AVSAddress
		}
		if req.OperatorSetID == 0 {
			req.OperatorSetID = cfg.OperatorSetID
		}
		if req.RPCURL == "" {
			req.RPCURL = cfg.RPCURL
		}
	}
	if req.AVSAddress == "" {
		return fmt.Errorf("avs_address must be set on stdin or in cc_init_data [data].\"eigenx.toml\"")
	}
	if req.RPCURL == "" && req.KMSURL == "" {
		return fmt.Errorf("rpc_url or kms_url must be set on stdin or in cc_init_data [data].\"eigenx.toml\"")
	}
	return nil
}

// generateRSAKeypair returns a fresh RSA-2048 keypair. The public key is
// PKIX-encoded inside a PUBLIC KEY PEM block to match the encoding the KMS
// client uses elsewhere (see pkg/encryption.GenerateKeyPair).
func generateRSAKeypair() (*rsa.PrivateKey, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("rsa.GenerateKey: %w", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("MarshalPKIXPublicKey: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return priv, pubPEM, nil
}

// buildReportData composes the 64-byte SEV-SNP REPORT_DATA field as 64
// printable-ASCII hex characters:
//
//	lower 32 chars = hex(SHA-256(rsaPubPEM || extraData)[:16])  -- nonce binding
//	upper 32 chars = hex(SHA-384(cc_init_data)[:16])            -- workload-identity binding
//
// Why hex instead of raw 64 bytes:
//
// AA's evidence endpoint at the upstream guest-components pin shipped in our
// AMI (f1561038...) routes through api-server-rest which puts the
// runtime_data query value into a Rust String, then ships
// String::into_bytes() to the SNP attester. Random raw bytes aren't valid
// UTF-8, so form_urlencoded::parse replaces invalid sequences with U+FFFD
// (3 UTF-8 bytes each) and the result blows past the 64-byte SNP REPORT_DATA
// limit. Restricting REPORT_DATA to 64 printable ASCII characters keeps the
// transport lossless.
//
// Each half holds 16 bytes (128 bits) of hash output, which is plenty for
// nonce freshness and image-binding integrity. Both halves are bound into
// the AMD-signed report; KMS operators recompute the same 64 hex chars and
// constant-time compare.
func buildReportData(rsaPubPEM, extraData, ccInitData []byte) [reportDataLength]byte {
	h := sha256.New()
	h.Write(rsaPubPEM)
	h.Write(extraData)
	lower := h.Sum(nil) // 32 bytes
	upperFull := sha512.Sum384(ccInitData)

	lowerHex := hex.EncodeToString(lower[:16])     // 32 ASCII chars
	upperHex := hex.EncodeToString(upperFull[:16]) // 32 ASCII chars

	var out [reportDataLength]byte
	copy(out[:32], lowerHex)
	copy(out[32:], upperHex)
	return out
}

// fetchAAEvidence calls the in-pod Attestation Agent at 127.0.0.1:8006 and
// returns the opaque raw-SNP evidence JSON bytes
// ({"attestation_report": ..., "cert_chain": ...}). The bytes are passed
// as-is into the KMS request — the wire encoding to base64 is handled by Go's
// []byte JSON marshalling.
func fetchAAEvidence(reportData [reportDataLength]byte) ([]byte, error) {
	// api-server-rest at the guest-components pin shipped in our AMI
	// (f1561038...) treats the runtime_data query value as raw bytes —
	// runtime_data.clone().into_bytes() — and SNP Attester demands the
	// resulting bytes be exactly 64 long. Newer guest-components revisions
	// added a `decode_runtime_data` step that decodes base64url when
	// `encoding=base64` is present, but our pin predates that. So we
	// percent-encode the 64 raw report-data bytes and let url.Values.Encode
	// produce e.g. %A2%5C... — Go's net/http URL parsing on the AA side
	// decodes these back to 64 raw bytes before stuffing them into
	// into_bytes(), giving the SNP Attester exactly the 64 bytes it wants.
	u, err := url.Parse(aaEvidenceURL)
	if err != nil {
		return nil, fmt.Errorf("parse AA URL: %w", err)
	}
	q := u.Query()
	q.Set("runtime_data", string(reportData[:]))
	u.RawQuery = q.Encode()

	client := &http.Client{Timeout: aaTimeout}
	resp, err := client.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, aaMaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read AA response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AA returned status %d: %s", resp.StatusCode, string(body))
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("AA returned empty body")
	}
	return body, nil
}

// retrieveAndDecrypt drives the on-chain operator discovery, the eigenx-snp
// secret-retrieval flow, and the IBE-decrypt of the caller-supplied ciphertext.
//
// Note: RetrieveSecretsWithOptions does NOT IBE-decrypt — it returns the
// recovered AppPrivateKey and the still-encrypted EncryptedEnv. The IBE-decrypt
// of the user-supplied ciphertext_hex happens here via crypto.DecryptForApp.
func retrieveAndDecrypt(
	req *Request,
	evidence, ccInitData, rsaPubPEM []byte,
	rsaPriv *rsa.PrivateKey,
) ([]byte, error) {
	zapLogger, err := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	if err != nil {
		return nil, fmt.Errorf("create logger: %w", err)
	}

	// If kms_url is supplied, treat it as a single-operator override and skip
	// chain-based discovery entirely. This is the path used by the fakeKMS
	// shim during end-to-end testing of the eigenx-snp flow without standing
	// up Ethereum + IAppController. Production sealed envelopes leave kms_url
	// empty and discovery happens via the on-chain operator set.
	var contractCaller kmsClient.ContractCaller
	if strings.TrimSpace(req.KMSURL) != "" {
		contractCaller = newSingleOperatorContractCaller(req.KMSURL)
	} else {
		ethClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
			BaseUrl:   req.RPCURL,
			BlockType: ethereum.BlockType_Latest,
		}, zapLogger)
		l1Client, err := ethClient.GetEthereumContractCaller()
		if err != nil {
			return nil, fmt.Errorf("get Ethereum contract caller: %w", err)
		}
		contractCaller, err = caller.NewContractCaller(l1Client, nil, zapLogger)
		if err != nil {
			return nil, fmt.Errorf("create contract caller: %w", err)
		}
	}

	client, err := kmsClient.NewClient(&kmsClient.ClientConfig{
		AVSAddress:     req.AVSAddress,
		OperatorSetID:  req.OperatorSetID,
		Logger:         zapLogger,
		ContractCaller: contractCaller,
	})
	if err != nil {
		return nil, fmt.Errorf("create KMS client: %w", err)
	}

	// PEM-encode the RSA private key so we can hand it to the client (which
	// needs PEM bytes to decrypt the partial-signature blobs in transit).
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaPriv),
	})

	opts := &kmsClient.SecretsOptions{
		AttestationMethod: "eigenx-snp",
		RawSNPEvidence:    evidence,
		CCInitData:        ccInitData,
		RSAPrivateKeyPEM:  privPEM,
		RSAPublicKeyPEM:   rsaPubPEM,
	}

	result, err := client.RetrieveSecretsWithOptions(req.AppID, opts)
	if err != nil {
		return nil, fmt.Errorf("RetrieveSecretsWithOptions: %w", err)
	}

	ciphertext, err := hex.DecodeString(req.CiphertextHex)
	if err != nil {
		// Tolerate 0x prefix to match the kmsClient CLI's hexutil.Decode behaviour.
		if len(req.CiphertextHex) > 2 && (req.CiphertextHex[0:2] == "0x" || req.CiphertextHex[0:2] == "0X") {
			ciphertext, err = hex.DecodeString(req.CiphertextHex[2:])
		}
		if err != nil {
			return nil, fmt.Errorf("decode ciphertext_hex: %w", err)
		}
	}

	plaintext, err := crypto.DecryptForApp(req.AppID, result.AppPrivateKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("DecryptForApp: %w", err)
	}
	return plaintext, nil
}

// aaSnpEvidence mirrors the AA-emitted SNP evidence shape at our pinned
// guest-components revision (f1561038...). The Rust source is
// attestation-agent/attester/src/snp/mod.rs::SnpEvidence — Rust's
// serde-derive on sev::AttestationReport produces a nested JSON object whose
// field names are the struct's Rust field names (snake_case) and whose
// fixed-size byte arrays serialize as JSON arrays of integers.
//
// We only deserialize the fields go-sev-guest's pb.Report carries (the AMD
// signed-component fields). pb.Report has no slot for fields that aren't on
// the AMD wire (e.g. the Rust-only id_key_digest is on the wire but pb.Report
// reads it from the same offset; see abi.ReportToProto). Anything we don't
// need is omitted from this struct.
type aaSnpEvidence struct {
	AttestationReport aaAttestationReport `json:"attestation_report"`
	CertChain         []aaCertEntry       `json:"cert_chain"`
}

// aaAttestationReport mirrors sev::AttestationReport from the virtee/sev
// crate. Newtype bitfield structs (GuestPolicy, PlatformInfo, KeyInfo)
// serde-serialize as their inner integer.
type aaAttestationReport struct {
	Version         uint32       `json:"version"`
	GuestSvn        uint32       `json:"guest_svn"`
	Policy          uint64       `json:"policy"`
	FamilyId        []byte       `json:"family_id"`
	ImageId         []byte       `json:"image_id"`
	Vmpl            uint32       `json:"vmpl"`
	SigAlgo         uint32       `json:"sig_algo"`
	CurrentTcb      aaTcbVersion `json:"current_tcb"`
	PlatInfo        uint64       `json:"plat_info"`
	KeyInfo         uint32       `json:"key_info"`
	ReportData      []byte       `json:"report_data"`
	Measurement     []byte       `json:"measurement"`
	HostData        []byte       `json:"host_data"`
	IdKeyDigest     []byte       `json:"id_key_digest"`
	AuthorKeyDigest []byte       `json:"author_key_digest"`
	ReportId        []byte       `json:"report_id"`
	ReportIdMa      []byte       `json:"report_id_ma"`
	ReportedTcb     aaTcbVersion `json:"reported_tcb"`
	CpuidFamId      *uint8       `json:"cpuid_fam_id"`
	CpuidModId      *uint8       `json:"cpuid_mod_id"`
	CpuidStep       *uint8       `json:"cpuid_step"`
	ChipId          []byte       `json:"chip_id"`
	CommittedTcb    aaTcbVersion `json:"committed_tcb"`
	Current         aaVersion    `json:"current"`
	Committed       aaVersion    `json:"committed"`
	LaunchTcb       aaTcbVersion `json:"launch_tcb"`
	LaunchMitVector *uint64      `json:"launch_mit_vector"`
	CurMitVector    *uint64      `json:"current_mit_vector"`
	Signature       aaSignature  `json:"signature"`
}

type aaTcbVersion struct {
	Fmc        *uint8 `json:"fmc"`
	Bootloader uint8  `json:"bootloader"`
	Tee        uint8  `json:"tee"`
	Snp        uint8  `json:"snp"`
	Microcode  uint8  `json:"microcode"`
}

type aaVersion struct {
	Major uint8 `json:"major"`
	Minor uint8 `json:"minor"`
	Build uint8 `json:"build"`
}

type aaSignature struct {
	R []byte `json:"r"`
	S []byte `json:"s"`
}

type aaCertEntry struct {
	CertType string `json:"cert_type"`
	Data     []byte `json:"data"`
}

// legacyEvidence is the {attestation_report:<raw 1184 bytes>, cert_chain:[<PEM>]}
// shape the KMS server's eigenx-snp method consumes. This mirrors
// pkg/attestation/eigenx_snp_method.go::rawSNPEvidence — duplicated rather than
// imported because we don't want a server package dependency in the helper.
type legacyEvidence struct {
	AttestationReport []byte   `json:"attestation_report"`
	CertChain         []string `json:"cert_chain"`
}

// transformAAEvidence rewrites AA's nested-JSON SNP evidence into the legacy
// raw-bytes wire shape that pkg/attestation expects. Two pieces:
//
//  1. The attestation_report object → 1184 raw little-endian bytes via
//     abi.ReportToAbiBytes (the inverse of the parsing the KMS server does
//     with abi.ReportToProto).
//  2. cert_chain entries {cert_type, data:[u8...]} → DER-then-PEM strings.
//     buildCertChain on the server side is identification-by-CN, not by
//     ordering, so any cert_type mapping (VLEK, VCEK, ARK, ...) round-trips
//     through PEM cleanly — Subject CN survives DER → PEM → DER.
func transformAAEvidence(raw []byte) ([]byte, error) {
	var ev aaSnpEvidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, fmt.Errorf("decode AA evidence JSON: %w", err)
	}

	reportProto, err := aaReportToProto(&ev.AttestationReport)
	if err != nil {
		return nil, fmt.Errorf("convert AA report to pb.Report: %w", err)
	}

	rawReport, err := abi.ReportToAbiBytes(reportProto)
	if err != nil {
		return nil, fmt.Errorf("encode pb.Report to ABI bytes: %w", err)
	}

	pemCerts := make([]string, 0, len(ev.CertChain))
	for i, entry := range ev.CertChain {
		if len(entry.Data) == 0 {
			continue
		}
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: entry.Data,
		})
		if pemBlock == nil {
			return nil, fmt.Errorf("cert_chain[%d] (%s): PEM encode returned nil", i, entry.CertType)
		}
		pemCerts = append(pemCerts, string(pemBlock))
	}

	out, err := json.Marshal(legacyEvidence{
		AttestationReport: rawReport,
		CertChain:         pemCerts,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal legacy evidence: %w", err)
	}
	return out, nil
}

// aaReportToProto maps the deserialized Rust struct to go-sev-guest's
// pb.Report. The mapping is field-for-field for the AMD signed-component
// fields; bitfield newtypes (policy/plat_info/key_info) carry through as
// the inner integer value.
//
// TCB version composition: virtee/sev's TcbVersion struct exposes named
// fields (bootloader, tee, snp, microcode); pb.Report stores TCB as a packed
// little-endian u64 matching the AMD wire format (legacy: bootloader at
// byte 0, tee at byte 1, snp at byte 6, microcode at byte 7; bytes 2-5 are
// reserved zero on Milan/Genoa). We rebuild that u64 here.
//
// CPUID family/model/stepping go into Cpuid1EaxFms; for V2 reports these
// fields are absent in the Rust struct (Option::None) and we leave the
// proto field zero (matching abi.ReportToAbiBytes behavior).
func aaReportToProto(r *aaAttestationReport) (*spb.Report, error) {
	if len(r.ReportData) != 64 {
		return nil, fmt.Errorf("report_data: got %d bytes, want 64", len(r.ReportData))
	}
	if len(r.Measurement) != 48 {
		return nil, fmt.Errorf("measurement: got %d bytes, want 48", len(r.Measurement))
	}
	if len(r.HostData) != 32 {
		return nil, fmt.Errorf("host_data: got %d bytes, want 32", len(r.HostData))
	}
	if len(r.FamilyId) != 16 {
		return nil, fmt.Errorf("family_id: got %d bytes, want 16", len(r.FamilyId))
	}
	if len(r.ImageId) != 16 {
		return nil, fmt.Errorf("image_id: got %d bytes, want 16", len(r.ImageId))
	}
	if len(r.IdKeyDigest) != 48 {
		return nil, fmt.Errorf("id_key_digest: got %d bytes, want 48", len(r.IdKeyDigest))
	}
	if len(r.AuthorKeyDigest) != 48 {
		return nil, fmt.Errorf("author_key_digest: got %d bytes, want 48", len(r.AuthorKeyDigest))
	}
	if len(r.ReportId) != 32 {
		return nil, fmt.Errorf("report_id: got %d bytes, want 32", len(r.ReportId))
	}
	if len(r.ReportIdMa) != 32 {
		return nil, fmt.Errorf("report_id_ma: got %d bytes, want 32", len(r.ReportIdMa))
	}
	if len(r.ChipId) != 64 {
		return nil, fmt.Errorf("chip_id: got %d bytes, want 64", len(r.ChipId))
	}
	if len(r.Signature.R) != 72 {
		return nil, fmt.Errorf("signature.r: got %d bytes, want 72", len(r.Signature.R))
	}
	if len(r.Signature.S) != 72 {
		return nil, fmt.Errorf("signature.s: got %d bytes, want 72", len(r.Signature.S))
	}

	// pb.Report.Signature is the full 512-byte signature field on the AMD
	// wire — 72 bytes r, 72 bytes s, 368 reserved zero bytes.
	sig := make([]byte, 512)
	copy(sig[0:72], r.Signature.R)
	copy(sig[72:144], r.Signature.S)

	// CPUID family/model/stepping packed into the cpuid(1).eax representation
	// pb.Report.Cpuid1EaxFms expects. abi.FmsToCpuid1Eax encodes (family,
	// model, stepping) → eax with the AMD-canonical extended field layout.
	var fms uint32
	if r.CpuidFamId != nil || r.CpuidModId != nil || r.CpuidStep != nil {
		var fam, mod, step uint8
		if r.CpuidFamId != nil {
			fam = *r.CpuidFamId
		}
		if r.CpuidModId != nil {
			mod = *r.CpuidModId
		}
		if r.CpuidStep != nil {
			step = *r.CpuidStep
		}
		fms = abi.FmsToCpuid1Eax(fam, mod, step)
	}

	var launchMit, curMit uint64
	if r.LaunchMitVector != nil {
		launchMit = *r.LaunchMitVector
	}
	if r.CurMitVector != nil {
		curMit = *r.CurMitVector
	}

	return &spb.Report{
		Version:          r.Version,
		GuestSvn:         r.GuestSvn,
		Policy:           r.Policy,
		FamilyId:         append([]byte(nil), r.FamilyId...),
		ImageId:          append([]byte(nil), r.ImageId...),
		Vmpl:             r.Vmpl,
		SignatureAlgo:    r.SigAlgo,
		CurrentTcb:       packLegacyTcb(r.CurrentTcb),
		PlatformInfo:     r.PlatInfo,
		SignerInfo:       r.KeyInfo,
		ReportData:       append([]byte(nil), r.ReportData...),
		Measurement:      append([]byte(nil), r.Measurement...),
		HostData:         append([]byte(nil), r.HostData...),
		IdKeyDigest:      append([]byte(nil), r.IdKeyDigest...),
		AuthorKeyDigest:  append([]byte(nil), r.AuthorKeyDigest...),
		ReportId:         append([]byte(nil), r.ReportId...),
		ReportIdMa:       append([]byte(nil), r.ReportIdMa...),
		ReportedTcb:      packLegacyTcb(r.ReportedTcb),
		ChipId:           append([]byte(nil), r.ChipId...),
		CommittedTcb:     packLegacyTcb(r.CommittedTcb),
		CurrentBuild:     uint32(r.Current.Build),
		CurrentMinor:     uint32(r.Current.Minor),
		CurrentMajor:     uint32(r.Current.Major),
		CommittedBuild:   uint32(r.Committed.Build),
		CommittedMinor:   uint32(r.Committed.Minor),
		CommittedMajor:   uint32(r.Committed.Major),
		LaunchTcb:        packLegacyTcb(r.LaunchTcb),
		Signature:        sig,
		Cpuid1EaxFms:     fms,
		LaunchMitVector:  launchMit,
		CurrentMitVector: curMit,
	}, nil
}

// packLegacyTcb composes the Milan/Genoa TCB wire layout — bootloader at
// byte 0, tee at byte 1, bytes 2-5 reserved zero, snp at byte 6, microcode
// at byte 7 — into the little-endian u64 pb.Report carries. Turin/Venice
// have a different layout that abi.ReportToAbiBytes routes via its own
// generation detection; we pin to the legacy form here because our cluster
// runs Milan/Genoa hosts. If we ever boot Turin instances this will need
// generation-aware packing (as the Rust side does in TcbVersion::encode).
func packLegacyTcb(t aaTcbVersion) uint64 {
	var b [8]byte
	b[0] = t.Bootloader
	b[1] = t.Tee
	b[6] = t.Snp
	b[7] = t.Microcode
	return uint64(b[0]) |
		uint64(b[1])<<8 |
		uint64(b[2])<<16 |
		uint64(b[3])<<24 |
		uint64(b[4])<<32 |
		uint64(b[5])<<40 |
		uint64(b[6])<<48 |
		uint64(b[7])<<56
}
