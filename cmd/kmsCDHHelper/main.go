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
//     KMS client recovers the AppPrivateKey (the platform path returns only the
//     recovered key, no env).
//  5. Fetches the stack's sealed secrets from the ecloud-platform
//     InternalSecretsService and IBE-decrypts each with crypto.DecryptForApp
//     under the stackID identity, using the recovered AppPrivateKey — so the
//     plaintext only exists inside this attested TEE (docs/references/new_kms.md).
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
	"regexp"
	"strings"
	"time"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	tomlv2 "github.com/pelletier/go-toml/v2"
)

// defaultSingleOperatorAddress is the operator address fakeKMS advertises
// in its /pubkey responses by default. The single-operator shim must list
// the SAME address as the peer, or kmsClient's CollectPartialSignatures
// silently drops the (otherwise valid) partial sig on an address-mismatch
// check and surfaces a confusing "collected 0, needed 1". Overridable via
// cc_init_data's operator_address for non-canonical fakeKMS deployments
// (or a real single-node KMS at a known address).
const defaultSingleOperatorAddress = "0x0000000000000000000000000000000000000001"

// envAllowSingleOperatorKMS opts the helper into the single-operator
// (threshold-1) KMS path that a non-empty cc_init_data kms_url selects. It is
// a deliberate trust downgrade for fakeKMS end-to-end testing and is OFF by
// default: production AMIs leave it unset so a kms_url fails closed. fakeKMS
// test images set it to "1". See applyInitdataKMSConfig.
const envAllowSingleOperatorKMS = "EIGENX_ALLOW_SINGLE_OPERATOR_KMS"

// singleOperatorContractCaller is a stub kmsClient.ContractCaller that
// advertises exactly one operator at a fixed URL — used for the fakeKMS
// e2e shim where the helper bypasses on-chain operator discovery. See
// retrieveAndDecrypt for the activation condition (kms_url non-empty).
type singleOperatorContractCaller struct {
	socketAddress   string
	operatorAddress string
}

func newSingleOperatorContractCaller(socketAddress, operatorAddress string) *singleOperatorContractCaller {
	if strings.TrimSpace(operatorAddress) == "" {
		operatorAddress = defaultSingleOperatorAddress
	}
	return &singleOperatorContractCaller{socketAddress: socketAddress, operatorAddress: operatorAddress}
}

func (s *singleOperatorContractCaller) GetOperatorSetMembersWithPeering(avsAddress string, operatorSetID uint32) (*peering.OperatorSetPeers, error) {
	// OperatorAddress must match what the target KMS advertises in /pubkey
	// responses, else CollectPartialSignatures drops the sig on the
	// address-mismatch check. Defaults to 0x...0001 (fakeKMS default).
	return &peering.OperatorSetPeers{
		OperatorSetId: operatorSetID,
		AVSAddress:    common.HexToAddress(avsAddress),
		Peers: []*peering.OperatorSetPeer{
			{
				OperatorAddress: common.HexToAddress(s.operatorAddress),
				SocketAddress:   s.socketAddress,
			},
		},
	}, nil
}

// Request is the JSON payload read from stdin from CDH's eigenx plugin.
//
// In the stack model, stack_id is the app identity: it selects the KMS
// platform path AND is the IBE identity secrets are sealed to. The KMS
// coordinates (kms_url, avs_address, operator_set_id, rpc_url) and the
// stack/platform fields are all sourced from the SNP-bound /run/peerpod/initdata
// document, so they carry the same integrity guarantees as the policy.rego
// image-digest binding; a stdin stack_id is tolerated for parsing but overridden
// by initdata (see applyInitdataKMSConfig).
//
// Secrets are NOT carried in this request and are NOT part of the KMS response:
// they are fetched from the ecloud-platform InternalSecretsService
// (PlatformSecretsURL) and IBE-decrypted with the threshold-recovered
// app_private_key inside this TEE (docs/references/new_kms.md).
//
// Key selects which environment variable to return from the assembled stack
// env, or the reserved sentinel appPrivateKeyKey to return the app_private_key
// itself. CDH calls the helper once per sealed env var in the pod spec, each
// carrying the Key it wants. The first call attests + fetches and caches the
// whole env map to tmpfs; later calls for the same stack read the cache (one
// attestation per pod, not per key). See env_cache.go.
type Request struct {
	KMSURL        string `json:"kms_url,omitempty"`
	AVSAddress    string `json:"avs_address,omitempty"`
	OperatorSetID uint32 `json:"operator_set_id,omitempty"`
	RPCURL        string `json:"rpc_url,omitempty"`
	// OperatorAddress is only consulted on the single-operator (kms_url) override path.
	OperatorAddress string `json:"operator_address,omitempty"`
	// StackID is the app identity in the stack model. It selects the KMS
	// platform path AND is the IBE identity secrets are sealed to. Sourced from
	// SNP-bound cc_init_data (applyInitdataKMSConfig); a stdin value is tolerated
	// but overridden.
	StackID string `json:"stack_id"`
	// PlatformSecretsURL / PlatformInternalAPIKey address the ecloud-platform
	// InternalSecretsService. Sourced ONLY from SNP-bound cc_init_data — never
	// from stdin — for the same SSRF/redirect reasons as the KMS coords.
	PlatformSecretsURL     string `json:"-"`
	PlatformInternalAPIKey string `json:"-"`
	// Key is the environment-variable name to return from the assembled stack
	// env, or the reserved sentinel appPrivateKeyKey to return the app_private_key.
	Key string `json:"key"`
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
	// OperatorAddress pins the single-operator shim's peer address when
	// kms_url is set; optional, defaults to defaultSingleOperatorAddress.
	OperatorAddress string `toml:"operator_address"`
	// Stack model: identity + platform secrets endpoint, SNP-bound.
	StackID                string `toml:"stack_id"`
	PlatformSecretsURL     string `toml:"platform_secrets_url"`
	PlatformInternalAPIKey string `toml:"platform_internal_api_key"`
}

const (
	aaEvidenceURL    = "http://127.0.0.1:8006/aa/evidence"
	aaTimeout        = 30 * time.Second
	aaMaxBodyBytes   = 1 << 20 // 1 MiB cap on AA response body
	rsaKeyBits       = 2048
	reportDataLength = 64
	initDataPath     = "/run/peerpod/initdata"
)

// appPrivateKeyKey is a reserved Key value that makes the helper emit the
// threshold-recovered app_private_key itself (hex of its compressed G1 bytes)
// rather than an environment variable. This is the KMS-derived root a
// signing daemon seeds from (app_private_key = S·H(appID)); it travels the
// exact same eigenx-snp attestation path as a sealed env var, so it is only
// ever recoverable inside an attested TEE. Because it is not part of the
// release env, it bypasses the merged-env assembly, the IBE-decrypt, and the
// tmpfs env cache entirely (the root must never be written to disk).
const appPrivateKeyKey = "__EIGENX_APP_PRIVATE_KEY__"

// cacheable reports whether a request key may be served from / written to the
// tmpfs env cache. The app_private_key root is never cached: it is not part of
// the release env and must not be persisted to disk, so its request always
// re-attests. This single predicate is the one place the invariant lives — add
// any future reserved sentinels to the exclusion here.
func cacheable(key string) bool {
	return key != appPrivateKeyKey
}

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

	// Fast path: another sealed env var for this same app already attested and
	// cached the full merged env this pod boot. Serve the requested key from
	// the cache and skip attestation + the KMS round trip entirely. The lock
	// is held across the read so we don't race a concurrent first-call writer
	// (kata-agent unseals sequentially today, but a multi-container pod shares
	// the podVM). See env_cache.go.
	//
	// The app_private_key root is never cached (it is not part of the env map),
	// so its request always attests fresh and never consults the cache.
	if cacheable(req.Key) {
		if env, ok, cerr := loadCachedEnv(req.StackID); cerr != nil {
			return fmt.Errorf("read env cache: %w", cerr)
		} else if ok {
			return emitKey(env, req.Key)
		}
	}

	rsaPriv, rsaPubPEM, err := generateRSAKeypair()
	if err != nil {
		return fmt.Errorf("generate RSA keypair: %w", err)
	}

	// CDH plugin loads /run/peerpod/initdata before spawning us; the bytes are
	// supplied via stdin in a future revision. For now we read it here so the
	// helper is self-contained. Stat first to bound memory: /run/peerpod is
	// host-controlled and a malicious CAA could plant a multi-GB file. Real
	// CoCo init-data is base64(gzip(toml)) — kilobytes — so 1 MiB is a
	// generous compressed-size cap that matches the KMS handler's wire-side
	// cc_init_data limit.
	const maxInitDataFileSize = 1 << 20 // 1 MiB
	info, err := os.Stat(initDataPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", initDataPath, err)
	}
	if info.Size() > maxInitDataFileSize {
		return fmt.Errorf("%s is %d bytes; refusing to read (cap %d)", initDataPath, info.Size(), maxInitDataFileSize)
	}
	ccInitData, err := os.ReadFile(initDataPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", initDataPath, err)
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

	env, err := retrieveAndDecrypt(req, evidence, ccInitData, rsaPubPEM, rsaPriv)
	if err != nil {
		return fmt.Errorf("retrieve and decrypt: %w", err)
	}

	// Cache the whole merged env so sibling sealed vars for this app this pod
	// boot hit the fast path above. Best-effort: a cache write failure must not
	// fail the unseal — we already have the value in hand.
	//
	// Never cache the app_private_key root: it is not part of the release env,
	// and it must not be persisted to the tmpfs cache. Its request always
	// re-attests (see the fast-path guard above).
	if cacheable(req.Key) {
		if cerr := storeCachedEnv(req.StackID, env); cerr != nil {
			log.Printf("warning: cache stack env for stack %q: %v", req.StackID, cerr)
		}
	}

	return emitKey(env, req.Key)
}

// readRequest parses the stdin JSON request. KMS-coord fields are NOT
// validated here; they're filled in from cc_init_data later (see
// applyInitdataKMSConfig). stack_id and key are required; the env values come
// from the ecloud-platform stack secrets, not the caller.
func readRequest(r io.Reader) (*Request, error) {
	var req Request
	dec := json.NewDecoder(r)
	// Tolerate unknown fields rather than DisallowUnknownFields(): the CDH
	// plugin and the helper are versioned independently (the plugin lives
	// in the podVM AMI, the helper is a sideloaded binary in the same
	// image but bumped on different cadences). A new plugin field — extra
	// context, telemetry — must not break the helper; struct tags ignore
	// unknown keys silently, which is the contract we want.
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	if req.StackID == "" {
		return nil, fmt.Errorf("stack_id is required")
	}
	if req.Key == "" {
		return nil, fmt.Errorf("key is required")
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
		// Tolerate base64 with or without `=` padding. kata-shim emits
		// unpadded in some cloud-provider configurations (GKE, AKS); the
		// AWS-shaped CAA path uses padded. Strip trailing `=` and use
		// RawStdEncoding so both shapes round-trip — see the matching
		// logic in pkg/attestation/eigenx_snp_method.go::decodeInitDataWire.
		stripped := bytes.TrimRight(trimmed, "=")
		b64Reader := base64.NewDecoder(base64.RawStdEncoding, bytes.NewReader(stripped))
		gzipReader, err := gzip.NewReader(b64Reader)
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer func() { _ = gzipReader.Close() }()
		// Bound decompressed size to defend against gzip bombs even on
		// the helper side (the helper runs in the workload's TEE, but a
		// compromised CAA could still feed it a malicious initdata
		// blob). 8 MiB is generous headroom over real CoCo init-data
		// documents (kilobytes).
		const maxDecompressedInitData = 8 << 20
		limited := io.LimitReader(gzipReader, maxDecompressedInitData+1)
		out, err := io.ReadAll(limited)
		if err != nil {
			return nil, fmt.Errorf("read decompressed initdata: %w", err)
		}
		if len(out) > maxDecompressedInitData {
			return nil, fmt.Errorf("decompressed initdata exceeds %d bytes", maxDecompressedInitData)
		}
		return out, nil
	}
	// Treat as raw TOML.
	return trimmed, nil
}

// applyInitdataKMSConfig overwrites the per-call Request's KMS-coord
// fields with the SNP-bound values from cc_init_data's [data]."eigenx.toml".
//
// initdata wins unconditionally — stdin values are dropped on the floor
// (with a non-fatal warning logged) when initdata also pins the field.
// Reason: kms_url, avs_address, operator_set_id, and rpc_url all control
// where the helper sends evidence and which on-chain operator set
// authenticates the response. A compromised K8s control plane can rewrite
// the CDH plugin's stdin payload (it spawns the helper); only cc_init_data
// is SNP-bound (folded into REPORT_DATA via SHA-384). Letting stdin
// override creates an SSRF/operator-redirect surface where an attacker can
// point the workload at a malicious KMS without invalidating the
// attestation.
//
// stdin remains the ONLY source for the per-secret fields (app_id,
// ciphertext_hex) — those don't carry a redirect-the-world risk.
func applyInitdataKMSConfig(req *Request, cfg *initdataKMSConfig) error {
	if cfg == nil {
		return fmt.Errorf("cc_init_data missing [data].\"eigenx.toml\"; KMS coords cannot be sourced safely")
	}
	if cfg.KMSURL == "" && cfg.RPCURL == "" {
		return fmt.Errorf("[data].\"eigenx.toml\" must set kms_url or rpc_url")
	}
	if cfg.AVSAddress == "" {
		return fmt.Errorf("[data].\"eigenx.toml\" must set avs_address")
	}
	// Validate URL schemes — both kms_url and rpc_url must be http(s).
	// initdata is SNP-bound, but defense-in-depth: a misconfigured initdata
	// pointing at file://, ftp://, etc. would otherwise reach url.Parse +
	// http.Client and produce confusing failures or hit unintended fetchers.
	if cfg.KMSURL != "" {
		if err := validateHTTPURL(cfg.KMSURL, "kms_url"); err != nil {
			return err
		}
	}
	if cfg.RPCURL != "" {
		if err := validateHTTPURL(cfg.RPCURL, "rpc_url"); err != nil {
			return err
		}
	}
	// Gate the single-operator path. A non-empty kms_url skips on-chain
	// operator discovery and the threshold model entirely, talking to one URL
	// as a single advertised operator (threshold-1). That's a deliberate trust
	// downgrade for fakeKMS end-to-end testing — it MUST NOT silently activate
	// in production. cc_init_data is SNP-bound (a compromised control plane
	// can't inject kms_url without invalidating attestation), but that only
	// proves the value is authentic, not that it's *intended* — a
	// misconfigured release could still pin a kms_url and drop the workload
	// onto the no-threshold path. So require an explicit opt-in baked into the
	// AMI's helper environment, mirroring fakeKMS's --snp-allow-amd-kds-fetch:
	// test images set EIGENX_ALLOW_SINGLE_OPERATOR_KMS=1; production images
	// don't, and a kms_url then fails loud here instead of downgrading trust.
	if cfg.KMSURL != "" && os.Getenv(envAllowSingleOperatorKMS) != "1" {
		return fmt.Errorf("cc_init_data sets kms_url (single-operator/threshold-1 path) "+
			"but %s is not enabled; refusing trust downgrade — production must use on-chain "+
			"operator discovery (set rpc_url, leave kms_url empty)", envAllowSingleOperatorKMS)
	}
	stdinOverridden := (req.KMSURL != "" && req.KMSURL != cfg.KMSURL) ||
		(req.AVSAddress != "" && req.AVSAddress != cfg.AVSAddress) ||
		(req.OperatorSetID != 0 && req.OperatorSetID != cfg.OperatorSetID) ||
		(req.RPCURL != "" && req.RPCURL != cfg.RPCURL)
	if stdinOverridden {
		// Log to stderr — the CDH plugin pipes stderr to journal so
		// operators can audit whether a workload is trying to bypass the
		// SNP-bound config. Continue with initdata values regardless.
		log.Printf("kmsCDHHelper: ignoring stdin KMS-coord overrides; SNP-bound initdata wins")
	}

	// Stack model: identity + platform secrets endpoint are mandatory and
	// SNP-bound. Fail closed if any is absent so the helper can never fall back
	// to an unauthenticated or unintended secrets source.
	if cfg.StackID == "" {
		return fmt.Errorf("[data].\"eigenx.toml\" must set stack_id")
	}
	if err := validateStackID(cfg.StackID); err != nil {
		return fmt.Errorf("[data].\"eigenx.toml\" %w", err)
	}
	if cfg.PlatformSecretsURL == "" {
		return fmt.Errorf("[data].\"eigenx.toml\" must set platform_secrets_url")
	}
	if cfg.PlatformInternalAPIKey == "" {
		return fmt.Errorf("[data].\"eigenx.toml\" must set platform_internal_api_key")
	}
	if err := validateHTTPURL(cfg.PlatformSecretsURL, "platform_secrets_url"); err != nil {
		return err
	}

	req.KMSURL = cfg.KMSURL
	req.AVSAddress = cfg.AVSAddress
	req.OperatorSetID = cfg.OperatorSetID
	req.RPCURL = cfg.RPCURL
	req.OperatorAddress = cfg.OperatorAddress
	req.StackID = cfg.StackID
	req.PlatformSecretsURL = cfg.PlatformSecretsURL
	req.PlatformInternalAPIKey = cfg.PlatformInternalAPIKey
	return nil
}

// stackIDPattern restricts stack_id to characters that are always a single,
// safe URL path segment: alphanumerics plus - _ . (covers UUIDs and slugs).
// This blocks path-injection/traversal (/, .., %2e, spaces, query/fragment
// metacharacters) before stack_id is used to build the platform ListSecrets
// path. Defense-in-depth alongside url.PathEscape at the request boundary.
var stackIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// validateStackID rejects an empty or path-unsafe stack_id. "." and ".." are
// rejected explicitly because they are traversal segments even though each
// char is in the allowed set.
func validateStackID(stackID string) error {
	if stackID == "" {
		return fmt.Errorf("stack_id: empty")
	}
	if stackID == "." || stackID == ".." {
		return fmt.Errorf("stack_id: %q is not a valid path segment", stackID)
	}
	if !stackIDPattern.MatchString(stackID) {
		return fmt.Errorf("stack_id: %q contains characters outside [A-Za-z0-9._-]", stackID)
	}
	return nil
}

// validateHTTPURL rejects anything that isn't http:// or https://. We do
// NOT enforce a host allowlist here — initdata is SNP-bound so the host is
// already pinned by the AMD-signed REPORT_DATA. The check is just a
// scheme-shape sanity rail: file://, ftp://, gopher://, etc. should never
// appear in production initdata, and rejecting them up front beats the
// confusing failure mode further down (gopher:// in particular has been a
// recurring SSRF gadget in Go's stdlib net/url).
func validateHTTPURL(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: parse: %w", field, err)
	}
	switch u.Scheme {
	case "http", "https":
		// fine
	default:
		return fmt.Errorf("%s: scheme %q not allowed (must be http or https)", field, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%s: missing host", field)
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
// We send REPORT_DATA to AA via api-server-rest's `runtime_data` query
// param WITHOUT an `encoding` param (see fetchAAEvidence). On that path
// api-server-rest takes the query value's bytes verbatim
// (`runtime_data.as_bytes()` — the documented "legacy" behavior, stable
// across guest-components revisions) and hands them to the SNP attester,
// which requires exactly 64 bytes. Routing arbitrary bytes through a URL
// query string is lossy: non-UTF-8 / non-ASCII sequences get mangled
// (percent-decode + UTF-8 replacement) and the result no longer matches
// the original 64 bytes. Restricting REPORT_DATA to 64 printable ASCII
// characters keeps the round-trip lossless regardless of the api-server
// version.
//
// (api-server-rest also supports `encoding=base64` — base64url-decode of
// runtime_data — which would let us send full 32-byte hashes instead of
// truncating to 16. That's a tracked simplification; see
// docs/009_eigenxSnpAttestation.md. Until then we use the version-agnostic
// ASCII-hex path.)
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
	// We pass runtime_data WITHOUT an `encoding` param, so api-server-rest
	// takes the query value's bytes verbatim (its "legacy" no-encoding path:
	// `runtime_data.as_bytes()`) and the SNP attester demands exactly 64
	// bytes. REPORT_DATA is therefore 64 printable-ASCII hex chars (see
	// buildReportData) so it survives the URL query round-trip losslessly.
	// url.Values.Encode percent-encodes as needed and net/http on the AA
	// side decodes back to the same 64 ASCII bytes.
	//
	// (api-server-rest also accepts `encoding=base64` — base64url — which
	// would avoid the ASCII-hex constraint and let us bind full 32-byte
	// hashes. Tracked follow-up: docs/009_eigenxSnpAttestation.md.)
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

// appPrivateKeyG1Bytes is the compressed size of a BLS12-381 G1 point — the
// exact length of a well-formed app_private_key.
const appPrivateKeyG1Bytes = 48

// emitAppPrivateKey validates a threshold-recovery result and returns the raw
// app_private_key (hex of its compressed G1 bytes) keyed by the sentinel. It is
// the root secret a signing daemon seeds from, so it is emitted only when it was
// validated against the master public key — never on the degraded (no-BFT-retry)
// path where a Byzantine operator could yield a corrupted key — and only when it
// has the exact G1 point length.
func emitAppPrivateKey(result *kmsClient.SecretsResult, appID string) (map[string]string, error) {
	if !result.Verified {
		return nil, fmt.Errorf("refusing to emit app_private_key for app %q: not verified against master public key (degraded recovery)", appID)
	}
	if len(result.AppPrivateKey.CompressedBytes) != appPrivateKeyG1Bytes {
		return nil, fmt.Errorf("KMS returned app_private_key of %d bytes for app %q, want %d", len(result.AppPrivateKey.CompressedBytes), appID, appPrivateKeyG1Bytes)
	}
	return map[string]string{
		appPrivateKeyKey: hex.EncodeToString(result.AppPrivateKey.CompressedBytes),
	}, nil
}

// assembleEnvFromSecrets IBE-decrypts each platform secret with the
// threshold-recovered app-private-key and returns the app's environment as a
// flat name→plaintext map. The IBE identity is the stackID (the ecloud CLI
// seals each value with EncryptForApp(stackID, master, …)), so the recovered
// key S·H(stackID) opens them. A value that fails to decrypt is a hard error:
// a sealed secret we cannot open is a real fault, not an empty value.
func assembleEnvFromSecrets(stackID string, appPrivateKey types.G1Point, secrets []stackSecret) (map[string]string, error) {
	env := make(map[string]string, len(secrets))
	for _, s := range secrets {
		plaintext, err := crypto.DecryptForApp(stackID, appPrivateKey, s.Value)
		if err != nil {
			return nil, fmt.Errorf("decrypt secret %q for stack %q: %w", s.Name, stackID, err)
		}
		env[s.Name] = string(plaintext)
	}
	return env, nil
}

// resolveEnv turns a recovered SecretsResult into the app's environment map.
// The secrets-fetch is injected so the sentinel/no-fetch path is unit-testable
// without a live KMS client or network. On the app_private_key sentinel it
// returns the raw key and never fetches; otherwise it fetches the stack's
// sealed secrets and IBE-decrypts each under the stackID identity.
func resolveEnv(
	req *Request,
	result *kmsClient.SecretsResult,
	fetch func(baseURL, apiKey, stackID string) ([]stackSecret, error),
) (map[string]string, error) {
	// Root-key request: emit the threshold-recovered app_private_key itself and
	// stop — it does not depend on the platform secrets, so return before the fetch.
	if req.Key == appPrivateKeyKey {
		return emitAppPrivateKey(result, req.StackID)
	}

	// Stack model: the KMS platform path returns ONLY the recovered
	// app-private-key (no env). Fetch the sealed secrets from the ecloud-platform
	// InternalSecretsService and IBE-decrypt each with the recovered key. The IBE
	// identity is the stackID (the ecloud CLI seals with EncryptForApp(stackID, …)).
	secrets, err := fetch(req.PlatformSecretsURL, req.PlatformInternalAPIKey, req.StackID)
	if err != nil {
		return nil, fmt.Errorf("fetch stack secrets: %w", err)
	}
	env, err := assembleEnvFromSecrets(req.StackID, result.AppPrivateKey, secrets)
	if err != nil {
		return nil, fmt.Errorf("assemble stack env for stack %q: %w", req.StackID, err)
	}
	return env, nil
}

// retrieveAndDecrypt drives operator discovery (on-chain or the single-operator
// shim) and the eigenx-snp secret-retrieval flow, then delegates to resolveEnv
// to turn the recovered app-private-key into the stack's environment map.
//
// In the stack model RetrieveSecretsWithOptions recovers only the AppPrivateKey;
// the environment is NOT carried in the KMS response. resolveEnv fetches the
// stack's sealed secrets from the ecloud-platform InternalSecretsService and
// IBE-decrypts each under the stackID identity, so the plaintext only ever
// exists inside this attested TEE. When the sentinel key (appPrivateKeyKey) is
// requested, resolveEnv returns the raw app_private_key and skips the fetch.
func retrieveAndDecrypt(
	req *Request,
	evidence, ccInitData, rsaPubPEM []byte,
	rsaPriv *rsa.PrivateKey,
) (map[string]string, error) {
	zapLogger, err := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	if err != nil {
		return nil, fmt.Errorf("create logger: %w", err)
	}

	// If kms_url is supplied, treat it as a single-operator override and skip
	// chain-based discovery entirely. This is the path used by the fakeKMS
	// shim during end-to-end testing of the eigenx-snp flow without standing
	// up Ethereum + IAppController. Production sealed envelopes leave kms_url
	// empty and discovery happens via the on-chain operator set.
	//
	// req.KMSURL reaches here only from cc_init_data (applyInitdataKMSConfig
	// overwrites it with the SNP-bound value; stdin can't win), so it's
	// already integrity-protected. Re-validate the scheme right at the
	// consumption site anyway — defense-in-depth so this remains an http(s)
	// POST target even if a future refactor changes how req.KMSURL is set,
	// closing any SSRF-to-IMDS (169.254.169.254) regression at the source.
	var contractCaller kmsClient.ContractCaller
	if strings.TrimSpace(req.KMSURL) != "" {
		if err := validateHTTPURL(req.KMSURL, "kms_url"); err != nil {
			return nil, err
		}
		contractCaller = newSingleOperatorContractCaller(req.KMSURL, req.OperatorAddress)
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
		StackID:           req.StackID, // selects the KMS platform path
	}

	result, err := client.RetrieveSecretsWithOptions(req.StackID, opts)
	if err != nil {
		return nil, fmt.Errorf("RetrieveSecretsWithOptions: %w", err)
	}

	return resolveEnv(req, result, fetchStackSecrets)
}

// aaSnpEvidence mirrors the AA-emitted SNP evidence shape. The Rust source
// is guest-components attestation-agent/attester/src/snp/mod.rs::SnpEvidence
// — serde-derive on sev::AttestationReport produces a nested JSON object
// whose field names are the struct's Rust field names (snake_case) and
// whose fixed-size byte arrays serialize as JSON arrays of integers.
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
	// Refuse Turin/Venice TCB layouts. virtee/sev's TcbVersion struct
	// only populates `fmc` (FMC fw version) on Turin/Venice — Milan/Genoa
	// leave it None. packLegacyTcb hard-codes the Milan/Genoa byte
	// layout (bootloader/tee at bytes 0,1; snp/microcode at 6,7); on
	// Turin the layout is different and silently mis-encoding it would
	// produce a `pb.Report` whose bytes don't match the AMD-signed
	// region, which fails verification with an opaque signature error.
	// Fail loud here instead. TODO(eigenx): generation-aware packing
	// when we boot Turin instances — see
	// docs/009_eigenxSnpAttestation.md ("Follow-up 2: Turin/Venice TCB
	// packing").
	if r.CurrentTcb.Fmc != nil || r.ReportedTcb.Fmc != nil ||
		r.CommittedTcb.Fmc != nil || r.LaunchTcb.Fmc != nil {
		return nil, fmt.Errorf("TCB version sets fmc — Turin/Venice not yet supported (only Milan/Genoa); see TODO(eigenx) in helper")
	}
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
// generation detection; we pin to the legacy form here because the
// supported hosts are Milan/Genoa. Turin/Venice hosts need generation-aware
// packing (as the Rust side does in TcbVersion::encode) — aaReportToProto
// fails loud on the Turin `fmc` field until then. See
// docs/009_eigenxSnpAttestation.md ("Follow-up 2").
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
