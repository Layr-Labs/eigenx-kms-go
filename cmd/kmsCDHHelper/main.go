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
	"time"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
)

// Request is the JSON payload read from stdin. KMSURL is reserved for forward
// compatibility — operator URLs are fetched from on-chain peering, not the
// caller. Keep the field so future versions can override without breaking the
// CDH plugin's wire shape.
type Request struct {
	KMSURL        string `json:"kms_url"`
	AVSAddress    string `json:"avs_address"`
	OperatorSetID uint32 `json:"operator_set_id"`
	RPCURL        string `json:"rpc_url"`
	AppID         string `json:"app_id"`
	CiphertextHex string `json:"ciphertext_hex"`
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

	// extraData is currently empty; reserved for the CDH plugin to bind extra
	// runtime context into the attestation nonce in a later revision.
	var extraData []byte
	reportData := buildReportData(rsaPubPEM, extraData, ccInitData)

	evidence, err := fetchAAEvidence(reportData)
	if err != nil {
		return fmt.Errorf("fetch AA evidence: %w", err)
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

// readRequest parses the stdin JSON request and validates required fields.
// kms_url is intentionally not validated — it's a forward-compat field.
func readRequest(r io.Reader) (*Request, error) {
	var req Request
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	if req.AVSAddress == "" {
		return nil, fmt.Errorf("avs_address is required")
	}
	if req.RPCURL == "" {
		return nil, fmt.Errorf("rpc_url is required")
	}
	if req.AppID == "" {
		return nil, fmt.Errorf("app_id is required")
	}
	if req.CiphertextHex == "" {
		return nil, fmt.Errorf("ciphertext_hex is required")
	}
	return &req, nil
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

// buildReportData composes the 64-byte SEV-SNP REPORT_DATA field:
//
//	lower 32 = SHA-256(rsaPubPEM || extraData)   -- nonce binding (mirrors KBS-EAR)
//	upper 32 = SHA-384(cc_init_data)[:32]        -- workload-identity binding
//
// Both halves are bound into the AMD-signed report so KMS operators can verify
// nonce freshness AND that the in-pod init-data matches what was attested.
func buildReportData(rsaPubPEM, extraData, ccInitData []byte) [reportDataLength]byte {
	nonceInput := make([]byte, 0, len(rsaPubPEM)+len(extraData))
	nonceInput = append(nonceInput, rsaPubPEM...)
	nonceInput = append(nonceInput, extraData...)
	lower := sha256.Sum256(nonceInput)

	upperFull := sha512.Sum384(ccInitData)

	var out [reportDataLength]byte
	copy(out[:32], lower[:])
	copy(out[32:], upperFull[:32])
	return out
}

// fetchAAEvidence calls the in-pod Attestation Agent at 127.0.0.1:8006 and
// returns the opaque raw-SNP evidence JSON bytes
// ({"attestation_report": ..., "cert_chain": ...}). The bytes are passed
// as-is into the KMS request — the wire encoding to base64 is handled by Go's
// []byte JSON marshalling.
func fetchAAEvidence(reportData [reportDataLength]byte) ([]byte, error) {
	runtimeData := base64.RawURLEncoding.EncodeToString(reportData[:])

	u, err := url.Parse(aaEvidenceURL)
	if err != nil {
		return nil, fmt.Errorf("parse AA URL: %w", err)
	}
	q := u.Query()
	q.Set("runtime_data", runtimeData)
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

	ethClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   req.RPCURL,
		BlockType: ethereum.BlockType_Latest,
	}, zapLogger)
	l1Client, err := ethClient.GetEthereumContractCaller()
	if err != nil {
		return nil, fmt.Errorf("get Ethereum contract caller: %w", err)
	}
	contractCaller, err := caller.NewContractCaller(l1Client, nil, zapLogger)
	if err != nil {
		return nil, fmt.Errorf("create contract caller: %w", err)
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
