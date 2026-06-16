// fakeKMS is a single-node KMS-compatible HTTP server for end-to-end testing
// of the eigenx-snp attestation flow without standing up a real threshold KMS
// cluster or registering apps on-chain.
//
// What's real:
//   - The full attestation pipeline (AMD chain validation, REPORT_DATA binding,
//     cc_init_data parsing) via pkg/attestation. Only the eigenx-snp method is
//     registered by default; flags can enable others.
//   - BLS-12-381 partial-signature math (HashToG1(appID)^s) and IBE encryption
//     for the master public key — same primitives, same code paths the
//     production KMS uses.
//   - RSA-2048 encryption-in-transit of partial signatures.
//
// What's faked:
//   - DKG. We hold a single BLS scalar `s` as both the master secret and "this
//     operator's share". Threshold = 1, Lagrange interpolation is trivially
//     identity, so the kmsClient on the helper side recovers the app private
//     key as H(appID)^s with no math change.
//   - Chain. Releases (image_digest, encrypted_env, etc.) come from a
//     TOML config file. There is no on-chain AppController lookup.
//   - Operator discovery. The kmsClient embedded in the helper expects
//     OperatorSetPeer entries from the chain; we don't ship that. The fake
//     binary expects to be addressed directly by URL via the existing
//     CONTRACT_CALLER_OVERRIDE-equivalent path... in practice, the helper
//     pointed at this fake will fail operator discovery. See README for the
//     workaround (a sibling fakePeering shim or pointing kms_url directly).
//
// Endpoints exposed (matching pkg/node/server.go wire format):
//
//	GET  /pubkey         — commitments + master public key
//	POST /secrets        — full attestation flow + encrypted partial sig + release
//	POST /app/sign       — partial signature for an app id
//	GET  /healthz        — liveness
//
// CLI:
//
//	fakeKMS \
//	  --port 8000 \
//	  --master-key-hex <64-hex BLS-12-381 scalar> \
//	  --apps-config /etc/fakekms/apps.toml \
//	  --operator-address 0x0000...01 \
//	  --enable-eigenx-snp-attestation
//
// Generate a master key with `fakeKMS gen-key` (writes hex to stdout), then
// IBE-encrypt the app's secret to it with `fakeKMS encrypt-env` and put the
// resulting hex in apps.toml's encrypted_env. The KMS serves that
// encrypted_env back in /secrets; the attested workload IBE-decrypts it with
// the threshold-recovered app_private_key (docs/references/new_kms.md).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/go-sev-guest/verify"
	tomlv2 "github.com/pelletier/go-toml/v2"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:        "fakeKMS",
		Usage:       "single-node KMS for eigenx-snp end-to-end testing",
		Description: "Implements /secrets, /pubkey, /app/sign matching the production KMS wire format. Real attestation, real BLS/IBE, faked chain + DKG.",
		Commands: []*cli.Command{
			{
				Name:  "gen-key",
				Usage: "Generate a fresh BLS-12-381 scalar (hex) suitable for --master-key-hex",
				Action: func(c *cli.Context) error {
					var s fr.Element
					if _, err := s.SetRandom(); err != nil {
						return fmt.Errorf("rand: %w", err)
					}
					b := s.Bytes()
					fmt.Println(hex.EncodeToString(b[:]))
					return nil
				},
			},
			{
				Name: "encrypt-env",
				Usage: "IBE-encrypt an app's secret env (a KEY=VALUE map) under the master key; " +
					"prints hex for apps.toml's encrypted_env. The plaintext is a JSON object so " +
					"the workload can address each variable by name (docs/references/new_kms.md).",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "master-key-hex", Required: true, Usage: "BLS-12-381 master scalar (hex)"},
					&cli.StringFlag{Name: "app-id", Required: true, Usage: "App ID the secret is encrypted to (IBE identity)"},
					&cli.StringSliceFlag{Name: "kv", Usage: "Secret env var as KEY=VALUE (repeatable)"},
				},
				Action: func(c *cli.Context) error {
					// Build the secret env map from repeated --kv KEY=VALUE flags.
					// The decrypted blob is a JSON {KEY:VALUE} object: the helper
					// indexes it by key so each sealed env var in the pod spec
					// resolves to one variable.
					env := map[string]string{}
					for _, kv := range c.StringSlice("kv") {
						k, v, ok := strings.Cut(kv, "=")
						if !ok || k == "" {
							return fmt.Errorf("invalid --kv %q: want KEY=VALUE", kv)
						}
						env[k] = v
					}
					if len(env) == 0 {
						return fmt.Errorf("at least one --kv KEY=VALUE is required")
					}
					plaintext, err := json.Marshal(env)
					if err != nil {
						return fmt.Errorf("marshal env: %w", err)
					}

					mb, err := hex.DecodeString(strings.TrimPrefix(c.String("master-key-hex"), "0x"))
					if err != nil {
						return fmt.Errorf("decode master-key-hex: %w", err)
					}
					var s fr.Element
					s.SetBytes(mb)
					if s.IsZero() {
						return fmt.Errorf("master key is zero")
					}
					mpk, err := crypto.ScalarMulG2(crypto.G2Generator, &s)
					if err != nil {
						return fmt.Errorf("derive master pubkey: %w", err)
					}
					ct, err := crypto.EncryptForApp(c.String("app-id"), *mpk, plaintext)
					if err != nil {
						return fmt.Errorf("EncryptForApp: %w", err)
					}
					// Hex — apps.toml's encrypted_env is surfaced verbatim and the
					// helper's decodeEncryptedEnv accepts hex.
					fmt.Println(hex.EncodeToString(ct))
					return nil
				},
			},
		},
		Flags: []cli.Flag{
			&cli.IntFlag{Name: "port", Value: 8000, Usage: "HTTP server port"},
			&cli.StringFlag{Name: "master-key-hex", Usage: "BLS-12-381 master scalar in hex (32 bytes / 64 chars). Use `fakeKMS gen-key` to mint one."},
			&cli.StringFlag{Name: "apps-config", Usage: "Path to apps.toml (release lookup table, see README)"},
			&cli.StringFlag{Name: "operator-address", Value: "0x0000000000000000000000000000000000000001", Usage: "Ethereum-shaped operator address advertised in /pubkey responses"},
			&cli.BoolFlag{Name: "enable-eigenx-snp-attestation", Value: true, Usage: "Register the eigenx-snp method (default true)"},
			&cli.BoolFlag{Name: "snp-allow-amd-kds-fetch", Value: false, Usage: "Allow go-sev-guest to fetch missing AMD intermediates from KDS at verify time. NEVER enable in production — opens a goroutine-flood DoS surface. Test-only flag for fakeKMS where the AA evidence may omit the ASVK."},
			&cli.StringSliceFlag{Name: "snp-measurement", Usage: "Accepted SEV-SNP MEASUREMENT (48-byte hex) to pin (firmware/vCPU-shape, not image). Repeatable; empty = not enforced."},
			&cli.BoolFlag{Name: "verbose", Usage: "Verbose / debug logging"},
		},
		Action: run,
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(c *cli.Context) error {
	logLevel := slog.LevelInfo
	if c.Bool("verbose") {
		logLevel = slog.LevelDebug
	}
	slogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	if c.String("master-key-hex") == "" {
		return fmt.Errorf("--master-key-hex is required (use `fakeKMS gen-key` to mint one)")
	}
	if c.String("apps-config") == "" {
		return fmt.Errorf("--apps-config is required")
	}

	// Parse master scalar.
	masterHex := strings.TrimPrefix(c.String("master-key-hex"), "0x")
	masterBytes, err := hex.DecodeString(masterHex)
	if err != nil {
		return fmt.Errorf("--master-key-hex: %w", err)
	}
	if len(masterBytes) != 32 {
		return fmt.Errorf("--master-key-hex must be 32 bytes (64 hex chars); got %d", len(masterBytes))
	}
	var masterScalar fr.Element
	masterScalar.SetBytes(masterBytes)
	if masterScalar.IsZero() {
		return fmt.Errorf("--master-key-hex must not be zero")
	}

	// Compute master public key = G2^s.
	masterPubKey, err := crypto.ScalarMulG2(crypto.G2Generator, &masterScalar)
	if err != nil {
		return fmt.Errorf("compute master pubkey: %w", err)
	}

	// Load apps config.
	appsCfg, err := loadAppsConfig(c.String("apps-config"))
	if err != nil {
		return fmt.Errorf("load apps config: %w", err)
	}

	// Build the attestation manager (real). Only register methods the operator
	// asked for. Default is just eigenx-snp.
	attestationManager := attestation.NewAttestationManager(slogger)
	if c.Bool("enable-eigenx-snp-attestation") {
		// Default to DisableCertFetching=true to match the production
		// constructor default (see pkg/attestation/eigenx_snp_method.go for the
		// goroutine-flood-DoS rationale). The fakeKMS smoke test flips it via
		// --snp-allow-amd-kds-fetch when the AA evidence omits the ASVK that
		// signs VLEKs — a real production deployment would either require AA
		// to ship the ASVK or run a KDS-fetching variant on a separate
		// rate-limited port.
		var snpOptions *verify.Options
		if c.Bool("snp-allow-amd-kds-fetch") {
			snpOptions = verify.DefaultOptions()
			snpOptions.DisableCertFetching = false
			slogger.Warn("AMD KDS cert fetching enabled — DO NOT use this in production")
		}
		method := attestation.NewEigenXSNPAttestationMethod(snpOptions, slogger)
		if msHex := c.StringSlice("snp-measurement"); len(msHex) > 0 {
			measurements := make([][]byte, 0, len(msHex))
			for _, h := range msHex {
				b, derr := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(h), "0x"))
				if derr != nil {
					return fmt.Errorf("invalid --snp-measurement %q: %w", h, derr)
				}
				measurements = append(measurements, b)
			}
			if serr := method.SetMeasurementAllowlist(measurements); serr != nil {
				return fmt.Errorf("set snp measurement allowlist: %w", serr)
			}
			slogger.Info("eigenx-snp MEASUREMENT pin enabled (firmware/vCPU-shape, not image)", "count", len(measurements))
		}
		if err := attestationManager.RegisterMethod(method); err != nil {
			return fmt.Errorf("register eigenx-snp: %w", err)
		}
	}
	if len(attestationManager.ListMethods()) == 0 {
		return fmt.Errorf("at least one attestation method must be enabled")
	}
	slogger.Info("attestation methods registered", "methods", attestationManager.ListMethods())

	srv := &server{
		logger:             slogger,
		masterScalar:       &masterScalar,
		masterPubKey:       *masterPubKey,
		operatorAddress:    common.HexToAddress(c.String("operator-address")),
		attestationManager: attestationManager,
		appsCfg:            appsCfg,
		rsa:                encryption.NewRSAEncryption(),
		bornAt:             time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/pubkey", srv.handlePubkey)
	mux.HandleFunc("/app/sign", srv.handleAppSign)
	mux.HandleFunc("/secrets", srv.handleSecrets)
	mux.HandleFunc("/healthz", srv.handleHealth)

	addr := fmt.Sprintf(":%d", c.Int("port"))
	slogger.Info("fakeKMS listening", "addr", addr, "operator", srv.operatorAddress.Hex(), "apps", len(appsCfg.Apps))
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return httpSrv.ListenAndServe()
}

// ----------------------------------------------------------------------------
// Apps config (TOML)
// ----------------------------------------------------------------------------

type appsConfig struct {
	Apps []appEntry `toml:"apps"`
	// indexed by app_id at load time for O(1) lookup
	index map[string]*appEntry
}

type appEntry struct {
	AppID         string            `toml:"app_id"`
	ImageDigest   string            `toml:"image_digest"`            // "sha256:<64hex>" — must match attestation claims
	Registry      string            `toml:"registry,omitempty"`      // OCI registry+repo (e.g. "ghcr.io/example/app"); when set, KMS step 4b binds claims.Registry to it
	EncryptedEnv  string            `toml:"encrypted_env,omitempty"` // hex IBE ciphertext (see `fakeKMS encrypt-env`) — surfaced verbatim in /secrets; the workload IBE-decrypts it with app_private_key
	PublicEnv     string            `toml:"public_env,omitempty"`    // JSON-shape — surfaced verbatim
	ContainerArgs []string          `toml:"container_args,omitempty"`
	Env           map[string]string `toml:"env,omitempty"`
	EnvOverride   map[string]string `toml:"env_override,omitempty"`
	RestartPolicy string            `toml:"restart_policy,omitempty"`
}

func (a *appEntry) toRelease() *types.Release {
	return &types.Release{
		ImageDigest:  a.ImageDigest,
		Registry:     a.Registry,
		EncryptedEnv: a.EncryptedEnv,
		PublicEnv:    a.PublicEnv,
		Timestamp:    time.Now().Unix(),
		ContainerPolicy: types.ContainerPolicy{
			Args:          a.ContainerArgs,
			Env:           a.Env,
			EnvOverride:   a.EnvOverride,
			RestartPolicy: a.RestartPolicy,
		},
	}
}

func loadAppsConfig(path string) (*appsConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg appsConfig
	if err := tomlv2.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse TOML: %w", err)
	}
	cfg.index = make(map[string]*appEntry, len(cfg.Apps))
	for i := range cfg.Apps {
		a := &cfg.Apps[i]
		if a.AppID == "" {
			return nil, fmt.Errorf("apps[%d]: app_id is required", i)
		}
		if !strings.HasPrefix(a.ImageDigest, "sha256:") || len(a.ImageDigest) != 7+64 {
			return nil, fmt.Errorf("apps[%d] (%s): image_digest must look like sha256:<64hex>", i, a.AppID)
		}
		cfg.index[a.AppID] = a
	}
	return &cfg, nil
}

func (a *appsConfig) lookup(appID string) (*appEntry, bool) {
	e, ok := a.index[appID]
	return e, ok
}

// ----------------------------------------------------------------------------
// Server
// ----------------------------------------------------------------------------

type server struct {
	logger             *slog.Logger
	masterScalar       *fr.Element
	masterPubKey       types.G2Point
	operatorAddress    common.Address
	attestationManager *attestation.AttestationManager
	appsCfg            *appsConfig
	rsa                *encryption.RSAEncryption
	bornAt             time.Time

	// JTI replay-cache (mirrors handleSecretsRequest behaviour for methods
	// that set claims.JTI). eigenx-snp leaves JTI empty so this is unused
	// in practice; kept for forward compatibility.
	jtiMu    sync.Mutex
	seenJTIs map[string]int64
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *server) handlePubkey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Threshold-1 single-share polynomial: the only commitment is the master
	// public key itself. The kmsClient's threshold-vote on /pubkey responses
	// is satisfied because there's only one operator.
	resp := map[string]interface{}{
		"operatorAddress": s.operatorAddress.Hex(),
		"commitments":     []types.G2Point{s.masterPubKey},
		"masterPublicKey": &s.masterPubKey,
		"version":         s.bornAt.Unix(),
		"isActive":        true,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *server) handleAppSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req types.AppSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "failed to parse request", http.StatusBadRequest)
		return
	}
	if req.AppID == "" {
		http.Error(w, "app_id is required", http.StatusBadRequest)
		return
	}
	partial, err := s.partialSign(req.AppID)
	if err != nil {
		s.logger.Error("partial sign failed", "app_id", req.AppID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := types.AppSignResponse{
		OperatorAddress:  s.operatorAddress.Hex(),
		PartialSignature: *partial,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req types.SecretsRequestV1
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}
	if req.AppID == "" {
		http.Error(w, "app_id is required", http.StatusBadRequest)
		return
	}
	if len(req.RSAPubKeyTmp) == 0 || len(req.RSAPubKeyTmp) > 8192 {
		http.Error(w, "rsa_pubkey_tmp invalid", http.StatusBadRequest)
		return
	}
	if len(req.ExtraData) > types.MaxExtraDataSize {
		http.Error(w, "extra_data too large", http.StatusBadRequest)
		return
	}
	if len(req.CCInitData) > types.MaxExtraDataSize {
		http.Error(w, "cc_init_data too large", http.StatusBadRequest)
		return
	}
	if len(req.Attestation) > types.MaxAttestationSize {
		http.Error(w, "attestation too large", http.StatusBadRequest)
		return
	}
	if req.AttestationMethod == "" {
		http.Error(w, "attestation_method is required", http.StatusBadRequest)
		return
	}

	// 1) Verify attestation (real path).
	attReq := &attestation.AttestationRequest{
		Method:       req.AttestationMethod,
		AppID:        req.AppID,
		Attestation:  req.Attestation,
		Challenge:    req.Challenge,
		PublicKey:    req.PublicKey,
		RSAPubKeyTmp: req.RSAPubKeyTmp,
		ExtraData:    req.ExtraData,
		CCInitData:   req.CCInitData,
	}
	claims, err := s.attestationManager.VerifyWithMethod(req.AttestationMethod, attReq)
	if err != nil {
		s.logger.Warn("attestation verification failed", "app_id", req.AppID, "method", req.AttestationMethod, "error", err)
		http.Error(w, fmt.Sprintf("invalid attestation: %v", err), http.StatusUnauthorized)
		return
	}
	if claims.AppID != req.AppID {
		http.Error(w, "app_id mismatch", http.StatusForbidden)
		return
	}

	// 2) JTI replay protection (no-op for eigenx-snp).
	if claims.JTI != "" && !s.checkJTI(claims.JTI, claims.ExpiresAt) {
		http.Error(w, "attestation already used", http.StatusUnauthorized)
		return
	}

	// 3) "Chain" lookup — really a TOML lookup.
	entry, ok := s.appsCfg.lookup(req.AppID)
	if !ok {
		http.Error(w, "release not found", http.StatusNotFound)
		return
	}
	release := entry.toRelease()

	// 4) Image digest binding.
	if claims.ImageDigest != release.ImageDigest {
		s.logger.Warn("image digest mismatch", "app_id", req.AppID, "expected", release.ImageDigest, "got", claims.ImageDigest)
		http.Error(w, "image digest mismatch", http.StatusForbidden)
		return
	}

	// 4b) Registry binding — mirrors pkg/node/handlers.go step 4b.
	// Fail open when either side is empty (older releases pre-Registry,
	// or attestation methods that don't surface registry); enforce when
	// both are set.
	if claims.Registry != "" && release.Registry != "" && claims.Registry != release.Registry {
		s.logger.Warn("registry mismatch", "app_id", req.AppID, "expected", release.Registry, "got", claims.Registry)
		http.Error(w, "registry mismatch", http.StatusForbidden)
		return
	}

	// 5) Partial signature for the app id (= H(appID)^s).
	partial, err := s.partialSign(req.AppID)
	if err != nil {
		s.logger.Error("partial sign failed", "app_id", req.AppID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	partialBytes, err := json.Marshal(partial)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	encryptedPartial, err := s.rsa.Encrypt(partialBytes, req.RSAPubKeyTmp)
	if err != nil {
		s.logger.Error("rsa encrypt failed", "app_id", req.AppID, "error", err)
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}

	resp := types.SecretsResponseV1{
		EncryptedEnv:        release.EncryptedEnv,
		PublicEnv:           release.PublicEnv,
		EncryptedPartialSig: encryptedPartial,
		ExtraData:           req.ExtraData,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
	s.logger.Info("served secrets", "app_id", req.AppID, "method", req.AttestationMethod)
}

// partialSign computes H(appID)^s, the partial signature this single-node
// "operator" contributes. Threshold = 1, so this *is* the recovered app
// private key after Lagrange interpolation on the kmsClient side.
func (s *server) partialSign(appID string) (*types.G1Point, error) {
	qID, err := crypto.HashToG1(appID)
	if err != nil {
		return nil, fmt.Errorf("hash to G1: %w", err)
	}
	return crypto.ScalarMulG1(*qID, s.masterScalar)
}

func (s *server) checkJTI(jti string, exp int64) bool {
	s.jtiMu.Lock()
	defer s.jtiMu.Unlock()
	if s.seenJTIs == nil {
		s.seenJTIs = make(map[string]int64)
	}
	now := time.Now().Unix()
	// Evict expired.
	for k, e := range s.seenJTIs {
		if e > 0 && e < now {
			delete(s.seenJTIs, k)
		}
	}
	if _, seen := s.seenJTIs[jti]; seen {
		return false
	}
	s.seenJTIs[jti] = exp
	return true
}

// silence unused import warning during partial scaffolding
var _ = rand.Reader
