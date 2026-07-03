# Owner-bound ECDSA Attestation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On the `/secrets` ECDSA path, require the attestation signer to be the app's on-chain creator and stop requiring an on-chain release (best-effort env, always return the share).

**Architecture:** Branch `handleSecretsRequest` by attestation method. ECDSA runs a new `verifyECDSAOwnership` check (signer derived from the already-verified `claims.PublicKey`, compared to `GetAppCreator(appID)`) then resolves the release best-effort (empty env if absent) and skips digest/registry/container-policy. All non-ECDSA methods keep today's flow exactly. The shared signing tail (key version → sign → RSA-encrypt → respond) is unchanged.

**Tech Stack:** Go, go-ethereum `crypto` (secp256k1 pubkey→address) + `common`, `net/http`, existing `pkg/node` test harness (`StubECDSAMethod`, `TestableContractCallerStub`).

## Global Constraints

- Server-side change only: `pkg/node/handlers.go` + `pkg/contractCaller/testhelpers.go` (test hook) + `cmd/kmsClient/README.md` (doc). Do NOT modify `pkg/attestation/ecdsa.go`.
- Stays on branch `feat/kmsclient-ecdsa-attestation`.
- ECDSA ownership rule: signer address (`ethcrypto.PubkeyToAddress(UnmarshalPubkey(claims.PublicKey))`) must `==` `GetAppCreator(common.HexToAddress(appID))`. Single-address EOA compare.
- ECDSA `appID` must be a valid hex contract address (`common.IsHexAddress`).
- ECDSA path: NO digest / registry / container-policy checks; release is best-effort (missing release ⇒ empty env, still serve the share).
- Non-ECDSA methods (gcp/intel/tpm/eigenx-snp) remain unchanged — release required, digest/registry/policy enforced.
- HTTP statuses (ECDSA): bad appID → 400; bad pubkey → 400; `GetAppCreator` failure → 502; signer≠creator → 403; success → 200.
- Run tests via `./scripts/goTest.sh ./pkg/node/ ...` and `./scripts/goTest.sh ./pkg/contractCaller/ ...` (NOT `go test` directly). The script starts web3signer docker containers then forwards args to `go test -timeout 10m`.
- Commits must NOT include any `Co-Authored-By` trailer.
- go-ethereum `crypto` is imported aliased as `ethcrypto`.

## Verified facts

- `StubECDSAMethod.Verify` (`pkg/attestation/testhelpers.go:64-72`) copies `request.PublicKey` straight into `claims.PublicKey`. Tests therefore control the signer by setting `req.PublicKey` to the creator's (or a wrong) secp256k1 public key bytes. No stub change required.
- `TestableContractCallerStub` embeds `MockContractCallerStub.GetAppCreator` which returns the zero address; it needs a configurable creator (Task 1).
- `claims.AppID == req.AppID` is already enforced before the branch point (`handlers.go:170`).
- `signAppIDWithVersion(appID, keyVersion)` derives the share from the appID string only — no release needed.
- Existing happy-path test pattern: `testSecretsEndpointFlow` (`secrets_test.go:159`) — copy its RSA-keypair + request-build + response-decode shape.

---

## File Structure

- `pkg/contractCaller/testhelpers.go` — Modify: add a configurable `creators` map, `SetAppCreator`, and a `GetAppCreator` override to `TestableContractCallerStub`.
- `pkg/node/handlers.go` — Modify: add `ethcrypto` import; add `verifyECDSAOwnership` helper; branch `handleSecretsRequest` so ECDSA uses ownership + best-effort env and skips digest/registry/policy.
- `pkg/node/secrets_test.go` — Modify: add ECDSA subtests (success-with-env, success-no-release, success-empty-env, wrong-signer-403, bad-appID-400, bad-pubkey-400) and a non-ECDSA "release still required" regression guard. Register the new subtests in `Test_SecretsEndpoint`.
- `cmd/kmsClient/README.md` — Modify: ECDSA key must be the app creator's key; attested path no longer needs a release.

---

### Task 1: Configurable app creator in the test stub

**Files:**
- Modify: `pkg/contractCaller/testhelpers.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `func (m *TestableContractCallerStub) SetAppCreator(app common.Address, creator common.Address)`
  - `func (m *TestableContractCallerStub) GetAppCreator(app common.Address, opts *bind.CallOpts) (common.Address, error)` — returns the configured creator, or zero address if unset (never errors).

- [ ] **Step 1: Add a unit test for the stub creator hook**

Append to `pkg/contractCaller/testhelpers.go`'s package a new test file is overkill; instead add this test to a new file `pkg/contractCaller/testhelpers_creator_test.go`:

```go
package contractCaller

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestTestableStubGetAppCreator(t *testing.T) {
	stub := NewTestableContractCallerStub()
	app := common.HexToAddress("0xD36193599084B7d905fD40A436A0588d945e8299")
	creator := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Unset → zero address, no error.
	got, err := stub.GetAppCreator(app, nil)
	require.NoError(t, err)
	require.Equal(t, common.Address{}, got)

	// After SetAppCreator → returns it (case-insensitive key).
	stub.SetAppCreator(app, creator)
	got, err = stub.GetAppCreator(app, nil)
	require.NoError(t, err)
	require.Equal(t, creator, got)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./scripts/goTest.sh ./pkg/contractCaller/ -run TestTestableStubGetAppCreator -v`
Expected: FAIL — the embedded `MockContractCallerStub.GetAppCreator` returns the zero address even after `SetAppCreator` (which doesn't exist yet → compile error `stub.SetAppCreator undefined`).

- [ ] **Step 3: Implement the creator hook**

In `pkg/contractCaller/testhelpers.go`, add a `creators` field to the struct, initialize it, and add the two methods.

Change the struct definition:

```go
type TestableContractCallerStub struct {
	MockContractCallerStub
	releases        map[string]*types.Release // confirmed (active) releases
	pendingReleases map[string]*types.Release // pending releases awaiting confirmation
	creators        map[common.Address]common.Address // configured app creators
	mu              sync.RWMutex
}
```

Change the constructor:

```go
func NewTestableContractCallerStub() *TestableContractCallerStub {
	return &TestableContractCallerStub{
		releases:        make(map[string]*types.Release),
		pendingReleases: make(map[string]*types.Release),
		creators:        make(map[common.Address]common.Address),
	}
}
```

Add the two methods (place them after `ConfirmUpgrade`):

```go
// SetAppCreator configures the on-chain creator returned by GetAppCreator for
// a given app address. Used to drive ECDSA ownership-binding tests.
func (m *TestableContractCallerStub) SetAppCreator(app common.Address, creator common.Address) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creators[app] = creator
}

// GetAppCreator returns the configured creator for an app, or the zero address
// if none was set. It never errors — release lookups and creator lookups are
// independent in tests.
func (m *TestableContractCallerStub) GetAppCreator(app common.Address, opts *bind.CallOpts) (common.Address, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.creators[app], nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./scripts/goTest.sh ./pkg/contractCaller/ -run TestTestableStubGetAppCreator -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/contractCaller/testhelpers.go pkg/contractCaller/testhelpers_creator_test.go
git commit -m "test(contractCaller): add configurable app creator to testable stub"
```

---

### Task 2: ECDSA ownership binding + best-effort env in the handler

**Files:**
- Modify: `pkg/node/handlers.go`
- Modify: `pkg/node/secrets_test.go`

**Interfaces:**
- Consumes: `TestableContractCallerStub.SetAppCreator` (Task 1); `StubECDSAMethod` echoing `req.PublicKey` into claims.
- Produces:
  - `func (s *Server) verifyECDSAOwnership(appID string, publicKey []byte) (int, error)` — returns `(httpStatus, error)`; `(0, nil)` on success. The status lets the caller `http.Error` with the right code.
  - ECDSA branch in `handleSecretsRequest` that uses `verifyECDSAOwnership` + best-effort release and skips digest/registry/policy.

- [ ] **Step 1: Write the failing ECDSA handler tests**

Add the following helper + subtests to `pkg/node/secrets_test.go`. The helper builds a real secp256k1 keypair so the signer address is deterministic, sets it as the app creator, and posts an ECDSA `/secrets` request. (Imports needed in the file: add `ethcrypto "github.com/ethereum/go-ethereum/crypto"` to the import block — `common`, `bytes`, `encoding/json`, `net/http`, `net/http/httptest`, `time`, `kmsTypes`, `encryption` are already imported.)

```go
// ecdsaSecretsCase posts an ECDSA /secrets request for appAddr, signing identity
// derived from creatorPubKey. signerIsCreator controls whether the configured
// on-chain creator matches the request's public key.
type ecdsaSecretsResult struct {
	code int
	resp kmsTypes.SecretsResponseV1
	body string
}

func postECDSASecrets(t *testing.T, f *testSecretsFixture, appID string, pubKey []byte) ecdsaSecretsResult {
	t.Helper()

	_, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	req := kmsTypes.SecretsRequestV1{
		AppID:             appID,
		AttestationMethod: "ecdsa",
		Attestation:       []byte("sig-placeholder"), // StubECDSAMethod ignores it
		PublicKey:         pubKey,
		RSAPubKeyTmp:      pubKeyPEM,
		AttestationTime:   time.Now().Unix(),
	}
	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.server.handleSecretsRequest(w, httpReq)

	out := ecdsaSecretsResult{code: w.Code, body: w.Body.String()}
	if w.Code == http.StatusOK {
		if err := json.NewDecoder(w.Body).Decode(&out.resp); err != nil {
			t.Fatalf("Failed to decode 200 response: %v", err)
		}
	}
	return out
}

func testSecretsECDSAOwnerWithEnv(t *testing.T) {
	f := newTestSecretsFixture(t)
	appAddr := common.HexToAddress("0x00000000000000000000000000000000000000a1")

	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubKey := ethcrypto.FromECDSAPub(&key.PublicKey)
	f.contractCallerStub.SetAppCreator(appAddr, ethcrypto.PubkeyToAddress(key.PublicKey))

	f.contractCallerStub.AddTestRelease(appAddr.Hex(), &kmsTypes.Release{
		ImageDigest:  "sha256:whatever",
		EncryptedEnv: "enc-env-xyz",
		PublicEnv:    "PUB=1",
		Timestamp:    time.Now().Unix(),
	})

	got := postECDSASecrets(t, f, appAddr.Hex(), pubKey)
	if got.code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", got.code, got.body)
	}
	if got.resp.EncryptedEnv != "enc-env-xyz" || got.resp.PublicEnv != "PUB=1" {
		t.Errorf("expected release env echoed, got enc=%q pub=%q", got.resp.EncryptedEnv, got.resp.PublicEnv)
	}
	if len(got.resp.EncryptedPartialSig) == 0 {
		t.Error("expected non-empty partial signature")
	}
}

func testSecretsECDSAOwnerNoRelease(t *testing.T) {
	f := newTestSecretsFixture(t)
	appAddr := common.HexToAddress("0x00000000000000000000000000000000000000a2")

	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubKey := ethcrypto.FromECDSAPub(&key.PublicKey)
	f.contractCallerStub.SetAppCreator(appAddr, ethcrypto.PubkeyToAddress(key.PublicKey))
	// No release added.

	got := postECDSASecrets(t, f, appAddr.Hex(), pubKey)
	if got.code != http.StatusOK {
		t.Fatalf("expected 200 (no release should NOT 404 for ecdsa), got %d body=%s", got.code, got.body)
	}
	if got.resp.EncryptedEnv != "" || got.resp.PublicEnv != "" {
		t.Errorf("expected empty env, got enc=%q pub=%q", got.resp.EncryptedEnv, got.resp.PublicEnv)
	}
	if len(got.resp.EncryptedPartialSig) == 0 {
		t.Error("expected non-empty partial signature even with no release")
	}
}

func testSecretsECDSAOwnerEmptyEnvRelease(t *testing.T) {
	f := newTestSecretsFixture(t)
	appAddr := common.HexToAddress("0x00000000000000000000000000000000000000a3")

	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubKey := ethcrypto.FromECDSAPub(&key.PublicKey)
	f.contractCallerStub.SetAppCreator(appAddr, ethcrypto.PubkeyToAddress(key.PublicKey))
	f.contractCallerStub.AddTestRelease(appAddr.Hex(), &kmsTypes.Release{
		ImageDigest: "sha256:whatever",
		Timestamp:   time.Now().Unix(),
		// env fields empty
	})

	got := postECDSASecrets(t, f, appAddr.Hex(), pubKey)
	if got.code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", got.code, got.body)
	}
	if got.resp.EncryptedEnv != "" || got.resp.PublicEnv != "" {
		t.Errorf("expected empty env, got enc=%q pub=%q", got.resp.EncryptedEnv, got.resp.PublicEnv)
	}
	if len(got.resp.EncryptedPartialSig) == 0 {
		t.Error("expected non-empty partial signature")
	}
}

func testSecretsECDSAWrongSigner(t *testing.T) {
	f := newTestSecretsFixture(t)
	appAddr := common.HexToAddress("0x00000000000000000000000000000000000000a4")

	// Creator is one key; the request is signed by a DIFFERENT key.
	creatorKey, _ := ethcrypto.GenerateKey()
	f.contractCallerStub.SetAppCreator(appAddr, ethcrypto.PubkeyToAddress(creatorKey.PublicKey))

	wrongKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	wrongPub := ethcrypto.FromECDSAPub(&wrongKey.PublicKey)

	got := postECDSASecrets(t, f, appAddr.Hex(), wrongPub)
	if got.code != http.StatusForbidden {
		t.Fatalf("expected 403 for wrong signer, got %d body=%s", got.code, got.body)
	}
	if !strings.Contains(got.body, "not the app creator") {
		t.Errorf("expected 'not the app creator' message, got %q", got.body)
	}
}

func testSecretsECDSAAppIDNotAddress(t *testing.T) {
	f := newTestSecretsFixture(t)
	key, _ := ethcrypto.GenerateKey()
	pubKey := ethcrypto.FromECDSAPub(&key.PublicKey)

	got := postECDSASecrets(t, f, "not-an-address", pubKey)
	if got.code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-address appID, got %d body=%s", got.code, got.body)
	}
	if !strings.Contains(got.body, "contract address") {
		t.Errorf("expected 'contract address' message, got %q", got.body)
	}
}

func testSecretsECDSABadPubKey(t *testing.T) {
	f := newTestSecretsFixture(t)
	appAddr := common.HexToAddress("0x00000000000000000000000000000000000000a5")
	f.contractCallerStub.SetAppCreator(appAddr, common.HexToAddress("0x00000000000000000000000000000000000000ff"))

	got := postECDSASecrets(t, f, appAddr.Hex(), []byte{0x01, 0x02, 0x03}) // not a valid pubkey
	if got.code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad pubkey, got %d body=%s", got.code, got.body)
	}
	if !strings.Contains(got.body, "public key") {
		t.Errorf("expected 'public key' message, got %q", got.body)
	}
}

func testSecretsNonECDSAStillRequiresRelease(t *testing.T) {
	// Regression guard: gcp method with NO release must still 404 — the
	// release requirement is intact for non-ECDSA methods.
	f := newTestSecretsFixture(t)
	_, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	h := sha256.Sum256(pubKeyPEM)
	claims := kmsTypes.AttestationClaims{
		AppID:       "no-release-app",
		ImageDigest: "sha256:test123",
		IssuedAt:    time.Now().Unix(),
		PublicKey:   pubKeyPEM,
		Nonce:       hex.EncodeToString(h[:]),
	}
	attBytes, _ := json.Marshal(claims)
	req := kmsTypes.SecretsRequestV1{
		AppID:             "no-release-app",
		AttestationMethod: "gcp",
		Attestation:       attBytes,
		RSAPubKeyTmp:      pubKeyPEM,
		AttestationTime:   time.Now().Unix(),
	}
	reqBody, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()
	f.server.handleSecretsRequest(w, httpReq)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for gcp with no release, got %d body=%s", w.Code, w.Body.String())
	}
}
```

Register the subtests in `Test_SecretsEndpoint` (add these lines to the existing `t.Run(...)` list):

```go
	t.Run("ECDSAOwnerWithEnv", func(t *testing.T) { testSecretsECDSAOwnerWithEnv(t) })
	t.Run("ECDSAOwnerNoRelease", func(t *testing.T) { testSecretsECDSAOwnerNoRelease(t) })
	t.Run("ECDSAOwnerEmptyEnvRelease", func(t *testing.T) { testSecretsECDSAOwnerEmptyEnvRelease(t) })
	t.Run("ECDSAWrongSigner", func(t *testing.T) { testSecretsECDSAWrongSigner(t) })
	t.Run("ECDSAAppIDNotAddress", func(t *testing.T) { testSecretsECDSAAppIDNotAddress(t) })
	t.Run("ECDSABadPubKey", func(t *testing.T) { testSecretsECDSABadPubKey(t) })
	t.Run("NonECDSAStillRequiresRelease", func(t *testing.T) { testSecretsNonECDSAStillRequiresRelease(t) })
```

Also ensure the import block of `secrets_test.go` includes `ethcrypto "github.com/ethereum/go-ethereum/crypto"` and `"strings"` (strings is already imported per the file header; add ethcrypto).

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `./scripts/goTest.sh ./pkg/node/ -run 'Test_SecretsEndpoint/ECDSA|Test_SecretsEndpoint/NonECDSAStillRequiresRelease' -v`
Expected: FAIL. Today the ECDSA path has no ownership check and requires a release: `ECDSAOwnerNoRelease` gets 404 (not 200), `ECDSAWrongSigner` does not 403, `ECDSAAppIDNotAddress`/`ECDSABadPubKey` do not 400. (The `NonECDSAStillRequiresRelease` guard already passes — that's fine; it must still pass after the change.)

- [ ] **Step 3: Add the `ethcrypto` import to the handler**

In `pkg/node/handlers.go`, update the import block to add the go-ethereum crypto alias:

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)
```

- [ ] **Step 4: Add the `verifyECDSAOwnership` helper**

In `pkg/node/handlers.go`, add this method (place it just above `handleSecretsRequest`):

```go
// verifyECDSAOwnership confirms the ECDSA attestation signer controls the app's
// on-chain creator key. The appID for ECDSA must be an app contract address;
// the signer is derived from the already-verified attestation public key and
// compared to GetAppCreator(appID). Returns (httpStatus, error); (0, nil) on
// success.
func (s *Server) verifyECDSAOwnership(appID string, publicKey []byte) (int, error) {
	if !common.IsHexAddress(appID) {
		return http.StatusBadRequest, fmt.Errorf("app_id must be a contract address for ecdsa attestation")
	}
	pub, err := ethcrypto.UnmarshalPubkey(publicKey)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid ecdsa public key: %w", err)
	}
	signer := ethcrypto.PubkeyToAddress(*pub)

	creator, err := s.node.baseContractCaller.GetAppCreator(common.HexToAddress(appID), nil)
	if err != nil {
		return http.StatusBadGateway, fmt.Errorf("failed to look up app creator: %w", err)
	}
	if signer != creator {
		return http.StatusForbidden, fmt.Errorf("ecdsa signer is not the app creator")
	}
	return 0, nil
}
```

- [ ] **Step 5: Branch the handler so ECDSA uses ownership + best-effort env**

In `pkg/node/handlers.go`, replace the existing Step 3-5 block (the on-chain release fetch through the container-policy check — currently lines ~192-255, beginning with the comment `// Step 3: Query latest release from on-chain AppController` and ending after the `validateContainerPolicy` block) with a method branch.

The replacement:

```go
	// Step 3: Resolve the release and run method-specific authorization.
	//
	// ECDSA is a lightweight ownership-proof method for testing: it binds to the
	// app's on-chain creator and does NOT depend on a release (best-effort env,
	// no digest/registry/container-policy checks). All other methods keep the
	// full release + image-digest + registry + container-policy enforcement.
	var release *types.Release
	if req.AttestationMethod == "ecdsa" {
		if status, ownErr := s.verifyECDSAOwnership(req.AppID, claims.PublicKey); ownErr != nil {
			s.node.logger.Sugar().Warnw("ECDSA ownership check failed",
				"operator_address", s.node.OperatorAddress.Hex(),
				"app_id", req.AppID,
				"error", ownErr)
			http.Error(w, ownErr.Error(), status)
			return
		}

		// Best-effort env: a missing release is fine for ECDSA — serve the share
		// with empty env. A present release contributes its env.
		release, err = s.node.baseContractCaller.GetLatestReleaseAsRelease(r.Context(), req.AppID)
		if err != nil {
			s.node.logger.Sugar().Infow("No release for ecdsa app; serving share with empty env",
				"operator_address", s.node.OperatorAddress.Hex(),
				"app_id", req.AppID)
			release = &types.Release{}
		}
	} else {
		// Query latest release from on-chain AppController
		release, err = s.node.baseContractCaller.GetLatestReleaseAsRelease(r.Context(), req.AppID)
		if err != nil {
			s.node.logger.Sugar().Warnw("Failed to get release", "operator_address", s.node.OperatorAddress.Hex(), "app_id", req.AppID, "error", err)
			http.Error(w, "Release not found", http.StatusNotFound)
			return
		}

		// Verify image digest matches.
		if claims.ImageDigest != release.ImageDigest {
			s.node.logger.Sugar().Warnw("Image digest mismatch", "operator_address", s.node.OperatorAddress.Hex(), "app_id", req.AppID, "expected", release.ImageDigest, "got", claims.ImageDigest)
			http.Error(w, "Image digest mismatch - unauthorized image", http.StatusForbidden)
			return
		}

		// Verify registry matches when claims surface one.
		if claims.Registry != "" && release.Registry != "" && claims.Registry != release.Registry {
			s.node.logger.Sugar().Warnw("Registry mismatch",
				"operator_address", s.node.OperatorAddress.Hex(),
				"app_id", req.AppID,
				"expected", release.Registry, "got", claims.Registry)
			http.Error(w, "Registry mismatch - unauthorized image source", http.StatusForbidden)
			return
		}

		// Verify container execution policy matches on-chain values.
		// eigenx-snp does not surface ContainerPolicy in claims; fail closed if a
		// release pins one (see docs/009_eigenxSnpAttestation.md).
		if req.AttestationMethod == "eigenx-snp" && hasContainerPolicy(release.ContainerPolicy) {
			s.node.logger.Sugar().Warnw(
				"refusing eigenx-snp request: release pins ContainerPolicy that this method does not yet surface in claims",
				"operator_address", s.node.OperatorAddress.Hex(),
				"app_id", req.AppID,
			)
			http.Error(w, "eigenx-snp attestation does not yet enforce ContainerPolicy; release requires it", http.StatusForbidden)
			return
		}
		if err := validateContainerPolicy(claims.ContainerPolicy, release.ContainerPolicy); err != nil {
			s.node.logger.Sugar().Warnw("Container policy mismatch", "operator_address", s.node.OperatorAddress.Hex(), "app_id", req.AppID, "error", err)
			http.Error(w, "Container policy mismatch", http.StatusForbidden)
			return
		}
	}
```

Note: this preserves every non-ECDSA check verbatim (digest, registry, eigenx-snp container-policy fail-closed, `validateContainerPolicy`) — it only moves them into the `else` branch. The comment block that previously documented registry/container-policy reasoning is condensed; the behavior is identical. The shared tail (Step 6 key version → Step 10 respond) that follows is unchanged and already reads `release.EncryptedEnv` / `release.PublicEnv`, which are empty strings for the ECDSA no-release case.

- [ ] **Step 6: Run the new tests to verify they pass**

Run: `./scripts/goTest.sh ./pkg/node/ -run 'Test_SecretsEndpoint/ECDSA|Test_SecretsEndpoint/NonECDSAStillRequiresRelease' -v`
Expected: PASS — all six ECDSA subtests and the non-ECDSA regression guard green.

- [ ] **Step 7: Run the full secrets + node suite to confirm no regression**

Run: `./scripts/goTest.sh ./pkg/node/ -run Test_SecretsEndpoint -v`
Expected: PASS — all existing subtests (Flow, Validation, ImageDigestMismatch, RegistryMismatch, AppIDMismatch, JTIReplay, ContainerPolicy*, TwoPhaseUpgrade, Allowlist*, ExtraData*) plus the new ECDSA ones.

- [ ] **Step 8: Vet and commit**

Run: `go vet ./pkg/node/` (expect `VET OK`, no output)

```bash
git add pkg/node/handlers.go pkg/node/secrets_test.go
git commit -m "feat(node): bind ecdsa /secrets to app creator and drop release requirement"
```

---

### Task 3: Document the ownership requirement

**Files:**
- Modify: `cmd/kmsClient/README.md`

**Interfaces:**
- Consumes: behavior from Task 2.
- Produces: docs only.

- [ ] **Step 1: Update the ECDSA security caveat**

In `cmd/kmsClient/README.md`, find the existing ECDSA "Security caveat" paragraph (in the "Decrypt Data with ECDSA Attestation" section). Replace the sentence that currently reads:

```markdown
private key and the freshness of the challenge. It does **not** prove a TEE
execution environment, and the operator does not bind the ECDSA address to the
application ID. The recovered application key is derived solely from the
application ID, so it is identical regardless of which ECDSA key is presented.
```

with:

```markdown
private key and the freshness of the challenge. It does **not** prove a TEE
execution environment. The operator binds the ECDSA signer to the app's on-chain
**creator**: the `--ecdsa-private-key` / `--ecdsa-private-key-file` you supply
MUST be the key of the EOA that deployed/created the app, or the request is
rejected with `ecdsa signer is not the app creator`. The attested ECDSA path
does not require an on-chain release; it returns the app's environment only if a
release exists, and otherwise returns empty env alongside the recovered key.
```

- [ ] **Step 2: Update the prerequisites bullet**

In the same section, the "Prerequisites for the attested path" list currently includes a bullet saying the application must exist on-chain because the operator fetches the release. Replace that bullet:

```markdown
- The application must exist on-chain — the operator fetches the app's release
  while serving the request.
```

with:

```markdown
- The app must exist on-chain so the operator can look up its creator. For ECDSA
  specifically, a published release is **not** required (env is returned only if
  a release exists); the signing key must belong to the app's creator.
```

- [ ] **Step 3: Verify and commit**

Run: `grep -n "app creator\|creator\|release" cmd/kmsClient/README.md | head`
Expected: the new "creator" wording appears in the ECDSA section.

```bash
git add cmd/kmsClient/README.md
git commit -m "docs(kmsClient): ecdsa key must be the app creator; release optional"
```

---

## Self-Review

**Spec coverage:**
- Ownership binding (signer == `GetAppCreator`) → Task 2 `verifyECDSAOwnership` + `ECDSAWrongSigner`/`ECDSAOwnerWithEnv` tests. ✓
- Signer derived from verified `claims.PublicKey` → Task 2 Step 4 (`UnmarshalPubkey`/`PubkeyToAddress`). ✓
- appID must be a hex address → Task 2 helper + `ECDSAAppIDNotAddress` test (400). ✓
- Bad public key → 400 → helper + `ECDSABadPubKey` test. ✓
- `GetAppCreator` failure → 502 → helper (no dedicated test; stub never errors — documented, acceptable). ✓
- Drop release requirement for ECDSA (no 404) → Task 2 branch + `ECDSAOwnerNoRelease` test. ✓
- Best-effort env (release env if present, else empty) → `ECDSAOwnerWithEnv` + `ECDSAOwnerEmptyEnvRelease` + `ECDSAOwnerNoRelease`. ✓
- Skip digest/registry/container-policy for ECDSA → ECDSA branch omits them; covered by no-release/empty-env tests passing despite `ImageDigest="ecdsa:unverified"`. ✓
- Non-ECDSA unchanged (release required, checks intact) → `else` branch verbatim + `NonECDSAStillRequiresRelease` guard + full `Test_SecretsEndpoint` rerun. ✓
- Test stub creator hook → Task 1. ✓
- README updated → Task 3. ✓
- Scope: only `pkg/node/handlers.go`, `pkg/contractCaller/testhelpers.go`, tests, README; `ecdsa.go` untouched. ✓

**Placeholder scan:** No TBD/TODO/"handle edge cases"/"similar to"; all code and test bodies are spelled out. ✓

**Type consistency:** `verifyECDSAOwnership(appID string, publicKey []byte) (int, error)` — defined in Task 2 Step 4 and called in Step 5 with `req.AppID, claims.PublicKey`. `SetAppCreator(app, creator common.Address)` and `GetAppCreator(app common.Address, opts *bind.CallOpts) (common.Address, error)` defined in Task 1 and used in Task 2 tests. `StubECDSAMethod` copies `req.PublicKey`→`claims.PublicKey`, so setting `req.PublicKey` to `ethcrypto.FromECDSAPub(&key.PublicKey)` makes the handler-derived signer equal `ethcrypto.PubkeyToAddress(key.PublicKey)`, which the test sets as the creator — consistent. `release.EncryptedEnv`/`PublicEnv` are strings; `&types.Release{}` yields empty strings, matching the empty-env assertions. ✓
