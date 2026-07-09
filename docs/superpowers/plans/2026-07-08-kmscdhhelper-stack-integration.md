# kmsCDHHelper → ecloud-platform Stack Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert `cmd/kmsCDHHelper` from the on-chain `encrypted_env` model to the ecloud-platform stack model: recover the app-private-key via the KMS `stack_id` platform path, fetch per-secret ciphertexts from the platform's InternalSecretsService, and IBE-decrypt them inside the TEE.

**Architecture:** The KMS `/secrets` platform path returns only the recovered app-private-key (no env). `stack_id` replaces `app_id` as the single identity (the CLI seals each secret with `EncryptForApp(stackID, master, …)`, so the KMS must sign `H(stackID)` and the helper must IBE-decrypt under `stackID`). The plaintext env is assembled by fetching each `{name, ciphertext}` from the platform's InternalSecretsService HTTP gateway (`GET /internal/v1/stacks/{stack_id}/secrets`, `Authorization: Bearer <internal_api_key>`) and decrypting each value. Endpoint + key are SNP-bound via `cc_init_data`.

**Tech Stack:** Go; `net/http`; `encoding/json`; `pkg/crypto` (BLS12-381 IBE); `pkg/clients/kmsClient`; TOML via `github.com/pelletier/go-toml/v2`; tests via `testify` + `net/http/httptest`.

## Global Constraints

Copied verbatim from `CLAUDE.md` (project instructions) and `MEMORY.md` (user rules) — every task's requirements implicitly include these:

- **Never co-author commits.** No `Co-Authored-By` trailers; no "Generated with Claude Code" lines in commit messages.
- **Always use `./scripts/goTest.sh`** instead of `go test` directly.
- **Do not create useless test-results files.**
- Threshold security model: decryption requires ⌈2n/3⌉ operator signatures (`dkg.CalculateThreshold`). Unchanged by this work.
- Operators are identified by Ethereum addresses; node IDs via `util.AddressToNodeID()`. Unchanged.
- Code quality gates (from the Makefile): `make fmt` / `make fmtcheck`, `make lint` (golangci-lint), `go build ./...` must all pass before a change is complete.

---

## Verified external API (do not re-derive)

Pinned by reading the actual source at the commits in the design doc (`eigenx-kms-go` @655fb97, `ecloud-platform` @1636f637):

```go
// pkg/crypto/bls.go — IBE. The first arg is the IBE identity (seal-side uses stackID).
func EncryptForApp(appID string, masterPublicKey types.G2Point, plaintext []byte) ([]byte, error)
func DecryptForApp(appID string, appPrivateKey types.G1Point, ciphertext []byte) ([]byte, error)
// Test helpers for building a synthetic key pair (from pkg/crypto):
func HashToG1(appID string) (*bls.G1Point?, error)            // returns *types-compatible G1; see ibe_test.go usage
func ScalarMulG1(point <G1>, scalar *fr.Element) (*types.G1Point, error)
func ScalarMulG2(point <G2>, scalar *fr.Element) (*types.G2Point, error)
var G2Generator // package-level G2 base point
// Usage pattern (pkg/crypto/ibe_test.go:259-275):
//   masterSecret, _ := new(fr.Element).SetRandom()
//   masterPubKey, _ := ScalarMulG2(G2Generator, masterSecret)
//   ct, _ := EncryptForApp(id, *masterPubKey, plaintext)
//   appHash, _ := HashToG1(id)
//   appPrivateKey, _ := ScalarMulG1(*appHash, masterSecret)   // == what threshold recovery yields
//   pt, _ := DecryptForApp(id, *appPrivateKey, ct)            // round-trips

// pkg/types/types.go
type G1Point struct { CompressedBytes []byte }
type G2Point struct { CompressedBytes []byte }

// pkg/clients/kmsClient/client.go
type SecretsOptions struct {
    AttestationMethod string
    ImageDigest       string
    ECDSAPrivateKey   *ecdsa.PrivateKey
    TPMAttestationBytes []byte
    RawSNPEvidence    []byte
    CCInitData        []byte
    RSAPrivateKeyPEM  []byte
    RSAPublicKeyPEM   []byte
    ExtraData         []byte
    // Task 1 ADDS:
    // StackID string
}
type SecretsResult struct {
    AppPrivateKey   types.G1Point
    EncryptedEnv    string   // EMPTY on the platform (stack_id) path
    PublicEnv       string   // EMPTY on the platform (stack_id) path
    PartialSigs     map[common.Address]types.G1Point
    ResponseCount   int
    ThresholdNeeded int
    ExtraData       []byte
    Verified        bool
}
func (c *Client) RetrieveSecretsWithOptions(appID string, opts *SecretsOptions) (*SecretsResult, error)
// createEigenXSNPAttestationRequest currently builds SecretsRequestV1 WITHOUT StackID (client.go:928-944).

// pkg/types/types.go — already present (added by PR #120):
type SecretsRequestV1 struct {
    AppID string `json:"app_id"`
    StackID string `json:"stack_id,omitempty"`  // non-empty => platform path
    AttestationMethod string `json:"attestation_method"`
    // …
}

// ecloud-platform InternalSecretsService HTTP gateway (@1636f637):
//   GET {platform_secrets_url}/internal/v1/stacks/{stack_id}/secrets
//   Header: Authorization: Bearer <internal_api_key>
//   200 body (protojson):  {"secrets":[{"name":"FOO","value":"<base64-std>"}]}
//   proto `bytes value` marshals as a base64-std JSON string; a Go struct field
//   `Value []byte` unmarshals it back to raw bytes automatically.
```

Note on `HashToG1` return type: in `pkg/crypto/ibe_test.go` it is used as `appHash, _ := HashToG1(appID); ScalarMulG1(*appHash, masterSecret)`. Implementers: match that exact call shape; do not re-derive the return type.

---

## File Structure

- `pkg/clients/kmsClient/client.go` (modify) — add `SecretsOptions.StackID`; set `req.StackID` in `createEigenXSNPAttestationRequest`.
- `pkg/clients/kmsClient/client_test.go` (modify) — assert `StackID` flows into the eigenx-snp request.
- `cmd/kmsCDHHelper/platform_secrets.go` (create) — `fetchStackSecrets` HTTP client + `stackSecret` type + response decode.
- `cmd/kmsCDHHelper/platform_secrets_test.go` (create) — httptest coverage.
- `cmd/kmsCDHHelper/main.go` (modify) — `Request` (stack_id + platform fields), `initdataKMSConfig`, `applyInitdataKMSConfig`, `retrieveAndDecrypt` + a new pure `assembleEnvFromSecrets`; remove `decodeEncryptedEnv`.
- `cmd/kmsCDHHelper/env_cache.go` (modify) — remove `mergeEnv`; rename cache key param `appID`→`stackID`.
- `cmd/kmsCDHHelper/main_test.go` (modify) — update for stack_id identity + new initdata fields.
- `cmd/kmsCDHHelper/env_cache_test.go` (modify) — drop `mergeEnv` tests; keep cache/emit tests keyed by stack_id.

---

### Task 1: Wire `StackID` through the KMS client

Without this the helper cannot reach the platform path — `createEigenXSNPAttestationRequest` never sets `req.StackID`, so the KMS treats every helper request as the on-chain path.

**Files:**
- Modify: `pkg/clients/kmsClient/client.go` (`SecretsOptions` struct ~line 67; `createEigenXSNPAttestationRequest` ~line 928)
- Test: `pkg/clients/kmsClient/client_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `SecretsOptions.StackID string` — set by the helper (Task 5) to select the platform path.

- [ ] **Step 1: Write the failing test**

Add to `pkg/clients/kmsClient/client_test.go` (package `kmsClient`):

```go
func TestCreateEigenXSNPAttestationRequest_SetsStackID(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	c := &Client{logger: logger}

	opts := &SecretsOptions{
		AttestationMethod: "eigenx-snp",
		RawSNPEvidence:    []byte(`{"attestation_report":"x"}`),
		CCInitData:        []byte("initdata"),
		RSAPublicKeyPEM:   []byte("-----BEGIN PUBLIC KEY-----"),
		StackID:           "stack-123",
	}

	req := c.createEigenXSNPAttestationRequest("stack-123", opts)

	assert.Equal(t, "stack-123", req.StackID, "StackID must flow into the request to select the platform path")
	assert.Equal(t, "eigenx-snp", req.AttestationMethod)
	assert.Equal(t, "stack-123", req.AppID)
}

func TestCreateEigenXSNPAttestationRequest_EmptyStackIDLeavesItUnset(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	c := &Client{logger: logger}

	opts := &SecretsOptions{
		AttestationMethod: "eigenx-snp",
		RawSNPEvidence:    []byte(`{"attestation_report":"x"}`),
		CCInitData:        []byte("initdata"),
		RSAPublicKeyPEM:   []byte("-----BEGIN PUBLIC KEY-----"),
		// StackID omitted
	}

	req := c.createEigenXSNPAttestationRequest("app-1", opts)

	assert.Empty(t, req.StackID, "empty StackID must leave the request on the on-chain path")
}
```

Ensure the test file imports `"go.uber.org/zap"` and `"github.com/stretchr/testify/assert"` (add if missing).

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./pkg/clients/kmsClient/ -run TestCreateEigenXSNPAttestationRequest -v`
Expected: FAIL — compile error `opts.StackID undefined (type *SecretsOptions has no field StackID)`.

- [ ] **Step 3: Add the field**

In `pkg/clients/kmsClient/client.go`, in `SecretsOptions` (after the `ExtraData` field ~line 88):

```go
	ExtraData        []byte // optional caller-supplied data bound into attestation (max 1 MB)

	// StackID, when non-empty, switches the KMS /secrets authorization to the
	// ecloud-platform release for this stack (the platform path) instead of the
	// on-chain AppController. On that path the KMS returns only the recovered
	// app-private-key (no env). Empty preserves the on-chain behavior.
	StackID string
```

- [ ] **Step 4: Set it in the eigenx-snp request builder**

In `createEigenXSNPAttestationRequest` (~line 935), add `StackID` to the returned struct:

```go
	return types.SecretsRequestV1{
		AppID:             appID,
		StackID:           opts.StackID,
		AttestationMethod: "eigenx-snp",
		Attestation:       opts.RawSNPEvidence,
		RSAPubKeyTmp:      opts.RSAPublicKeyPEM,
		AttestationTime:   time.Now().Unix(),
		ExtraData:         opts.ExtraData,
		CCInitData:        opts.CCInitData,
	}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./scripts/goTest.sh ./pkg/clients/kmsClient/ -run TestCreateEigenXSNPAttestationRequest -v`
Expected: PASS (both subtests).

- [ ] **Step 6: Verify no regression in the package**

Run: `./scripts/goTest.sh ./pkg/clients/kmsClient/ -v`
Expected: PASS (all existing tests unaffected — `StackID` defaults to `""`).

- [ ] **Step 7: Commit**

```bash
git add pkg/clients/kmsClient/client.go pkg/clients/kmsClient/client_test.go
git commit -m "feat(kmsClient): wire StackID into eigenx-snp secrets request"
```

---

### Task 2: `fetchStackSecrets` — platform InternalSecretsService HTTP client

**Files:**
- Create: `cmd/kmsCDHHelper/platform_secrets.go`
- Test: `cmd/kmsCDHHelper/platform_secrets_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  ```go
  type stackSecret struct { Name string; Value []byte }
  func fetchStackSecrets(baseURL, apiKey, stackID string) ([]stackSecret, error)
  ```
  Task 4 calls `fetchStackSecrets`; Task 4's `assembleEnvFromSecrets` consumes `[]stackSecret`.

- [ ] **Step 1: Write the failing test**

Create `cmd/kmsCDHHelper/platform_secrets_test.go` (package `main`):

```go
package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchStackSecrets_HappyPath(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		// proto bytes marshal as base64-std strings on the wire.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secrets": []map[string]string{
				{"name": "DB_PASSWORD", "value": base64.StdEncoding.EncodeToString([]byte("ciphertext-1"))},
				{"name": "API_KEY", "value": base64.StdEncoding.EncodeToString([]byte("ciphertext-2"))},
			},
		})
	}))
	defer srv.Close()

	got, err := fetchStackSecrets(srv.URL, "secret-key", "stack-abc")
	require.NoError(t, err)

	assert.Equal(t, "Bearer secret-key", gotAuth, "must present the internal API key as a Bearer token")
	assert.Equal(t, "/internal/v1/stacks/stack-abc/secrets", gotPath)
	require.Len(t, got, 2)
	assert.Equal(t, "DB_PASSWORD", got[0].Name)
	assert.Equal(t, []byte("ciphertext-1"), got[0].Value, "value must be base64-decoded to raw ciphertext bytes")
	assert.Equal(t, "API_KEY", got[1].Name)
	assert.Equal(t, []byte("ciphertext-2"), got[1].Value)
}

func TestFetchStackSecrets_Non200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := fetchStackSecrets(srv.URL, "k", "stack-abc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestFetchStackSecrets_MalformedJSONIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := fetchStackSecrets(srv.URL, "k", "stack-abc")
	require.Error(t, err)
}

func TestFetchStackSecrets_EscapesStackIDInPath(t *testing.T) {
	// A stack_id containing path metacharacters must be percent-escaped into a
	// SINGLE path segment — it must not split into extra segments or traverse.
	// (Config-time validation in applyInitdataKMSConfig is the primary guard;
	// this is defense-in-depth at the request boundary.)
	for _, tc := range []struct {
		name    string
		stackID string
	}{
		{"embedded_slash", "weird/id"},
		{"dotdot_escaped", "%2e%2e"},
		{"literal_dotdot_slash", "../etc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotEscapedPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotEscapedPath = r.URL.EscapedPath()
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []any{}})
			}))
			defer srv.Close()

			_, err := fetchStackSecrets(srv.URL, "k", tc.stackID)
			require.NoError(t, err)
			// The stack segment sits between "/stacks/" and "/secrets"; assert the
			// path shape is exactly one escaped segment there and never traverses.
			assert.Contains(t, gotEscapedPath, "/internal/v1/stacks/")
			assert.True(t, strings.HasSuffix(gotEscapedPath, "/secrets"))
			assert.NotContains(t, gotEscapedPath, "/../", "stack_id must not introduce a traversal segment")
			assert.NotContains(t, gotEscapedPath, "stacks/../", "stack_id must not escape the stacks/ prefix")
		})
	}
}

func TestFetchStackSecrets_BodyCapped(t *testing.T) {
	// A misbehaving endpoint returning a huge body must not OOM the
	// memory-constrained peer-pod. The response is read under io.LimitReader;
	// a body past the cap yields a decode error (truncated JSON), not a hang.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write a valid prefix then far more than the cap of junk so the
		// LimitReader truncates mid-stream and json.Unmarshal fails.
		_, _ = w.Write([]byte(`{"secrets":[`))
		junk := make([]byte, platformSecretsMaxBody+1024)
		for i := range junk {
			junk[i] = 'A'
		}
		_, _ = w.Write(junk)
	}))
	defer srv.Close()

	_, err := fetchStackSecrets(srv.URL, "k", "stack-abc")
	require.Error(t, err)
}

func TestFetchStackSecrets_EmptyListIsOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []any{}})
	}))
	defer srv.Close()

	got, err := fetchStackSecrets(srv.URL, "k", "stack-abc")
	require.NoError(t, err)
	assert.Empty(t, got)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./cmd/kmsCDHHelper/ -run TestFetchStackSecrets -v`
Expected: FAIL — `undefined: fetchStackSecrets`.

- [ ] **Step 3: Implement `fetchStackSecrets`**

Create `cmd/kmsCDHHelper/platform_secrets.go`:

```go
package main

// Client for ecloud-platform's InternalSecretsService HTTP gateway. On the
// stack model the KMS returns only the recovered app-private-key; the actual
// secret ciphertexts live in the platform and are fetched here, then
// IBE-decrypted inside the TEE with that key (see retrieveAndDecrypt).
//
// The endpoint + bearer key are SNP-bound via cc_init_data (applyInitdataKMSConfig),
// and the route is only reachable by the helper over the trusted internal network.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// platformSecretsTimeout bounds the whole ListSecrets round trip.
	platformSecretsTimeout = 30 * time.Second
	// platformSecretsMaxBody caps the response body. Stack secret sets are
	// small (kilobytes of ciphertext); 8 MiB is generous headroom that still
	// protects the memory-constrained peer-pod from a misbehaving endpoint.
	platformSecretsMaxBody = 8 << 20
	// platformSecretsErrBodyMax bounds how much of a non-200 response body is
	// echoed into an error (which reaches stderr/journal via main's log.Printf).
	// Enough to surface a real error message without dumping a large
	// remote-controlled body into operator logs.
	platformSecretsErrBodyMax = 4 << 10
)

// stackSecret is one platform secret: a name and its opaque IBE ciphertext.
type stackSecret struct {
	Name  string
	Value []byte
}

// internalSecret mirrors the protojson wire shape of InternalSecret. The proto
// `bytes value` field marshals as a base64-std string; a Go []byte field
// unmarshals it back to raw bytes automatically.
type internalSecret struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
}

type listSecretsResponse struct {
	Secrets []internalSecret `json:"secrets"`
}

// fetchStackSecrets GETs a stack's sealed secrets from the platform's
// InternalSecretsService HTTP gateway and returns each {name, ciphertext}.
// baseURL is the gateway root; the stack path is appended here. apiKey is the
// static internal API key, presented as a Bearer token.
func fetchStackSecrets(baseURL, apiKey, stackID string) ([]stackSecret, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse platform secrets URL: %w", err)
	}
	// Percent-escape stackID into a SINGLE path segment. NOTE: url.JoinPath is
	// NOT safe here — it does not percent-escape "." / ".." or embedded "/", it
	// path-CLEANS them (silently dropping/rewriting segments), which is a
	// traversal footgun. Build the path explicitly with url.PathEscape so a
	// hostile stack_id can never reshape the request path. (stackID is also
	// content-validated at config time in applyInitdataKMSConfig — this is
	// defense-in-depth at the request boundary.)
	base := strings.TrimRight(u.Path, "/")
	u.Path = base + "/internal/v1/stacks/" + url.PathEscape(stackID) + "/secrets"

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build ListSecrets request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: platformSecretsTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, platformSecretsMaxBody))
	if err != nil {
		return nil, fmt.Errorf("read ListSecrets response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Truncate the surfaced body: it is remote-controlled and reaches
		// stderr/journal via main's log.Printf.
		snippet := body
		if len(snippet) > platformSecretsErrBodyMax {
			snippet = snippet[:platformSecretsErrBodyMax]
		}
		return nil, fmt.Errorf("platform ListSecrets returned status %d: %s", resp.StatusCode, string(snippet))
	}

	var parsed listSecretsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode ListSecrets response: %w", err)
	}

	out := make([]stackSecret, 0, len(parsed.Secrets))
	for _, s := range parsed.Secrets {
		out = append(out, stackSecret{Name: s.Name, Value: s.Value})
	}
	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./scripts/goTest.sh ./cmd/kmsCDHHelper/ -run TestFetchStackSecrets -v`
Expected: PASS (happy-path, non-200, malformed-JSON, path-escape subcases, body-cap, empty-list).

- [ ] **Step 5: Commit**

```bash
git add cmd/kmsCDHHelper/platform_secrets.go cmd/kmsCDHHelper/platform_secrets_test.go
git commit -m "feat(kmsCDHHelper): add platform InternalSecretsService client"
```

---

### Task 3: `assembleEnvFromSecrets` — pure IBE-decrypt + assembly

Extract the env-assembly step as a pure function so it is testable without the KMS client. This replaces the old `decodeEncryptedEnv` + `mergeEnv(public_env, …)` logic.

**Files:**
- Modify: `cmd/kmsCDHHelper/main.go` (add the function; near `retrieveAndDecrypt`)
- Test: `cmd/kmsCDHHelper/main_test.go`

**Interfaces:**
- Consumes: `stackSecret` (Task 2); `types.G1Point`, `crypto.DecryptForApp` (verified API).
- Produces:
  ```go
  func assembleEnvFromSecrets(stackID string, appPrivateKey types.G1Point, secrets []stackSecret) (map[string]string, error)
  ```
  Task 4's `retrieveAndDecrypt` calls this.

- [ ] **Step 1: Write the failing test**

Add to `cmd/kmsCDHHelper/main_test.go`. Add imports as needed (none of these are in `main_test.go` today): `"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"`, `"github.com/Layr-Labs/eigenx-kms-go/pkg/types"`, `"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"` (used by the Task 5 `resolveEnv` tests in the same file), and `fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"` (import path per `pkg/crypto/ibe_test.go:18`; package name is `fr` so the alias is cosmetic).

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./cmd/kmsCDHHelper/ -run TestAssembleEnvFromSecrets -v`
Expected: FAIL — `undefined: assembleEnvFromSecrets`.

- [ ] **Step 3: Implement `assembleEnvFromSecrets`**

In `cmd/kmsCDHHelper/main.go`, add (near `retrieveAndDecrypt`):

```go
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
```

`crypto` is already imported in `main.go` (`main.go:51`), but `pkg/types` is NOT — add `"github.com/Layr-Labs/eigenx-kms-go/pkg/types"` to `main.go`'s import block (the new `assembleEnvFromSecrets` signature uses `types.G1Point`).

- [ ] **Step 4: Run test to verify it passes**

Run: `./scripts/goTest.sh ./cmd/kmsCDHHelper/ -run TestAssembleEnvFromSecrets -v`
Expected: PASS (all three subtests).

- [ ] **Step 5: Commit**

```bash
git add cmd/kmsCDHHelper/main.go cmd/kmsCDHHelper/main_test.go
git commit -m "feat(kmsCDHHelper): add pure IBE env assembly from platform secrets"
```

---

### Task 4: Stack identity in `Request` + `initdataKMSConfig` + `applyInitdataKMSConfig`

Replace `app_id` with `stack_id` as identity and source the platform secrets endpoint + key from SNP-bound `cc_init_data`.

**Files:**
- Modify: `cmd/kmsCDHHelper/main.go` (`Request` ~line 128; `initdataKMSConfig` ~line 149; `applyInitdataKMSConfig` ~line 414; `readRequest` ~line 299)
- Test: `cmd/kmsCDHHelper/main_test.go`

**Interfaces:**
- Consumes: `validateHTTPURL` (existing, `main.go:480`).
- Produces: `Request` with `StackID`, `PlatformSecretsURL`, `PlatformInternalAPIKey`; `initdataKMSConfig` with matching TOML fields. Task 5 reads these.

- [ ] **Step 1: Write the failing tests**

In `cmd/kmsCDHHelper/main_test.go`, add new tests and update the field names. First add:

```go
func TestApplyInitdataKMSConfig_PlatformFields(t *testing.T) {
	t.Run("populates stack + platform fields from initdata", func(t *testing.T) {
		req := &Request{}
		cfg := &initdataKMSConfig{
			RPCURL:                 "http://rpc.example",
			AVSAddress:             "0xabc",
			StackID:                "stack-123",
			PlatformSecretsURL:     "http://platform.internal:9003",
			PlatformInternalAPIKey: "internal-key",
		}
		require.NoError(t, applyInitdataKMSConfig(req, cfg))
		assert.Equal(t, "stack-123", req.StackID)
		assert.Equal(t, "http://platform.internal:9003", req.PlatformSecretsURL)
		assert.Equal(t, "internal-key", req.PlatformInternalAPIKey)
	})

	t.Run("missing stack_id fails closed", func(t *testing.T) {
		cfg := &initdataKMSConfig{
			RPCURL: "http://rpc.example", AVSAddress: "0xabc",
			PlatformSecretsURL: "http://p.internal", PlatformInternalAPIKey: "k",
		}
		err := applyInitdataKMSConfig(&Request{}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "stack_id")
	})

	t.Run("missing platform_secrets_url fails closed", func(t *testing.T) {
		cfg := &initdataKMSConfig{
			RPCURL: "http://rpc.example", AVSAddress: "0xabc",
			StackID: "s", PlatformInternalAPIKey: "k",
		}
		err := applyInitdataKMSConfig(&Request{}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "platform_secrets_url")
	})

	t.Run("missing platform_internal_api_key fails closed", func(t *testing.T) {
		cfg := &initdataKMSConfig{
			RPCURL: "http://rpc.example", AVSAddress: "0xabc",
			StackID: "s", PlatformSecretsURL: "http://p.internal",
		}
		err := applyInitdataKMSConfig(&Request{}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "platform_internal_api_key")
	})

	t.Run("non-http platform_secrets_url rejected", func(t *testing.T) {
		cfg := &initdataKMSConfig{
			RPCURL: "http://rpc.example", AVSAddress: "0xabc",
			StackID: "s", PlatformSecretsURL: "file:///etc/passwd", PlatformInternalAPIKey: "k",
		}
		err := applyInitdataKMSConfig(&Request{}, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scheme")
	})

	t.Run("malformed stack_id rejected (path-injection guard)", func(t *testing.T) {
		for _, bad := range []string{"a/b", "..", "../etc", "has space", "semi;colon", "q?uery"} {
			cfg := &initdataKMSConfig{
				RPCURL: "http://rpc.example", AVSAddress: "0xabc",
				StackID: bad, PlatformSecretsURL: "http://p.internal", PlatformInternalAPIKey: "k",
			}
			err := applyInitdataKMSConfig(&Request{}, cfg)
			require.Error(t, err, "stack_id %q must be rejected", bad)
			assert.Contains(t, err.Error(), "stack_id")
		}
	})

	t.Run("valid stack_id shapes accepted", func(t *testing.T) {
		for _, ok := range []string{
			"stack-123",
			"3f2504e0-4f89-11d3-9a0c-0305e82c3301", // UUID
			"Stack_ID.v2",
		} {
			cfg := &initdataKMSConfig{
				RPCURL: "http://rpc.example", AVSAddress: "0xabc",
				StackID: ok, PlatformSecretsURL: "http://p.internal", PlatformInternalAPIKey: "k",
			}
			require.NoError(t, applyInitdataKMSConfig(&Request{}, cfg), "stack_id %q must be accepted", ok)
		}
	})
}

func TestValidateStackID(t *testing.T) {
	require.NoError(t, validateStackID("stack-123"))
	require.NoError(t, validateStackID("3f2504e0-4f89-11d3-9a0c-0305e82c3301"))
	for _, bad := range []string{"", "a/b", "..", "../x", "a b", "a;b", "a?b", "a#b"} {
		require.Error(t, validateStackID(bad), "%q must be rejected", bad)
	}
}
```

Then update the EXISTING tests that construct `Request{AppID: ...}` or `initdataKMSConfig` without the new required fields, since `applyInitdataKMSConfig` now also requires stack/platform fields:
- In `TestApplyInitdataKMSConfig` and `TestApplyInitdataKMSConfig_SingleOperatorGate`, add `StackID: "s", PlatformSecretsURL: "http://p.internal", PlatformInternalAPIKey: "k"` to every `initdataKMSConfig{...}` literal in the **success** subtests ("initdata populates empty request", "initdata wins over stdin", "kms_url with opt-in succeeds", "production rpc_url path needs no opt-in"). Leave the failure subtests (missing avs_address, missing rpc_url/kms_url, scheme, host, gate-fail) as-is — they must still fail for their original reason, which is checked before the new required-field checks (see Step 3 ordering).
- Replace `Request{AppID: "x"}` literals with `Request{}` (the `AppID` field is removed in this task).

Update `readRequest` tests:
- `TestReadRequest_HappyPath`: change `AppID: "app-id"` to `StackID: "stack-id"` and the assertion `got.AppID`→`got.StackID`.
- `TestReadRequest_IgnoresUnknownFields`: change body to `{"stack_id":"x","key":"K","some_future_field":"deadbeef"}` and assert `got.StackID == "x"`.
- `TestReadRequest_MissingFields`: change the "missing app_id" case to "missing stack_id" (req `Request{RPCURL: ..., Key: "K"}`, expectedErr `"stack_id is required"`); the "missing key" case sets `StackID: "stack-id"`.
- `TestParseInitdataKMSConfig`: leave as-is (it parses only KMS coords; adding platform fields to the TOML is covered separately — optionally extend the `eigenx.toml` block with `stack_id`, `platform_secrets_url`, `platform_internal_api_key` and assert them on `cfg`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `./scripts/goTest.sh ./cmd/kmsCDHHelper/ -run 'TestApplyInitdataKMSConfig|TestReadRequest' -v`
Expected: FAIL — compile errors (`Request` has no `StackID`/`PlatformSecretsURL`/`PlatformInternalAPIKey`; `AppID` removed) and assertion failures.

- [ ] **Step 3: Update `Request`, `initdataKMSConfig`, `readRequest`, `applyInitdataKMSConfig`**

In `main.go`, replace the `Request` struct's identity/coord fields. Change `AppID` to `StackID` and add the two platform fields (sourced only from initdata):

```go
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
```

Update the `Request` doc comment above the struct to describe the stack model (identity is `stack_id`; secrets come from the platform, not the KMS response). Keep it accurate — remove the "public_env + encrypted_env" language.

Add the TOML fields to `initdataKMSConfig`:

```go
type initdataKMSConfig struct {
	KMSURL        string `toml:"kms_url"`
	AVSAddress    string `toml:"avs_address"`
	OperatorSetID uint32 `toml:"operator_set_id"`
	RPCURL        string `toml:"rpc_url"`
	OperatorAddress string `toml:"operator_address"`
	// Stack model: identity + platform secrets endpoint, SNP-bound.
	StackID                string `toml:"stack_id"`
	PlatformSecretsURL     string `toml:"platform_secrets_url"`
	PlatformInternalAPIKey string `toml:"platform_internal_api_key"`
}
```

In `readRequest`, replace the `req.AppID == ""` check:

```go
	if req.StackID == "" {
		return nil, fmt.Errorf("stack_id is required")
	}
	if req.Key == "" {
		return nil, fmt.Errorf("key is required")
	}
```

Add a `validateStackID` helper near `validateHTTPURL` in `main.go`. It restricts
`stack_id` to a conservative character set so it is always a single, safe URL path
segment (the stack model has "no per-tenant context — the caller names stack_id
explicitly", so this value is load-bearing: IBE identity + KMS signing identity +
platform path segment):

```go
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
```

Add `"regexp"` to `main.go`'s import block.

In `applyInitdataKMSConfig`, keep all existing KMS-coord validation and the single-operator gate exactly as-is (those failure checks run first), then BEFORE the final assignment block add the new required-field validation and assignment. Insert after the existing `stdinOverridden` logging block, replacing the final assignments:

```go
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
```

Remove the now-replaced trailing assignment block (the old `req.KMSURL = cfg.KMSURL … return nil`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `./scripts/goTest.sh ./cmd/kmsCDHHelper/ -run 'TestApplyInitdataKMSConfig|TestReadRequest|TestParseInitdataKMSConfig' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/kmsCDHHelper/main.go cmd/kmsCDHHelper/main_test.go
git commit -m "feat(kmsCDHHelper): stack_id identity + SNP-bound platform secrets config"
```

---

### Task 5: Rewire `retrieveAndDecrypt` to the platform flow; drop on-chain env

**Files:**
- Modify: `cmd/kmsCDHHelper/main.go` (`retrieveAndDecrypt` ~line 642; remove `decodeEncryptedEnv` ~line 762; `run` ~line 194 references)
- Modify: `cmd/kmsCDHHelper/env_cache.go` (remove `mergeEnv`; rename `appID`→`stackID`)
- Test: `cmd/kmsCDHHelper/main_test.go`, `cmd/kmsCDHHelper/env_cache_test.go`

**Interfaces:**
- Consumes: `assembleEnvFromSecrets` (Task 3), `fetchStackSecrets` (Task 2), `SecretsOptions.StackID` (Task 1), `emitAppPrivateKey` (existing).
- Produces:
  ```go
  // resolveEnv turns a recovered SecretsResult into the app env map, injecting
  // the secrets-fetch so the sentinel/no-fetch path is unit-testable.
  func resolveEnv(req *Request, result *kmsClient.SecretsResult,
      fetch func(baseURL, apiKey, stackID string) ([]stackSecret, error)) (map[string]string, error)
  ```
  `retrieveAndDecrypt` calls `resolveEnv(req, result, fetchStackSecrets)`.

- [ ] **Step 1a: Write the failing sentinel/resolve test**

Add to `cmd/kmsCDHHelper/main_test.go`. This proves the sentinel path skips the fetch and the normal path uses it — without standing up a KMS client or network (the design §6 test targets: "retrieveAndDecrypt env assembly" and "Sentinel … does NOT call fetchStackSecrets"):

```go
func TestResolveEnv_SentinelSkipsFetch(t *testing.T) {
	// A validated app_private_key result; emitAppPrivateKey requires Verified
	// and a 48-byte compressed G1.
	result := &kmsClient.SecretsResult{
		Verified:      true,
		AppPrivateKey: types.G1Point{CompressedBytes: make([]byte, appPrivateKeyG1Bytes)},
	}
	req := &Request{StackID: "stack-1", Key: appPrivateKeyKey}

	fetchCalled := false
	fetch := func(baseURL, apiKey, stackID string) ([]stackSecret, error) {
		fetchCalled = true
		return nil, nil
	}

	env, err := resolveEnv(req, result, fetch)
	require.NoError(t, err)
	assert.False(t, fetchCalled, "sentinel path must NOT fetch platform secrets")
	_, ok := env[appPrivateKeyKey]
	assert.True(t, ok, "sentinel path emits the app_private_key under the sentinel key")
}

func TestResolveEnv_NormalPathFetchesAndAssembles(t *testing.T) {
	const stackID = "stack-xyz"
	masterSecret, err := new(fr.Element).SetRandom()
	require.NoError(t, err)
	masterPubKey, err := crypto.ScalarMulG2(crypto.G2Generator, masterSecret)
	require.NoError(t, err)
	appHash, err := crypto.HashToG1(stackID)
	require.NoError(t, err)
	appPrivateKey, err := crypto.ScalarMulG1(*appHash, masterSecret)
	require.NoError(t, err)
	ct, err := crypto.EncryptForApp(stackID, *masterPubKey, []byte("v1"))
	require.NoError(t, err)

	result := &kmsClient.SecretsResult{AppPrivateKey: *appPrivateKey}
	req := &Request{StackID: stackID, Key: "FOO", PlatformSecretsURL: "http://p", PlatformInternalAPIKey: "k"}

	var gotURL, gotKey, gotStack string
	fetch := func(baseURL, apiKey, s string) ([]stackSecret, error) {
		gotURL, gotKey, gotStack = baseURL, apiKey, s
		return []stackSecret{{Name: "FOO", Value: ct}}, nil
	}

	env, err := resolveEnv(req, result, fetch)
	require.NoError(t, err)
	assert.Equal(t, "http://p", gotURL)
	assert.Equal(t, "k", gotKey)
	assert.Equal(t, stackID, gotStack)
	assert.Equal(t, map[string]string{"FOO": "v1"}, env)
}

func TestResolveEnv_FetchErrorPropagates(t *testing.T) {
	result := &kmsClient.SecretsResult{AppPrivateKey: types.G1Point{CompressedBytes: make([]byte, appPrivateKeyG1Bytes)}}
	req := &Request{StackID: "s", Key: "FOO", PlatformSecretsURL: "http://p", PlatformInternalAPIKey: "k"}
	fetch := func(_, _, _ string) ([]stackSecret, error) { return nil, fmt.Errorf("boom") }

	_, err := resolveEnv(req, result, fetch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}
```

Add `"fmt"` to the test imports if not already present. `kmsClient`, `crypto`, `types`, and `fr` were added to `main_test.go`'s imports in Task 3 (same file); if executing tasks out of order, ensure all of `"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"`, `"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"`, `"github.com/Layr-Labs/eigenx-kms-go/pkg/types"`, and `fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"` are present.

- [ ] **Step 1b: Run to verify it fails**

Run: `./scripts/goTest.sh ./cmd/kmsCDHHelper/ -run TestResolveEnv -v`
Expected: FAIL — `undefined: resolveEnv`.

- [ ] **Step 1c: Update `run`, add `resolveEnv`, and rewire `retrieveAndDecrypt`**

In `run()` (`main.go` ~line 194), replace `req.AppID` references with `req.StackID` (cache fast-path `loadCachedEnv(req.StackID)`, `storeCachedEnv(req.StackID, env)`, and the log field). The `cacheable(req.Key)` guard is unchanged. Also fix the now-stale cache-warning wording at `main.go:288` — change `log.Printf("warning: cache merged env for app %q: %v", req.AppID, cerr)` to `log.Printf("warning: cache stack env for stack %q: %v", req.StackID, cerr)` (there is no "merged" public/secret env anymore).

Add `resolveEnv` (near `retrieveAndDecrypt`):

```go
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
```

In `retrieveAndDecrypt`, change identity to `req.StackID`, set `opts.StackID`, call `RetrieveSecretsWithOptions(req.StackID, opts)`, and delegate to `resolveEnv`:

```go
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
```

Delete the old post-recovery body from `// Root-key request …` through the `mergeEnv` return (it now lives in `resolveEnv`). Also update the `newSingleOperatorContractCaller`/discovery block above it to use `req.StackID` where it currently references `req.AppID` (the KMS-coord discovery logic itself is unchanged — only identity naming). Update `retrieveAndDecrypt`'s doc comment to describe the stack flow.

Delete the `decodeEncryptedEnv` function entirely (no caller remains).

- [ ] **Step 2: Remove `mergeEnv` and rekey the cache to stackID**

In `env_cache.go`:
- Delete `mergeEnv` (no caller remains).
- Rename the `appID` parameter to `stackID` in `cachePath`, `loadCachedEnv`, `storeCachedEnv` (behavior identical — a stack UUID is filesystem-safe; keep the sanitization). Update their doc comments to say "stack" instead of "app".

- [ ] **Step 3: Update env_cache_test.go**

In `cmd/kmsCDHHelper/env_cache_test.go`:
- Delete any `TestMergeEnv*` tests (the function is gone).
- For cache round-trip / emit tests, rename `appID` args to a stack id string; the assertions are otherwise unchanged. `emitKey` tests are unchanged (its signature didn't change).

- [ ] **Step 4: Build and run the full helper package**

Run: `go build ./cmd/kmsCDHHelper/ && ./scripts/goTest.sh ./cmd/kmsCDHHelper/ -v`
Expected: PASS — all tests; no `undefined`/`declared and not used` errors. If the compiler reports `decodeEncryptedEnv`/`mergeEnv` still referenced, remove the stragglers.

- [ ] **Step 5: Commit**

```bash
git add cmd/kmsCDHHelper/main.go cmd/kmsCDHHelper/env_cache.go cmd/kmsCDHHelper/env_cache_test.go cmd/kmsCDHHelper/main_test.go
git commit -m "feat(kmsCDHHelper): fetch+decrypt stack secrets from platform; drop on-chain env"
```

---

### Task 6: Full-suite gates + doc sync

**Files:**
- Modify: `cmd/kmsCDHHelper/main.go` (top-of-file package doc comment, `main.go:1-24`)
- Modify: `docs/009_eigenxSnpAttestation.md` (helper-flow description, ~lines 30-34; `eigenx.toml` fields, ~line 114)
- (No new tests — this task runs the mechanical gates and syncs docs.)

**Interfaces:** none.

- [ ] **Step 1: Update the package doc comment**

The `main.go` header (lines 1-24) still describes the old flow ("IBE-decrypts the KMS-returned encrypted_env"). Rewrite it to describe the stack model:
- The helper drives eigenx-snp attestation, recovers the app-private-key via the KMS `stack_id` platform path (KMS returns only the key share),
- fetches sealed secrets from the ecloud-platform InternalSecretsService, IBE-decrypts each with the recovered key (identity = stackID), and emits the requested key.
Keep the wire-contract bullet list (stdin JSON / stdout plaintext / stderr / exit code) accurate.

- [ ] **Step 1b: Sync `docs/009_eigenxSnpAttestation.md`**

That doc describes the helper flow being changed. Update:
- The `cmd/kmsCDHHelper/` bullet (~lines 30-34): it currently ends "calls `RetrieveSecretsWithOptions`, IBE-decrypts" — describing the on-chain encrypted_env decrypt. Change it to: recovers the app-private-key via the KMS `stack_id` platform path, then fetches the stack's sealed secrets from the ecloud-platform InternalSecretsService and IBE-decrypts each under the stackID identity.
- The `[data]."eigenx.toml"` description (~line 114): note that the block now also carries `stack_id`, `platform_secrets_url`, and `platform_internal_api_key` (all SNP-bound), and that identity is the `stack_id` (not `app_id`).
Keep edits factual and scoped to the helper flow; do not touch the unrelated api-server-rest/runtime_data follow-up section.

- [ ] **Step 2: Format**

Run: `make fmt`
Expected: no diff beyond intended changes.

- [ ] **Step 3: Format check + build + vet**

Run: `make fmtcheck && go build ./...`
Expected: both succeed, no output errors.

- [ ] **Step 4: Lint**

Run: `make lint`
Expected: 0 issues. Note: `net/url`, `crypto/sha512`, and `encoding/base64` all remain used elsewhere in `main.go` after `decodeEncryptedEnv` is removed (`validateHTTPURL`/`fetchAAEvidence` use `net/url`; `buildReportData` uses `crypto/sha512`; `decodeInitdata` uses `encoding/base64`), so no import should need removing — but if the compiler/lint does flag a genuinely unused import after your edits, remove it.

- [ ] **Step 5: Full test suite**

Run: `./scripts/goTest.sh ./...`
Expected: 0 FAIL across the repo. Pay attention to `pkg/clients/kmsClient` and `cmd/kmsCDHHelper`.

- [ ] **Step 6: Commit**

```bash
git add cmd/kmsCDHHelper/main.go docs/009_eigenxSnpAttestation.md
git commit -m "docs(kmsCDHHelper): sync helper docs to stack model"
```

---

## Self-Review

**Spec coverage:**
- Stack-only (remove on-chain env) → Task 5 (removes `decodeEncryptedEnv`, `mergeEnv`, encrypted_env/public_env handling). ✓
- Endpoint + key from cc_init_data → Task 4 (`initdataKMSConfig` + `applyInitdataKMSConfig`). ✓
- `stack_id` replaces `app_id` → Task 4 (`Request`/`readRequest`) + Task 5 (`run`/`retrieveAndDecrypt`). ✓
- HTTP gateway ListSecrets client → Task 2. ✓
- IBE-decrypt each secret under stackID → Task 3. ✓
- `SecretsOptions.StackID` wiring gap → Task 1. ✓
- Sentinel `__EIGENX_APP_PRIVATE_KEY__` preserved (skips fetch, never cached) → Task 5 `resolveEnv` returns before fetch; `TestResolveEnv_SentinelSkipsFetch` asserts fetch is not called; existing `cacheable` keeps it out of the cache. ✓
- `stack_id` path-injection hardening → Task 2 (`url.PathEscape` + traversal tests) + Task 4 (`validateStackID` content check). ✓
- Fail-closed error handling (missing config, non-200, undecryptable value, missing key, fetch error) → Tasks 2, 3, 4, 5. ✓
- Testing (kmsClient StackID, applyInitdata + validateStackID, fetchStackSecrets incl. path-escape + body-cap, assembly round-trip, resolveEnv sentinel/normal/error, cache) → Tasks 1-5. ✓
- Doc sync (`main.go` header + `docs/009_eigenxSnpAttestation.md`) → Task 6. ✓

**Placeholder scan:** No TBD/TODO/"add error handling"/"similar to Task N" — all code shown inline. The one `HashToG1` return-type note explicitly instructs matching `ibe_test.go`'s call shape rather than guessing. ✓

**Type consistency:** `stackSecret{Name, Value}`, `fetchStackSecrets(baseURL, apiKey, stackID) ([]stackSecret, error)`, `assembleEnvFromSecrets(stackID string, appPrivateKey types.G1Point, secrets []stackSecret) (map[string]string, error)`, `resolveEnv(req *Request, result *kmsClient.SecretsResult, fetch func(baseURL, apiKey, stackID string) ([]stackSecret, error)) (map[string]string, error)`, `validateStackID(stackID string) error`, `SecretsOptions.StackID` — names/signatures identical across Tasks 1-5. Task 5's `resolveEnv` consumes `fetchStackSecrets` (Task 2) whose signature exactly matches the injected `fetch` parameter type. ✓

## Pipeline State

| Field   | Value                          |
|---------|--------------------------------|
| stage   | 5 (pr feedback loop)           |
| branch  | sm-updateHelper                |
| pr      | #122 (draft)                   |
| round   | 0                              |
| gate    | approved 2026-07-08 (user: push + implement) |

All 6 tasks implemented + per-task-reviewed (spec ✅ / quality approved each). Final whole-branch review (ea6adce..e0f745e): READY — 0 findings at/above Minor; fail-closed platform auth, path-injection double-guard (validateStackID + url.PathEscape), IBE identity=stackID consistent, on-chain env fully removed, sentinel skips fetch+cache. One below-Minor stale comment fixed in 532b279. Gates: build clean, gofmt clean, lint 0 on touched pkgs, `cmd/kmsCDHHelper` + `pkg/clients/kmsClient` tests PASS. (Pre-existing unrelated flake: `pkg/blockHandler` anvil-RPC test — feature does not touch that package.)
