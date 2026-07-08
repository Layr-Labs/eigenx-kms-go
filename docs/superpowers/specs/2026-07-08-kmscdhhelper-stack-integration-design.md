# kmsCDHHelper → ecloud-platform Stack Integration — Design

**Date:** 2026-07-08
**Status:** Design — pending review
**Repos:** `eigenx-kms-go` (this repo, `github.com/Layr-Labs/eigenx-kms-go`, @655fb97) + `ecloud-platform` (`/Users/seanmcgary/Code/ecloud-platform`, `github.com/Layr-Labs/ecloud-platform`, @1636f637)
**Follows:** `docs/superpowers/specs/2026-07-02-ecloud-platform-integration-design.md` (PR #120 — the KMS server/operator side of this integration)

## 1. Overview & Scope

PR #120 taught the KMS operator to authorize `/secrets` requests against the
**ecloud-platform** when a request carries a `stack_id`, and — critically — on that
platform path the operator returns **only the encrypted partial key share, no env**.
The platform owns application secrets itself.

`cmd/kmsCDHHelper` is the stdin/stdout child binary the CDH (Confidential Data Hub)
plugin spawns inside a SEV-SNP peer-pod to unseal a workload's environment variables.
Today it assumes the **old on-chain model**: the KMS `/secrets` response carries the
release's `encrypted_env` / `public_env`, which the helper IBE-decrypts and merges.
That model no longer applies to stack-based apps.

This design **converts the helper to the stack model**:

- The KMS `/secrets` call is made on the **platform (`stack_id`) path** and yields only
  the recovered **app-private-key** (`S·H(stackID)`); its env fields are ignored.
- The plaintext environment is assembled by fetching each secret's **ciphertext from
  ecloud-platform's `InternalSecretsService.ListSecrets(stack_id)`** and **IBE-decrypting
  each value** with the recovered key, inside the TEE.

### Decisions locked during brainstorming

| Question | Decision |
| --- | --- |
| Keep the on-chain path, or move to stack-only? | **Stack-only.** Remove the on-chain `encrypted_env`/`public_env` decode + merge path from the helper entirely. The app model has moved to stacks driven by the ecloud-platform API. |
| How does the helper discover the platform secrets endpoint + auth? | **From `cc_init_data`** (SNP-bound). Add `platform_secrets_url` and `platform_internal_api_key` to the `[data]."eigenx.toml"` block, alongside the existing KMS coords. They inherit the same SEV-SNP REPORT_DATA integrity binding as `kms_url`/`avs_address`/etc. |
| `app_id` / `stack_id` / IBE-identity relationship | **`stack_id` replaces `app_id`** as the single identity. The CLI seals secrets with `EncryptForApp(stackID, master, …)` (IBE identity = `stackID`); the KMS signs `H(identity)`; so the helper sends `stack_id` as the KMS signing identity AND uses it as the IBE-decrypt identity. There is no separate `app_id` in the helper anymore. |
| How to call `InternalSecretsService` | **HTTP gateway** (`GET /internal/v1/stacks/{stack_id}/secrets`, `Authorization: Bearer <internal_api_key>`), not a generated gRPC client. Matches the helper's existing `net/http` idiom and adds no proto/grpc codegen to this standalone binary. The internal route is reachable only by the helper over the trusted internal network. |

### Out of scope

- **KMS server-side changes** — the `stack_id` platform path shipped in PR #120 and is
  unchanged here.
- **The CDH plugin / kata-agent contract** — still one helper invocation per sealed env
  var. The plugin populating `stack_id` (rather than `app_id`) on stdin is a plugin-side
  change; the helper sources identity from SNP-bound `cc_init_data` regardless, so it does
  not depend on the plugin's stdin fields for identity.
- **gRPC/proto codegen in the helper** — the HTTP gateway is used.
- **The single-operator fakeKMS shim** (`kms_url` + `EIGENX_ALLOW_SINGLE_OPERATOR_KMS`)
  stays as-is for e2e testing of the attestation path.

## 2. Grounding: verified facts

### Secret model (ecloud-platform @1636f637)
- **Secrets are per-stack, individually IBE-sealed by the CLI.**
  `ecloud-cli/internal/kmscipher/kmscipher.go`:
  ```go
  func (e kmsEncrypter) Encrypt(plaintext []byte) ([]byte, error) {
      return kmscrypto.EncryptForApp(e.stackID, e.master, plaintext) // identity = stackID
  }
  ```
  The master public key is fetched via `StackService.GetStackPublicKey(stackID)`
  (`ecloud-cli/cmd/secrets/secrets.go:114`). Each secret value is sealed **independently**
  (per `{name, value}`), not as one combined env blob.
- **`InternalSecretsService.ListSecrets`** (`protos/eigenlayer/platform/v1/internalsecrets/`)
  returns per-secret opaque ciphertext for a stack:
  ```proto
  message InternalSecret { string name = 1; bytes value = 2; } // value = opaque, pre-encrypted
  message InternalListSecretsRequest  { string stack_id = 1; }
  message InternalListSecretsResponse { repeated InternalSecret secrets = 1; }
  ```
  Service comment: "called by the operator / CoCo VM to fetch encrypted secret values for
  a stack during pod initialization … decryption happens inside the CoCo VM using the
  KMS-managed key."
- **HTTP gateway route** (generated `rpc.pb.gw.go`):
  `GET /internal/v1/stacks/{stack_id}/secrets`. Response is protojson:
  `{"secrets":[{"name":"FOO","value":"<base64-std>"}]}` — proto `bytes` marshal as
  base64 strings.
- **Auth:** the internal server gates `ListSecrets` with the static internal API key via
  `ApiKeyUnaryInterceptor`, read from the `Authorization: Bearer <key>` header
  (`pkg/rpcServer/internalServer.go:34,39-44,99,105`). It lives on the internal gRPC
  server (default 9002) + its HTTP gateway (grpcPort+1, e.g. 9003), never on the public
  ALB. No per-tenant context — the caller names `stack_id` explicitly.

### KMS operator/client side (this repo @655fb97)
- **The `/secrets` platform path returns only the key share.** `pkg/node/handlers.go:315`
  keeps `release` nil on the `stack_id` path; `:474-477` only fills `EncryptedEnv`/
  `PublicEnv` when `release != nil`. So `SecretsResponseV1.EncryptedEnv`/`PublicEnv` are
  **empty** on the platform path.
- **The KMS always signs `H(req.AppID)`.** `handlers.go` computes the partial sig via
  `signAppIDWithVersion(req.AppID, …)` on both paths; the platform path does not change
  the signing identity. `claims.AppID == req.AppID` is enforced (`handlers.go:~287`).
  ⇒ To recover a key that opens secrets sealed to identity `stackID`, the helper must send
  `req.AppID = stackID`.
- **`SecretsRequestV1.StackID`** exists (`pkg/types/types.go:136`) and is the platform
  switch: non-empty ⇒ platform path.
- **`kmsClient` does NOT wire `StackID` yet.** `SecretsOptions` has no `StackID` field and
  `createEigenXSNPAttestationRequest` never sets `req.StackID`
  (`pkg/clients/kmsClient/client.go`). **This design adds it** — without it the helper
  cannot reach the platform path.
- **IBE primitives** (`pkg/crypto/bls.go`):
  ```go
  func EncryptForApp(appID string, masterPublicKey types.G2Point, plaintext []byte) ([]byte, error)
  func DecryptForApp(appID string, appPrivateKey types.G1Point, ciphertext []byte) ([]byte, error)
  ```
  The `appID` arg is the IBE identity. Seal-side uses `stackID`; open-side must use the
  same `stackID`.
- **`RetrieveSecretsWithOptions`** (`client.go:552`) returns `*SecretsResult` with
  `AppPrivateKey types.G1Point`, `Verified bool`, and (on the platform path, empty)
  `EncryptedEnv`/`PublicEnv`.

### Helper today (`cmd/kmsCDHHelper` @655fb97)
- `Request{ KMSURL, AVSAddress, OperatorSetID, RPCURL, OperatorAddress, AppID, Key }`
  (`main.go:128`). Identity is `AppID`.
- `initdataKMSConfig{ KMSURL, AVSAddress, OperatorSetID, RPCURL, OperatorAddress }`
  (`main.go:149`), parsed from `[data]."eigenx.toml"`.
- `applyInitdataKMSConfig` (`main.go:414`) makes SNP-bound initdata win over stdin for the
  KMS coords, validates URL schemes via `validateHTTPURL` (`main.go:480`), and gates the
  single-operator `kms_url` path behind `EIGENX_ALLOW_SINGLE_OPERATOR_KMS`.
- `retrieveAndDecrypt` (`main.go:642`) calls `RetrieveSecretsWithOptions`, then either
  emits the `appPrivateKeyKey` sentinel or IBE-decrypts `result.EncryptedEnv` and
  `mergeEnv`s it under `result.PublicEnv`.
- `env_cache.go`: `mergeEnv(publicEnvJSON, secretPlaintext)`, `emitKey`, and a per-app
  tmpfs cache keyed by `cachePath(appID)`.
- `appPrivateKeyKey = "__EIGENX_APP_PRIVATE_KEY__"` sentinel (`main.go:176`) returns the
  raw recovered key (hex compressed G1) and is never cached (`cacheable`, `main.go:183`).

**Verified external API (do not re-derive)**
```go
// pkg/crypto/bls.go
func DecryptForApp(appID string, appPrivateKey types.G1Point, ciphertext []byte) ([]byte, error)

// pkg/clients/kmsClient/client.go
type SecretsOptions struct { /* … existing fields … */ }         // add: StackID string
func (c *Client) RetrieveSecretsWithOptions(appID string, opts *SecretsOptions) (*SecretsResult, error)
type SecretsResult struct {
    AppPrivateKey types.G1Point
    EncryptedEnv  string // empty on platform path
    PublicEnv     string // empty on platform path
    Verified      bool
    /* … */
}

// pkg/types/types.go
type SecretsRequestV1 struct { AppID string; StackID string; AttestationMethod string; /* … */ }

// ecloud-platform InternalSecretsService HTTP gateway (@1636f637)
//   GET {platform_secrets_url}/internal/v1/stacks/{stack_id}/secrets
//   Header: Authorization: Bearer <internal_api_key>
//   200 body (protojson): {"secrets":[{"name":"<string>","value":"<base64-std bytes>"}]}
```

## 3. Data flow

```
stdin Request{ stack_id?(ignored for identity), key }
  │
  ├─ cache fast-path (keyed by stack_id) ─── hit ──▶ emitKey
  │
  ├─ read /run/peerpod/initdata → decode → parse [data]."eigenx.toml"
  │     initdataKMSConfig{ kms_url?, avs_address, operator_set_id, rpc_url,
  │                        operator_address?, stack_id,
  │                        platform_secrets_url, platform_internal_api_key }
  │     applyInitdataKMSConfig: initdata wins; validate schemes; require
  │       stack_id + platform_secrets_url + platform_internal_api_key
  │
  ├─ RSA keypair ▶ REPORT_DATA ▶ fetch AA evidence ▶ transformAAEvidence  (unchanged)
  │
  ├─ RetrieveSecretsWithOptions(stackID, eigenx-snp, opts.StackID=stackID)
  │     → SecretsResult{ AppPrivateKey, Verified }   (env fields ignored)
  │
  ├─ key == __EIGENX_APP_PRIVATE_KEY__ ?
  │     yes ▶ emitAppPrivateKey(result) ── return (no secrets fetch, never cached)
  │
  ├─ fetchStackSecrets(platform_secrets_url, api_key, stackID)
  │     → [] { Name, Value(ciphertext bytes) }
  │
  ├─ for each secret: crypto.DecryptForApp(stackID, AppPrivateKey, Value)
  │     → env[name] = plaintext            (hard-fail if any value won't open)
  │
  ├─ storeCachedEnv(stackID, env)          (best-effort)
  └─ emitKey(env, key)
```

## 4. Components

### 4.1 `pkg/clients/kmsClient/client.go` — wire `StackID`
- Add `StackID string` to `SecretsOptions`.
- In `createEigenXSNPAttestationRequest`, set `req.StackID = opts.StackID`.
- No behavior change when `StackID == ""` (empty ⇒ existing on-chain path; all current
  callers/tests unaffected).

### 4.2 `cmd/kmsCDHHelper/main.go`
- **`Request`**: replace `AppID string \`json:"app_id"\`` with `StackID string
  \`json:"stack_id"\``. `Key` unchanged. `readRequest` requires `stack_id` + `key`.
  (KMS-coord stdin fields remain, still overridden by initdata.)
- **`initdataKMSConfig`**: add
  ```go
  StackID                string `toml:"stack_id"`
  PlatformSecretsURL     string `toml:"platform_secrets_url"`
  PlatformInternalAPIKey string `toml:"platform_internal_api_key"`
  ```
- **`applyInitdataKMSConfig`**: after the existing KMS-coord handling, require non-empty
  `stack_id`, `platform_secrets_url`, `platform_internal_api_key`; validate
  `platform_secrets_url` via `validateHTTPURL`. Set `req.StackID`, and stash the platform
  secrets URL + key onto the request (new `Request` fields, sourced only from initdata —
  never from stdin, same rationale as the KMS coords). initdata wins over any stdin
  values.
- **`retrieveAndDecrypt`**: pass `StackID: req.StackID` in `SecretsOptions`; call
  `RetrieveSecretsWithOptions(req.StackID, opts)`. After recovery:
  - sentinel path (`req.Key == appPrivateKeyKey`) unchanged — `emitAppPrivateKey`.
  - otherwise call `fetchStackSecrets` + assemble the env map via `DecryptForApp(stackID,
    result.AppPrivateKey, value)` per secret. Remove the `decodeEncryptedEnv` /
    `result.EncryptedEnv` / `mergeEnv(result.PublicEnv, …)` logic.
- `decodeEncryptedEnv` is **removed** (no KMS-returned env to decode).
- All remaining `req.AppID` references become `req.StackID`.

### 4.3 `cmd/kmsCDHHelper/platform_secrets.go` (new)
```go
// fetchStackSecrets GETs the stack's sealed secrets from the ecloud-platform
// InternalSecretsService HTTP gateway and returns each {name, ciphertext}.
func fetchStackSecrets(baseURL, apiKey, stackID string) ([]stackSecret, error)
type stackSecret struct { Name string; Value []byte }
```
- `net/http` GET `{baseURL}/internal/v1/stacks/{stackID}/secrets`, header
  `Authorization: Bearer <apiKey>`, bounded timeout + `io.LimitReader` body cap (mirror
  `fetchAAEvidence` constants/patterns). URL-escape `stackID` in the path.
- Non-200 ⇒ error (surface capped body). Decode `{"secrets":[{"name","value"}]}`; `value`
  is base64-std → raw ciphertext bytes (Go unmarshals a JSON `[]byte` field from a base64
  string automatically).

### 4.4 `cmd/kmsCDHHelper/env_cache.go`
- Remove `mergeEnv` (no public/secret merge — the decrypted stack secrets ARE the env).
- Cache keyed by `stackID` (rename the `appID` param to `stackID`; `cachePath` sanitization
  unchanged — a stack UUID is filesystem-safe).
- `emitKey`, tmpfs locking, atomic write: unchanged.

## 5. Error handling (fail-closed)

| Condition | Behavior |
| --- | --- |
| initdata missing `stack_id` / `platform_secrets_url` / `platform_internal_api_key` | hard error before any network call |
| `platform_secrets_url` not http(s) | hard error (`validateHTTPURL`) |
| `RetrieveSecretsWithOptions` fails / degraded for sentinel key | existing behavior (`emitAppPrivateKey` refuses unverified) |
| `ListSecrets` unreachable / non-200 / malformed JSON | hard error, diagnostic on stderr |
| a secret value fails `DecryptForApp` | hard error (a sealed value we can't open is a real fault, not an empty secret) |
| empty secret list | empty env map; `emitKey` then fails loud if `key` is absent |
| requested `key` absent from decrypted env | hard error (`emitKey`, unchanged) |

## 6. Testing

- **`kmsClient`**: `SecretsOptions.StackID` flows into `req.StackID` for the eigenx-snp
  builder; empty `StackID` leaves it unset (table test on `createEigenXSNPAttestationRequest`).
- **`applyInitdataKMSConfig`**: new required fields enforced; `platform_secrets_url` scheme
  rejection; initdata-wins over stdin; stack_id required.
- **`fetchStackSecrets`**: `httptest.Server` — happy path (asserts `Authorization: Bearer`
  header + path, decodes base64 values), non-200, malformed JSON, oversized-body cap.
- **`retrieveAndDecrypt` env assembly**: round-trip — `EncryptForApp(stackID, master, v)`
  for a few names, stub the KMS client to return the matching `AppPrivateKey`, assert each
  is opened and assembled by name; assert a value sealed to a *different* identity fails.
- **Sentinel**: `__EIGENX_APP_PRIVATE_KEY__` emits the raw key and does NOT call
  `fetchStackSecrets` / touch the cache.
- **Cache**: keyed by `stack_id`; fast-path hit skips attestation + fetch.
- Full gates: `./scripts/goTest.sh` (per project convention), `make fmtcheck`, `make lint`,
  `go build ./...`.

## 7. File inventory

New:
- `cmd/kmsCDHHelper/platform_secrets.go` (+ `platform_secrets_test.go`)

Modified:
- `pkg/clients/kmsClient/client.go` — `SecretsOptions.StackID`; set `req.StackID` in
  `createEigenXSNPAttestationRequest`
- `cmd/kmsCDHHelper/main.go` — `Request` (stack_id + platform fields), `initdataKMSConfig`,
  `applyInitdataKMSConfig`, `retrieveAndDecrypt`; remove `decodeEncryptedEnv`
- `cmd/kmsCDHHelper/env_cache.go` — remove `mergeEnv`; key cache by `stack_id`
- `cmd/kmsCDHHelper/main_test.go`, `env_cache_test.go` — updated for the stack model

## 8. Open items (resolve during planning/impl)

1. **Exact initdata TOML key names** — `platform_secrets_url` / `platform_internal_api_key`
   proposed; confirm they match whatever the CDH plugin / CAA will actually write into
   `[data]."eigenx.toml"`.
2. **`stack_id` on stdin vs initdata** — identity comes from SNP-bound initdata (secure).
   Confirm whether the plugin should still send `stack_id` on stdin for logging/consistency
   (tolerated + ignored for identity, like the KMS coords today).
3. **Base URL shape** — whether `platform_secrets_url` is the gateway root (helper appends
   `/internal/v1/stacks/{id}/secrets`) or a fuller prefix. Proposed: root; pin during impl.
