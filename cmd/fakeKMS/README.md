# fakeKMS

A single-node KMS that implements the production `/secrets`, `/pubkey`, and
`/app/sign` wire format with **real attestation + real BLS/IBE crypto**, but a
faked "chain" (releases come from a TOML file) and faked DKG (one master
scalar instead of a threshold-shared one).

It exists to exercise the `eigenx-snp` attestation flow end-to-end — workload
→ CDH plugin → `eigenx-cdh-helper` → KMS → IBE-decrypted secret — on a real
SEV-SNP peer-pod without standing up Ethereum, the IAppController, or a
multi-operator DKG cluster. It is a **test harness, not a production
component**; never deploy it as a real KMS.

## What's real vs faked

| Concern | fakeKMS |
|---|---|
| Attestation verification (`eigenx-snp`) | **Real** — full AMD SEV-SNP chain + REPORT_DATA + cc_init_data binding via `pkg/attestation` |
| BLS12-381 partial signature / IBE | **Real** — `pkg/crypto` |
| RSA-encrypted partial sig in transit | **Real** — `pkg/encryption` |
| Release lookup (image digest, registry, env) | **Faked** — read from `apps.toml`, not on-chain |
| DKG / threshold | **Faked** — one master scalar, threshold-1 |
| Operator set / peering | **Faked** — advertises itself as the single operator |

## Build

```bash
go build -o fakeKMS ./cmd/fakeKMS
# or the container (build context = repo root):
docker build -t fakekms -f cmd/fakeKMS/Dockerfile .
```

## Run

```bash
# 1. Mint a master key
MASTER=$(./fakeKMS gen-key)

# 2. IBE-encrypt the app's secret env to the master key — this mirrors how a
#    real release's encrypted_env is produced. The secret env is a KEY=VALUE
#    map (repeat --kv); the plaintext is a JSON object so the workload can
#    address each variable by name. Put the printed hex in apps.toml's
#    encrypted_env for the matching app_id.
./fakeKMS encrypt-env \
  --master-key-hex "$MASTER" \
  --app-id example-app \
  --kv DB_PASSWORD=hunter2 \
  --kv API_KEY=sk-xyz
# -> 49424501...   (prefix 494245 = "IBE"; this is the IBE ciphertext of
#                   {"DB_PASSWORD":"hunter2","API_KEY":"sk-xyz"})

# 3. Serve
./fakeKMS \
  --port 8000 \
  --master-key-hex "$MASTER" \
  --apps-config /etc/fakekms/apps.toml \
  --operator-address 0x0000000000000000000000000000000000000001 \
  --enable-eigenx-snp-attestation
```

The KMS serves that `encrypted_env` verbatim in its `/secrets` response. The
attested workload IBE-decrypts it inside the TEE with the threshold-recovered
`app_private_key` (see `docs/references/new_kms.md`), then the eigenx CDH
helper merges it with the release's plaintext `public_env` (secret keys win)
and serves each variable by name to the pod's sealed env vars. The secret
plaintext never leaves the enclave and is never carried in the pod spec —
fakeKMS holds only the ciphertext.

### Flags

| Flag | Default | Notes |
|---|---|---|
| `--port` | `8000` | HTTP server port |
| `--master-key-hex` | — | BLS-12-381 master scalar (64 hex chars); `fakeKMS gen-key` mints one |
| `--apps-config` | — | path to `apps.toml` (required) |
| `--operator-address` | `0x…0001` | address advertised in `/pubkey`; the client's single-operator shim must list the same one |
| `--enable-eigenx-snp-attestation` | `true` | register the `eigenx-snp` method |
| `--snp-allow-amd-kds-fetch` | `false` | allow go-sev-guest to fetch missing AMD intermediates from KDS at verify time. **Test-only** — opens a goroutine-flood DoS surface; never enable in a real KMS |
| `--verbose` | `false` | debug logging |

## `apps.toml` schema

Each `[[apps]]` entry is one app's faked on-chain release. `app_id` and
`image_digest` are required; the rest are optional. When `registry` is set,
the KMS enforces `claims.Registry == registry` (the same step-4b check the
production handler runs).

```toml
[[apps]]
app_id        = "example-app"
image_digest  = "sha256:b58899f069c47216f6002a6850143dc6fae0d35eb8b0df9300bbe6327b9c2171"
registry      = "docker.io/library/alpine"   # optional; enables registry binding
encrypted_env = "49424501..."                 # hex IBE ciphertext of {"KEY":"VALUE",...} from `fakeKMS encrypt-env`
public_env    = '{"LOG_LEVEL":"info"}'        # optional, plaintext JSON {"KEY":"VALUE"}; merged under the secrets
# Optional container-policy fields (args / env / env_override / restart_policy):
# container_args = ["sh", "-c", "..."]
# restart_policy = "Always"
```

The app's environment is a flat key→value map. `encrypted_env` is the IBE
ciphertext of the **secret** env as a JSON object (produced by `fakeKMS
encrypt-env` above); `public_env` is the **plaintext** env as a JSON object.
The helper merges them (secret keys win on collision) and serves each variable
by name — one sealed env var in the pod spec per key. Per
`docs/references/new_kms.md`, `encrypted_env` is decrypted in-TEE with the
recovered app private key; `public_env` is surfaced verbatim.

## Endpoints

- `GET  /pubkey`  — commitments + master public key
- `POST /secrets` — full attestation flow, returns RSA-encrypted partial sig + release
- `POST /app/sign` — partial signature for an app id
- `GET  /healthz` — liveness

## Cluster deployment

Deploying fakeKMS into a test cluster (Service/NodePort, the apps ConfigMap,
the KDS-fetch flag) is an infra concern and lives outside this repo — it is a
test harness, not a managed component, so its image repository and manifests
are kept with the cluster tooling rather than under this repo's build/IaC.
