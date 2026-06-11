# 009 — eigenx-snp Attestation Method

Design notes + tracked follow-ups for the `eigenx-snp` attestation method
(PR #105). This is the SEV-SNP sibling of the pluggable attestation
architecture introduced in [008_simpleAttestation.md](008_simpleAttestation.md).

## Requirements

Let a workload running in a Confidential Containers SEV-SNP **peer-pod**
fetch its app secrets from the threshold KMS using a raw AMD-signed SNP
report plus the `cc_init_data` document — with **no Trustee/KBS in the
verification path** (that's the `kbs-ear` method's job; eigenx-snp is the
direct path).

The user container stays unaware of attestation: a CDH plugin (Rust, in
`ecloud-platform-infra/.../confidential-containers/cdh-plugin-source/`)
shells out to the `eigenx-cdh-helper` Go binary, which drives the flow and
returns plaintext. Dispatched on `provider="eigenx"` in the sealed-secret
envelope.

## What shipped (PR #105)

- **`pkg/attestation/eigenx_snp_method.go`** — server-side method. Verifies
  the AMD chain via go-sev-guest (VLEK ASVK chain pre-loaded for
  Milan/Genoa/Turin), recomputes the 64-byte REPORT_DATA
  (`hex(SHA-256(rsa‖extra)[:16]) ‖ hex(SHA-384(cc_init_data)[:16])`),
  constant-time compares, decodes `cc_init_data`'s `base64(gzip(toml))`
  wire format, and TOML-parses `policy.rego` for the image registry +
  digest.
- **`cmd/kmsCDHHelper/`** — workload-side helper. Reads stdin request +
  `/run/peerpod/initdata`, sources SNP-bound KMS coords from
  `[data]."eigenx.toml"` (stdin overrides ignored), builds REPORT_DATA,
  pulls AA evidence, transforms AA's nested-JSON SNP shape into the legacy
  raw-bytes wire format, calls `RetrieveSecretsWithOptions`, IBE-decrypts.
- **`cmd/fakeKMS/`** — single-node KMS test harness for the e2e flow.
- **Bindings enforced server-side**: image digest, registry
  (`claims.Registry == release.Registry`), and REPORT_DATA nonce.

Trust chain: AMD HW → SNP report → `cc_init_data` (SHA-384 in REPORT_DATA
upper 16 bytes) → `policy.rego` image ref → on-chain `Release` digest +
registry.

---

## Follow-up 1: ContainerPolicy enforcement

Tracked by `TODO(eigenx)` at
[`pkg/node/handlers.go`](../pkg/node/handlers.go) (the eigenx-snp
fail-closed branch in `handleSecretsRequest`).

### Problem

An on-chain `Release` can pin **how** the container runs — `Args`,
`CmdOverride`, `Env`, `EnvOverride`, `RestartPolicy` (`types.ContainerPolicy`).
The TPM/GCP methods surface the *running* container's launch spec from the
TEE token (`tpm_method.go`: `result.Container.Args/EnvVars/RestartPolicy`
→ `claims.ContainerPolicy`), and the generic
`validateContainerPolicy(claims.ContainerPolicy, release.ContainerPolicy)`
matches them.

The SEV-SNP report carries no such launch spec, so `claims.ContainerPolicy`
is the zero value for eigenx-snp. `validateContainerPolicy` only checks
non-empty *expected* fields, so a zero-value claim would spuriously pass —
the release's pinned policy would be silently unenforced.

### Current behaviour (shipped) — fail closed

`handleSecretsRequest` refuses (HTTP 403) when `req.AttestationMethod ==
"eigenx-snp"` **and** the release pins a non-empty ContainerPolicy.
Releases that don't pin one are unaffected. This avoids the silent-bypass
gap until enforcement lands.

### Where the data already is

The running container's command/env **are** already cryptographically
committed: kata-agent enforces a `policy.rego` at runtime on every
`CreateContainerRequest`, and that rego pins the exact `OCI.Process`
(args, env, cwd). `policy.rego` is part of `cc_init_data`, which is
SHA-384-bound into REPORT_DATA's upper 16 bytes — the same binding that
already protects the image digest. So the values carry identical
integrity to the registry/digest we already trust; we just don't parse
them out.

Illustrative kata `policy.rego`:

```rego
package agent_policy

CreateContainerRequest {
    input.OCI.Process.Args == ["/bin/sh", "-c", "echo hi && sleep 3600"]
    every env in input.OCI.Process.Env {
        env in ["PORT=8080", "MODE=prod"]
    }
}
```

### Implementation options

1. **Regex/string-scrape the rego.** Brittle, and grows the attack surface
   we already had to harden against once (`stripRegoComments` exists
   because a stale image ref in a rego comment could bind the wrong
   identity — see `parseInitDataPolicy` in `eigenx_snp_method.go`). Scaling
   comment/quoting robustness to args + env arrays multiplies that risk.
   **Not recommended.**

2. **Evaluate the rego** with a real engine (`open-policy-agent/opa` or the
   `regorus` Go bindings) and query the pinned values. Correct, but pulls a
   heavy dependency into the KMS and means the KMS interprets
   attacker-supplied rego. Heavier than warranted.

3. **Dedicated structured side-channel (recommended).** Add a
   `[data]."eigenx-container-policy.toml"` key to `cc_init_data`, parsed by
   the KMS into `claims.ContainerPolicy` — exactly the pattern
   `[data]."eigenx.toml"` already uses for KMS coords. SNP-bound (same
   SHA-384), it's TOML the KMS *defines* (no rego-injection surface), and
   the deploy tooling that already emits `eigenx.toml` + `policy.rego`
   emits this from the same release spec.

   ```toml
   # cc_init_data → [data]."eigenx-container-policy.toml"
   args           = ["/bin/sh", "-c", "echo hi && sleep 3600"]
   restart_policy = "Always"
   [env]
   PORT = "8080"
   MODE = "prod"
   ```

   Trade-off: it's a *parallel* assertion to the rego rather than reading
   the rego directly, so tooling must keep the two consistent. That's a
   tooling invariant, not a security hole — kata still runtime-enforces the
   rego; the KMS check is the defense-in-depth layer.

### Sketch (option 3)

```go
// pkg/attestation/eigenx_snp_method.go
func parseInitDataContainerPolicy(ccInitData []byte) (types.ContainerPolicy, error) {
    tomlBytes, err := decodeInitDataWire(ccInitData)
    if err != nil {
        return types.ContainerPolicy{}, err
    }
    var doc initDataDoc
    if err := tomlv2.Unmarshal(tomlBytes, &doc); err != nil {
        return types.ContainerPolicy{}, err
    }
    raw, ok := doc.Data["eigenx-container-policy.toml"].(string)
    if !ok {
        return types.ContainerPolicy{}, nil // none pinned → empty, handler decides
    }
    var cp types.ContainerPolicy
    return cp, tomlv2.Unmarshal([]byte(raw), &cp)
}
```

`Verify` populates `claims.ContainerPolicy` from it; then the fail-closed
branch in `handlers.go` is **deleted**, and the existing
`validateContainerPolicy(claims.ContainerPolicy, release.ContainerPolicy)`
call enforces it for eigenx-snp exactly as it does for TPM.

### What doesn't map

kata's rego models `OCI.Process` (args, env, cwd) only. `RestartPolicy`
and `CmdOverride` are Kubernetes/release concepts, not OCI-runtime ones, so
they have no rego counterpart. Option 3's dedicated TOML can still carry
them (the deploy tooling knows them), but if we ever switch to reading the
rego directly (option 1/2) those two fields would stay unverifiable and
need an explicit decision — drop them from eigenx-snp policy, or keep the
TOML side-channel for them.

---

## Follow-up 2: Turin/Venice TCB packing

Tracked by `TODO(eigenx)` at
[`cmd/kmsCDHHelper/main.go`](../cmd/kmsCDHHelper/main.go) (`packLegacyTcb` /
`aaReportToProto`).

`packLegacyTcb` hard-codes the Milan/Genoa TCB byte layout (bootloader at
byte 0, tee at 1, snp at 6, microcode at 7). Turin/Venice introduced the
`fmc` (FMC firmware version) field and a different layout. `aaReportToProto`
currently **fails loud** when any TCB sets `fmc` (Turin/Venice), rather than
silently mis-encoding — a wrong packing would produce a `pb.Report` whose
bytes don't match the AMD-signed region, failing verification with an opaque
signature error.

The fix when we boot Turin instances: generation-aware packing matching
`virtee/sev`'s `TcbVersion::encode` (Milan/Genoa legacy layout vs
Turin/Venice layout). Until then the loud failure is the correct posture —
our cluster runs Milan/Genoa (m6a) only.
