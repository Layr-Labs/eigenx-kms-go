# 010 — HOST_DATA vs REPORT_DATA on managed-cloud SEV-SNP

## Summary

eigenx-snp binds `cc_init_data` into the guest-chosen **REPORT_DATA** field of the
SEV-SNP report, not the launch-set **HOST_DATA** field. This is deliberate: on
AWS (and other managed CSPs that do not use the QEMU launch path) **HOST_DATA is
all-zero**, so it cannot carry the `cc_init_data` digest the way the Confidential
Containers "initdata" design intends. This doc records why, with citations and an
empirical measurement from a live AWS SEV-SNP peer-pod.

It also states the consequence that drives the open security work (see the
PR #105 review and Follow-up 1): because cc_init_data rides in a *guest-chosen*
field, the binding is only trustworthy once the report's **MEASUREMENT** is
checked against an allowlist of authorized podVM images — otherwise any genuine
SEV-SNP guest (e.g. an attacker's own VM running arbitrary code) can choose any
cc_init_data and produce a valid signature over the matching REPORT_DATA.

## The three report fields and who controls them

| Field | Size / offset | Set by | Guest can choose at attestation time? |
|---|---|---|---|
| `REPORT_DATA`  | 64 B @ `0x50` | **guest**, per report, via `SNP_GUEST_REQUEST` | **Yes** — fresh value each request |
| `MEASUREMENT`  | 48 B @ `0x90` | **AMD-SP firmware** (launch digest of the initial guest image) | No — fixed at launch, guest-immutable |
| `HOST_DATA`    | 32 B @ `0xC0` | **host / launch tooling** at `SNP_LAUNCH_FINISH` | No — fixed at launch |

(Offsets/sizes per the AMD SEV-SNP ABI Spec #56860, ATTESTATION_REPORT table;
transcribed in go-sev-guest `abi/abi.go` — `MeasurementSize=48`, `HostDataSize=32`,
`HostData = data[0xC0:0xE0]`.)

Only REPORT_DATA is under the guest's control at attestation time. That is both
why we *can* use it to carry `cc_init_data` on any platform, and why it carries
**no integrity by itself** — anyone running a real SEV-SNP guest can put anything
there.

## Why not HOST_DATA (the intended CoCo anchor)

The Confidential Containers / kata "initdata" design *intends* the launch host to
set `HOST_DATA = digest(initdata)` so a relying party can bind runtime config to
the attested launch. Per the CoCo Trustee initdata spec (`kbs/docs/initdata.md`),
the per-platform mapping is:

- Intel TDX → `mr_config_id` (48 B)
- **AMD SNP → `hostdata` (32 B)**
- Arm CCA → `CCA_REALM_PERSONALIZATION_VALUE` (64 B)

and the digest is `hash(initdata)` (sha-256 fits AMD SNP's 32 B exactly).

This works **only when the launch stack actually sets host-data**:

- **QEMU does.** `qemu/target/i386/sev.c` registers a `host-data` object property
  on `sev-snp-guest`, whose setter base64-decodes a 32-byte value into
  `struct kvm_sev_snp_launch_finish.host_data`, which is passed to
  `KVM_SEV_SNP_LAUNCH_FINISH`. If the property is omitted the struct is
  zero-initialized → HOST_DATA stays all-zero.
- **AWS does not.** The peer-pods `cloud-api-adaptor` AWS provider launches the
  confidential VM through the **native EC2 API** — `RunInstances` with
  `CpuOptions.AmdSevSnp = Enabled` — **not QEMU**. There is no `host-data`
  parameter anywhere in that launch path; the EC2 CVM launch API exposes no
  field to provide a 32-byte HOST_DATA. Pod config travels as cloud-init
  user-data, which is *not* folded into the report. So HOST_DATA is left at its
  zero default.

Evidence classification:
- **Documented:** QEMU plumbs host-data; CoCo maps initdata→hostdata; the AWS
  provider sets `CpuOptions.AmdSevSnp` and no host-data (absence of plumbing in
  `cloud-providers/aws/provider.go`).
- **Inferred-from-absence:** "AWS forces HOST_DATA to zero" is not an AMD/AWS
  spec statement — it follows from (a) no host-data in the AWS launch path and
  (b) the QEMU zero-default. We cannot inspect the AWS hypervisor directly, so
  the empirical check below is the load-bearing confirmation.

## Empirical confirmation (live AWS SEV-SNP peer-pod)

Captured from a real peer-pod report on `eigencompute-testnet-coco`
(AWS m6a, AMD Milan, 2026-06-15) by logging the parsed report fields server-side
in the eigenx-snp method:

```
host_data_hex      = 0000000000000000000000000000000000000000000000000000000000000000
host_data_all_zero = true
measurement_hex    = 507e82d27ea5b951dd765a3eb31ba5f582673b301d6983ded482d3feb066cb68979f1f11fede97687374d3a25002a15f
policy             = 33751040   (0x2030000)
vmpl               = 0
```

Readout:
- **HOST_DATA = 32 zero bytes** — confirms the claim. cc_init_data cannot be
  anchored via HOST_DATA on this platform.
- **MEASUREMENT = non-zero 48-byte launch digest** — present and usable; this is
  the field that must be allowlisted to anchor the guest to authorized code.
- **policy = 0x2030000**: DEBUG (bit 19) = 0, SMT (bit 16) = 1,
  PAGE_SWAP_DISABLE (bit 25) = 1 on a legitimately-launched pod. Note DEBUG=0
  here is *this* pod's choice — an attacker can launch with DEBUG=1, so it must
  be enforced (see below), not assumed.
- **vmpl = 0**.

How to reproduce: deploy an eigenx-snp peer-pod, and read the
`"eigenx-snp report fields"` INFO log from the KMS (fakeKMS or a real node) — it
logs `host_data_hex` / `host_data_all_zero` / `measurement_hex` / `policy` /
`vmpl` for every `/secrets` call. See `pkg/attestation/eigenx_snp_method.go`.

## Consequence for the trust model

Because the cc_init_data digest rides in guest-chosen REPORT_DATA (not in a
launch-anchored field), the REPORT_DATA match alone proves only *"some genuine
SEV-SNP guest chose this cc_init_data"* — not *"our authorized podVM did."* The
missing link is supplied by **MEASUREMENT**: pinning the report's MEASUREMENT to
an allowlist of authorized podVM launch digests proves the guest is running our
image, which is the trusted kata/helper stack that honestly reflects the real
cc_init_data into REPORT_DATA and enforces `policy.rego`.

Until MEASUREMENT (and DEBUG==0 / VMPL) are enforced, the method authenticates
"real AMD silicon" but not "authorized code" — see the PR #105 review findings
and the hardening work tracked alongside Follow-up 1.

## References

- AMD SEV-SNP ABI Specification #56860 — ATTESTATION_REPORT table; `SNP_LAUNCH_FINISH`.
- go-sev-guest v0.15.0: `abi/abi.go` (field offsets/sizes); `client/client.go`
  (REPORT_DATA is guest-supplied per request); `validate/validate.go` (`HostData`,
  `Measurement`, `GuestPolicy`, `VMPL` options).
- QEMU `target/i386/sev.c`: `host-data` property → `kvm_sev_snp_launch_finish` →
  `KVM_SEV_SNP_LAUNCH_FINISH`.
- Confidential Containers Trustee `kbs/docs/initdata.md`: AMD SNP → `hostdata` (32 B),
  digest = hash(initdata).
- cloud-api-adaptor `src/cloud-providers/aws/provider.go`: native `RunInstances` +
  `CpuOptions.AmdSevSnp=Enabled`, no host-data plumbing.
- This repo: `cmd/kmsCDHHelper/main.go` (`buildReportData` — cc_init_data →
  REPORT_DATA[32:64]); `pkg/attestation/eigenx_snp_method.go` (`Verify` — checks
  REPORT_DATA, logs report fields).
