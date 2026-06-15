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
- **MEASUREMENT = non-zero 48-byte launch digest** — present, but see the
  critical caveat below: on AWS it does NOT bind the AMI content, so it cannot
  anchor "our image."
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
honest conclusion: today the method authenticates *"real AMD SEV-SNP silicon on
AWS"* but **not** *"authorized code."* DEBUG==0 / VMPL pinning (shipped) close
the debug-leak and privilege holes, but they do not anchor image identity.

### MEASUREMENT does NOT anchor the image on AWS (verified)

The intuitive fix — allowlist the report's MEASUREMENT — **does not work on
AWS**, established two ways:

1. **Empirical.** Two podVM AMIs with genuinely different baked content
   (different `eigenx-cdh-helper` binaries: `ami-0897315fa1dd04d8d` vs
   `ami-0d13ceeb180a1f6a1`), same instance type (m6a.large, 2 vCPU), same
   region, produced the **identical** MEASUREMENT
   `507e82d27ea5b951dd765a3eb31ba5f582673b301d6983ded482d3feb066cb68979f1f11fede97687374d3a25002a15f`.

2. **Architectural (AWS docs + AWS-authored tooling).** AWS SEV-SNP measures
   only AWS's OVMF firmware + the initial vCPU state (VMSAs). OVMF chain-loads
   the AMI's bootloader/kernel/rootfs from EBS **after** `SNP_LAUNCH_FINISH`, so
   AMI content is outside the measured window. `sev-snp-measure --vmm-type=ec2`
   (authored by AWS) takes **no `--kernel/--initrd`** input — only OVMF + vCPU
   count. So MEASUREMENT is firmware+vCPU only, identical across all AMIs on a
   given OVMF version / instance shape. (AWS EC2 SEV-SNP docs; `aws/uefi`;
   `virtee/sev-snp-measure` PR #13.)

**Therefore:** allowlisting MEASUREMENT on AWS gates only on *"genuine AMD SNP +
AWS OVMF version + vCPU count"* — a value every AWS customer on that shape
shares. An attacker running arbitrary code in their own AWS m6a guest produces
the same MEASUREMENT. It is a useful firmware-genuineness check, **not** an
image-identity anchor. The `SetMeasurementAllowlist` plumbing (shipped) is
retained for that genuineness use and for non-AWS platforms, but it must not be
mistaken for image attestation on AWS.

### Why the GCP TDX demo (coco-peerpods-demo) anchored image identity and we can't

A natural objection: a sibling project (`coco-peerpods-demo`) ran attested
CoCo peer-pods "nicely" with image pinning. It did — but on a different
platform **and TEE**, and via a register SEV-SNP does not have. The distinction
matters and a common misconception (that the *boot measurement* covers the
image) is wrong on **both** platforms:

- That demo is **GCP + Intel TDX**, not AWS + AMD SEV-SNP.
- **TDX MRTD does NOT cover the app image** — same as AWS MEASUREMENT. The
  demo's own data proves it: MRTD stayed `feb748…` **unchanged across coordinator
  versions v6→v21** because "base TDVF+kernel identical" (its CLAUDE.md). MRTD
  measures the TD virtual firmware + kernel base; the coordinator/agents live in
  the rootfs, which MRTD does not cover. So "the boot measurement folds in the
  whole image" is false for TDX too.
- What anchored the **image** there was **RTMR[3]** — a TDX *runtime-extendable*
  measurement register. The CoCo launcher extends RTMR[3] with the pulled
  container's digest (`RTMR_new = SHA384(RTMR_old || SHA384(content))`), and the
  verifier pins RTMR[3]. Image identity came from RTMR[3], not MRTD.
- **SEV-SNP has no RTMR equivalent** — there is no runtime-extendable measurement
  register in the SNP report. So even the mechanism that worked on TDX is
  unavailable to us.

Corrected comparison:

| | GCP TDX (demo) | AWS SEV-SNP (this method) |
|---|---|---|
| Boot-base measurement | MRTD = TDVF + kernel | MEASUREMENT = AWS OVMF + vCPU |
| Boot measurement covers app image? | **No** (MRTD unchanged v6→v21) | No (AMI chain-loaded post-launch) |
| Runtime image-digest measurement | **RTMR[3]** (extendable) ✅ | **none** ❌ |
| On-report image-identity anchor | RTMR[3] | nothing |
| HOST_DATA usable | (TDX uses `mr_config_id`) | no — all-zero on AWS |

The honest takeaway: the limitation is not "SEV-SNP vs TDX" alone — it's that
SEV-SNP lacks runtime measurement registers, and AWS's managed launch exposes
no image-covering field. The GCP demo worked because TDX *has* RTMRs and the
launcher used them. The eigenx-snp method on AWS has neither an image-covering
boot measurement nor RTMRs.

### Every image-identity anchor on AWS SEV-SNP — exhaustively checked

We investigated whether *any* mechanism can prove "the guest is running our
authorized podVM image" from the SNP report on AWS. All are closed. The matrix,
with how each was established:

| Anchor mechanism | Works on AWS? | How established |
|---|---|---|
| MEASUREMENT covers the image | ❌ | EMPIRICAL: two AMIs, different baked binaries, same shape → identical measurement `507e82d2…`. + AWS docs/`sev-snp-measure --vmm-type=ec2` (OVMF+vCPU only, no kernel/initrd). |
| HOST_DATA = digest(cc_init_data) | ❌ | EMPIRICAL: live report HOST_DATA = 32 zero bytes. AWS launch path sets no host-data (QEMU-only feature). |
| RTMR runtime-extension (TDX-style) | ❌ | VERIFIED: SEV-SNP report proto has no RTMR/PCR fields — the register type does not exist in SNP. |
| vTPM rooted in the SNP report | ❌ | VERIFIED: NitroTPM is Nitro-host-provided (outside the SNP boundary); AWS has no paravisor; no `aws_snp_vtpm` verifier in Trustee; CAA `TEE_PLATFORM` has no AWS option; AWS provider sets only `AmdSevSnp=enabled`. (Azure's `az_snp_vtpm` works because its paravisor binds the vTPM AK into REPORT_DATA — AWS has no equivalent.) |
| Custom OVMF / UefiData / Secure Boot in report | ❌ | EMPIRICAL: decoded our live podVM's UEFI varstore with AWS's `python-uefivars` — **no PK enrolled, Secure Boot is OFF**. + OVMF is AWS-fixed (only reproducible, not replaceable); the varstore is not an input to AWS's documented measurement reproduction, so changing it would not move MEASUREMENT (strong inference). |
| SNP ID block (id_key_digest/author_key_digest) | ❌ | VERIFIED: EC2 exposes no launch-config/ID-block API — only `CpuOptions.AmdSevSnp=enabled`. |

The trust chain on AWS SNP is **hardware → AWS OVMF, and stops there.** It cannot
be extended to cover our image because (a) nothing we control enters the launch
measurement, (b) there is no report-bound register (no RTMR/PCR) to record an
extension, and (c) the one local boot-gating mechanism that could help (UEFI
Secure Boot) is both disabled in our image and unmeasured anyway.

### What it would actually take

Image attestation requires a platform that measures the image *into the
attestation report*. None of these is achievable by code we write on AWS:

1. **GCP TDX** — MRTD (firmware/kernel) + RTMR[3] (runtime container-digest
   extension). This is the path `coco-peerpods-demo` used successfully, and our
   existing `tpm` attestation method already supports `PlatformIntelTDX` /
   `PlatformGCPShieldedVM`.
2. **Azure CVM** — SEV-SNP + paravisor-bound vTPM (Trustee `az_snp_vtpm`).
3. **Bare-metal SEV-SNP** — you run the QEMU/launch stack, so measured direct
   boot folds kernel/initrd/cmdline into MEASUREMENT and/or you set HOST_DATA
   and an ID block.
4. **AWS exposing** a measured paravisor+bound vTPM, an image-covering launch
   measurement, or a report-bound NitroTPM — none exist today.

### Consequence for eigenx-snp on AWS (the honest scope)

On AWS today, the eigenx-snp method proves: *genuine AMD SEV-SNP silicon on AWS,
running AWS's OVMF, with DEBUG off and VMPL 0* (the Tier-1 `validate` checks),
and that the request's `rsa_pubkey`/`cc_init_data` are bound into REPORT_DATA.
It does **not** prove the guest is running the authorized podVM image — the
cc_init_data (and the image digest scraped from its policy.rego) is
self-asserted by the guest via guest-chosen REPORT_DATA, with no measured
anchor. This is the open item from the PR #105 review (finding M1 / the
critical): it is **not closeable on AWS** by any in-report mechanism, only by a
platform that measures the image (above). The `SetMeasurementAllowlist` plumbing
is retained for firmware-genuineness and for those platforms, but is not image
attestation on AWS.

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
- AWS EC2 SEV-SNP docs (OVMF runs before / loads the AMI; MEASUREMENT = initial
  guest memory + vCPU state): `docs.aws.amazon.com/AWSEC2/latest/UserGuide/sev-snp.html`,
  `.../snp-attestation.html`. `aws/uefi` (reproducible OVMF). `virtee/sev-snp-measure`
  PR #13 (AWS EC2 measurement: OVMF + vCPUs only, no kernel/initrd input).
- vTPM: Trustee `deps/verifier/src/az_snp_vtpm` binds the vTPM AK into the SNP
  report's REPORT_DATA (Azure paravisor) — the construction that makes SNP+vTPM
  image attestation work, and which AWS lacks. Trustee verifier list has no
  `aws_snp_vtpm`. AWS NitroTPM is Nitro-System-provided
  (`docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm.html`) — outside the
  SNP boundary, with no documented binding to the SNP report.
- CAA `src/cloud-api-adaptor/Makefile.defaults`: `TEE_PLATFORM` ∈
  {none, az-cvm-vtpm, tdx, se, cca} — no AWS/SNP-vTPM platform. Azure provider
  sets `SecurityType: ConfidentialVM` + `VTpmEnabled: true`; AWS provider sets
  none. CAA `podvm-mkosi/README.md`: measured boot + immutable rootfs are a
  stated future goal, not current.
- UEFI Secure Boot: EMPIRICAL — decoding the live podVM's UEFI varstore with
  awslabs/`python-uefivars` reports "No PK … SecureBoot will not be enabled"
  (no PK/KEK/db/dbx enrolled). AWS `uefi-variables` / `create-ami-with-uefi-
  secure-boot` docs (UefiData is the NV varstore set at register-image); OVMF
  is AWS-fixed per `aws/uefi`. EC2 SNP launch exposes only `AmdSevSnp=enabled`
  (`snp-work-launch.html`) — no ID-block API.
- coco-peerpods-demo (GCP TDX): MRTD covers TDVF+kernel only (unchanged across
  coordinator v6→v21 per its CLAUDE.md); image identity bound via RTMR[3]
  runtime extension (its docs/coco-kata-overview.md). Demonstrates the
  TDX-RTMR mechanism SEV-SNP lacks.
- This repo: `cmd/kmsCDHHelper/main.go` (`buildReportData` — cc_init_data →
  REPORT_DATA[32:64]); `pkg/attestation/eigenx_snp_method.go` (`Verify` — checks
  REPORT_DATA, runs validate.SnpAttestation, logs report fields).

## Verification status of claims in this doc

- VERIFIED EMPIRICALLY (our infra): MEASUREMENT identical across two
  different-content AMIs; HOST_DATA all-zero; UEFI Secure Boot off (no PK).
- VERIFIED IN SOURCE: no RTMR in SNP proto; CAA TEE_PLATFORM/provider wiring;
  az_snp_vtpm binding; AWS docs on OVMF/measurement/launch options.
- STRONG INFERENCE (not a single vendor sentence): AWS never states "HOST_DATA
  is unsettable" or "UefiData does not affect MEASUREMENT" or "NitroTPM is
  unbound from the SNP report" verbatim — each is composed from the
  reproduction recipe + threat model + empirical results. Flagged as such.
