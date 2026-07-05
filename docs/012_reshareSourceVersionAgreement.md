# 012 — Reshare Source-Version Agreement

## Status

**Implemented** (branch `sm-kmsFix`). Fixes a master-secret corruption reproduced on
`kms-preprod-sepolia` (image `v0.3.3_fd99a16`, cluster freshly re-DKG'd 2026-07-02 20:43Z)
that PR #110 (`docs/011_reshareDealerSetAgreement.md`) did **not** prevent.

### As-built summary

All three layers landed, test-first:

- **Layer 1 — MPK validation.** `reshare.ValidateReshareMasterPublicKey` recomputes
  `Σ_{d∈D} λ_d(D)·C_d[0]` and requires it to equal the carried-forward MPK; wired into
  finalize (`node.go`) before persist. Any source-version or dealer-set divergence →
  refreshed shares don't reconstruct the served MPK → **loud abort, never persist**.
  Corruption is now impossible.
- **Layer 2 — source-version agreement.** Dealers advertise the version they deal FROM in
  `CommitmentMessage.SourceVersion`; finalize calls `reshare.SelectMajoritySourceVersion`
  to keep only dealers on the majority source version (deterministic across nodes) and
  drop laggards. A dropped laggard recomputes its own share as a recipient of the kept
  dealers, resyncing. **Ties and sub-threshold majorities abort** (conservative; Layer 1
  backstops any residual divergence). Added exact-match `keystore.GetPrivateShareForVersion`
  (errors on absence — never a nearest-match, which would reintroduce the bug).
- **Layer 3a — share retention.** Generated shares are retained at the node level
  (`retainGeneratedShares`, bounded to the last `retainedShareRounds = 4` rounds,
  **memory-only**) past session teardown; `handleReshareShareRequest` falls back to them
  when the live session is gone. This removes the incident's actual **503 trigger**, so the
  lag that caused the split no longer forms. A restart drops the store → degrades to the
  pre-existing abort-and-retry, never to corruption. Cross-round catch-up beyond the
  retention window (Layer 3b) is deferred: a node down longer than `K` rounds re-joins via
  the existing new-operator path.

Regression coverage: `pkg/reshare/mpk_validation_test.go` (uniform passes / mixed-source
fails / missing-commitment errors), `pkg/reshare/source_version_test.go` (selection rules +
`TestLayer2_MixedSourceRoundReproducedAndFixed` end-to-end: unfiltered reconstructs
`S'' != S`, filtered preserves `S`), `pkg/keystore/keystore_test.go`
(`GetPrivateShareForVersion` exact-match/no-fallback), `pkg/node/share_retention_test.go`
(survives teardown / bounded eviction / returns a copy). Existing dealer-agreement
integration tests still pass unchanged.

## Summary

PR #110 made all operators agree on the **dealer set within a reshare round**. It did
**not** make them agree on the **source key version they deal from across rounds**. When
one operator aborts a round (correctly, via #110's abort-retry) while the others complete,
the cluster enters a **version split**: the aborting node stays on version `N-1`, the
others advance to `N`. On the *next* round every node deals from its own local active
share — mixing shares anchored on two different polynomials — which silently re-corrupts
the master secret. Because the version *number* is a shared timestamp, all nodes still
report identical `new_version`, so the split is invisible in logs and metrics.

## Live evidence

A 15-minute ECDSA encrypt/decrypt soak (genesis ciphertext held constant + a fresh
round-trip each iteration) caught it:

```
iter=0  genesis-durability=PASS  fresh-roundtrip=PASS
iter=1  genesis-durability=PASS  fresh-roundtrip=PASS
iter=2  genesis-durability=PASS  fresh-roundtrip=PASS
iter=3  genesis-durability=FAIL  fresh-roundtrip=FAIL      <-- both fail
iter=4  genesis-durability=FAIL  fresh-roundtrip=FAIL
```

Manual reproduction (fresh encrypt, seconds-old ciphertext):

```
failed to recover valid app private key: all 3 combinations exhausted
(had 3 signatures, needed 2 valid)
```

The *fresh* round-trip failing (not just the genesis one) rules out key drift on the
stored ciphertext and proves the live cluster is serving a key that no longer matches its
published MPK.

> **Precise mechanism (corrected).** After the corrupt round the three nodes' refreshed
> shares are **mutually consistent** — they all lie on the same combined polynomial
> `G(z) = Σ_{i∈D} λ_i(D)·f'_i(z)`. They are consistent shares of the **wrong** secret
> `S'' = Σ λ_i·x_i` (Lagrange interpolation at 0 of the mismatched source points `x_i`),
> not of the original `S`. Decrypt fails because `VerifyAppPrivateKey`
> (`pkg/crypto/bls.go`) rejects the recovered `sk(S'')` against the **carried-forward**
> `MPK(S)`. This distinction matters for Layer 1 below: `Σ λ_i·C_i[0] = S''·G2 ≠ S·G2`, so
> the MPK check is exactly the right discriminator.

### Reshare timeline (from operator logs)

| Time (UTC) | op1 (0x144c…) | op2 (0x0351…) | op3 (0x04f6…) |
|-----------|---------------|---------------|---------------|
| 21:26:08  | completed `…027560` | completed `…027560` | completed `…027560` |
| 21:28     | **ABORT** — 503 fetching op3's share; stays `…027560` | completed `…027680` | completed `…027680` |
| 21:30:08  | completed `…027800` | completed `…027800` | completed `…027800` |
| 21:32:08  | completed `…027920` | completed `…027920` | completed `…027920` |

op1's 21:28 abort (`node.go:1940`, "could not obtain a dealer in the agreed set",
`missing_dealer=op3`, `status 503 for share request`) left it a version behind. At 21:30
all three "complete" on the same version *number* — but op1 dealt from its stale
`…027560` share while op2/op3 dealt from `…027680`. From 21:30 onward the shares no longer
lie on one polynomial. Corruption is permanent until a state reset.

## Root cause

Two distinct defects combine. Either alone is survivable; together they produce silent
permanent corruption.

### Defect A — no cross-round agreement on the *source* version (the corrupting defect)

Reshare dealing reads the node's **local** active share with no cross-node agreement on
which version is being refreshed:

```go
// pkg/node/node.go:1558
currentShare, err := n.keyStore.GetActivePrivateShare()
...
// pkg/node/node.go:1567
shares, commitments, err := n.resharer.GenerateNewShares(currentShare, newThreshold)
```

`ComputeNewKeyShare` reconstructs each refreshed share by Lagrange interpolation over the
dealers' polynomials. That is only a valid re-sharing of the *same* secret `S` if every
dealer's polynomial is anchored at its share **of the same source polynomial** — i.e.
every node must deal from the same source version. #110 guarantees a common *dealer set*;
nothing guarantees a common *source version*. Once a single abort desynchronizes versions,
the next round interpolates across two polynomials and yields shares of neither `S`.

### Defect B — abort trigger: share-fetch 503 after the dealer completes (the trigger)

The on-demand share fetch #110 added cannot serve a share for a round the dealer has
already finished. On completion the dealer tears down its session
(`defer n.cleanupSession(...)`, `node.go:1577`), so a lagging requester hits:

```go
// pkg/node/handlers.go:686
session := s.node.waitForSession(reqMsg.SessionTimestamp, 5*time.Second)
if session == nil {
    http.Error(w, "Session not found", http.StatusServiceUnavailable) // 503
    return
}
```

The generated shares live only on `session.myGeneratedShares` (`node.go:110-115`), which
dies with the session. A node that lags by even a few seconds — exactly the partition
symptom #110 documents — can no longer fetch, so it aborts. #110 correctly makes that
abort non-corrupting *within* the round, but Defect A turns the resulting version lag into
corruption on the *following* round.

### Defect C — no post-reshare MPK validation (the missing safety net)

Design 011 step 5 ("Validate before commit … recompute/validate the served MPK against
the post-reshare commitments; if validation fails, abort") was never implemented.
Finalize instead **blindly carries the old MPK forward**:

```go
// pkg/node/node.go:1969-1973
// Carry forward MPK from the current active version (MPK doesn't change during reshare)
if currentVersion := n.keyStore.GetActiveVersion(); currentVersion != nil && currentVersion.MasterPublicKey != nil {
    mpkCopy := *currentVersion.MasterPublicKey
    newKeyVersion.MasterPublicKey = &mpkCopy
}
```

Had this step validated `Σ newCommitments[0]` (the refreshed group secret's public point)
against the carried-forward MPK, the 21:30 divergence would have been caught and aborted
loudly at the source, instead of silently corrupting and surfacing only at decrypt time.

## Why #110 didn't catch this

| | #110 (dealer-set agreement) | This proposal (source-version agreement) |
|---|---|---|
| Agrees on | dealer set *within* a round | source version *across* rounds |
| Failure it prevents | mixed dealer sets in one round | dealing from mismatched source shares |
| Symptom if violated | "all combinations exhausted" | identical — "all combinations exhausted" |
| Visible in versions? | n/a | **After the corrupt round, no** — the post-round version *label* is a shared timestamp, so all nodes report the same `new_version` while their shares diverge. **Before/at dealing time, yes** — the lagging node's *active* version number differs from the quorum's, and that difference is the signal Layer 2 exploits. |

The symptoms are identical, which is why this looked like "#110 didn't work." It did work,
for its scope; this is an adjacent, unaddressed axis of disagreement.

## Proposed fix

Three layers, in priority order. Layer 1 stops corruption immediately (loud abort); Layers
2–3 restore liveness so aborts don't accumulate into a wedged cluster.

### Layer 1 — Post-reshare MPK validation (implements 011 step 5). PRIORITY.

In finalize, before persisting, recompute the group public point from the post-reshare
commitments and require it to equal the carried-forward MPK. On mismatch, **abort and
retry** — never persist a divergent share.

- Location: `pkg/node/node.go` ~1969 (replace the blind carry-forward).
- Check: the refreshed sharing's public constant term (`Σ_{i∈D} λ_i(D)·C_i[0]`, the same
  reconstruction `ComputeNewKeyShare` performs, lifted to G2) must equal
  `currentVersion.MasterPublicKey`. Reuse the existing commitment math; do not invent a
  second code path.
- Effect: converts silent corruption into a retryable abort. This is the stop-gap that
  makes the cluster **safe from corruption** even before Layers 2–3 land — analogous to
  #110's strict guard. **It is not a complete stop-gap:** see the liveness caveat below.

> **Layer-1-alone liveness caveat (do not understate this).** Layer 1 does **not** touch
> the trigger (Defect B) or the source of divergence (Defect A). Trace it: round N, a node
> hits a 503 and aborts, falling a version behind (Defect B, untouched). Round N+1: the
> remaining nodes deal from the new version, the behind node from its stale version →
> mixed sources → the Layer-1 check **fails on every node, every round, from now on.** A
> single transient blip thus converts silent corruption into a **permanent rotation
> stall** — not merely "may stall under partition." During the stall, decrypt survives
> only via the same-version subset (op2+op3), i.e. with n=3 the cluster is **one node
> fault away from a decrypt outage** and forward-secrecy rotation (TDD Goal 7) is suspended
> indefinitely with all operators honest and online. **Therefore:** shipping Layer 1 alone
> is correct (no corruption) but requires a **hard alert on the validation-abort log line**
> and a runbook noting the degraded-decrypt risk. Layers 2–3 are what restore the "worst
> case is a wasted round" guarantee; Layer 1 alone does not provide it.

### Layer 2 — Agree on the source version (fixes Defect A).

Make every dealer's source version an explicit, checked part of the round. **Do not** try
to derive an "expected" source version from trigger timestamps — the previous *boundary
timestamp* is shared, but the previous *finalized version* is local knowledge (in the
incident op1's latest is `…560`, the quorum's is `…680`; a cluster-wide Layer-1 abort can
even leave the "previous version" as one **nobody** holds). Instead, agree by broadcast +
unanimity:

- Each dealer includes its **own active version number** as `SourceVersion` in the
  `CommitmentMessage` (and the new-operator path receivers apply the same check).
- Finalize requires **all dealers in the agreed set `D` to report one identical
  `SourceVersion`**; otherwise abort-and-retry. Per the corrected Claim D, the active
  version number *at dealing time* is exactly the discriminator — no chain-derived
  expected value is needed.
- A dealer whose active version is **behind** the quorum must **abstain from dealing** and
  catch up (Layer 3) before it may contribute; it can never inject a stale-source
  polynomial.
- **Bind `SourceVersion` into the on-chain `commitmentHash`** (the value submitted to the
  registry at finalize) so source-version equivocation is detectable/slashable through the
  existing #110 registry machinery, not just via the P2P broadcast.
- **Also pin `expectedReshareDealers`.** #110 derives the candidate dealer set from the
  **local** `activeVersion.ParticipantIDs` (`node.go:787-809`); under a split the two
  sides feed divergent ParticipantIDs into #110's "agreement." Taking ParticipantIDs from
  the **agreed source version** closes this implicitly — call it out explicitly in
  implementation.

Requires a new keystore primitive (see below): an **exact-match** version accessor.

### Keystore primitive (prerequisite for Layer 2).

The keystore today exposes only `GetActivePrivateShare`, `GetActiveVersion`, and
`GetKeyVersionAtTime`. **`GetKeyVersionAtTime` must not be used here** — it returns the
latest version `<= t` (`keystore.go` `GetKeyVersionAtTime`), so a behind node asking for
the quorum's newer version would silently get its **stale** version back and recreate the
exact bug. Add `GetPrivateShareForVersion(version)` / `GetVersion(version)` that return an
**error on absence** (never a nearest-match), and have the behind node treat that error as
"I must catch up, not deal."

### Layer 3 — Serve shares for completed rounds (fixes Defect B; enables catch-up).

Stop the 503 that triggers the lag, and enable a behind node to finalize a round it missed:

- Retain the finalized per-recipient generated shares **past session teardown**, keyed by
  version, bounded to the last `K` rounds (K = 2–3 is ample at a ~2-min interval).
  `handleReshareShareRequest` serves from that store instead of requiring a live session.
- **Persistence decision (must be explicit).** The keystore/sessions are in-memory; a
  dealer **restart** currently also yields the 503. If retention is memory-only, restarts
  still abort (acceptable, rarer); if persisted, then per-recipient shares for other
  operators now sit **at rest across rounds**, which extends #110's exposure argument —
  #110 argued only about the *wire* ("exposes nothing the original send didn't"); at-rest
  retention for K rounds means a dealer compromise leaks shares for versions still active
  on lagging nodes. Choose memory-only unless restart-survival is required, and if
  persisted, encrypt at rest (TDD production requirement) and argue the delta.
- **Catch-up is a real protocol path, not just a fetch.** Layer 2's "abstain and catch up"
  requires a behind node to finalize round N (fetching every missed dealer's share for the
  agreed source version) possibly while round N+1 is starting. Specify: catch-up depth is
  bounded by `K` (a node that missed > K rounds cannot catch up and must re-join via the
  new-operator path); the 2-of-3-behind case correctly stalls (the lone advanced node has
  `|D| = 1 < t`) until at least one laggard catches up. This makes Layer 3
  **correctness-critical for Layer 2's liveness**, not merely a "nice to have."

### Interaction / correctness argument

- Layer 1 alone guarantees **no corruption**, but (see caveat) can permanently stall
  rotation after one blip — it is a corruption stop-gap, not a liveness-preserving fix.
- Layer 2 removes the *source* of divergence (mismatched-source dealing can no longer be
  finalized) so Layer 1 fires only on genuine faults.
- Layer 3 removes the *trigger* (503) and provides the catch-up that lets a behind node
  rejoin the agreed source version, so Layer 2's "abstain if behind" resolves quickly.
- Only with all three does "worst case is a wasted round" hold, extending the #110
  guarantee to the cross-round axis.

## TDD alignment

- **Liveness.** The TDD requires any `⌈2n/3⌉` operators to complete DKG/reshare (TDD
  threshold/liveness sections; note the "KMS-010" ID used in #110 does **not** appear in
  the TDD itself — it is #110's label, inherited here without an anchor). The "worst case a
  wasted round" guarantee holds **only with all three layers**; Layer 1 alone can violate
  liveness after a single blip (see caveat). The rollout reflects this.
- **MPK stability across reshare** (TDD: "applications unaffected, master public key
  unchanged"). Layer 1 *enforces* an invariant the TDD states but the code never checked —
  the most TDD-faithful part of this proposal.
- **Forward secrecy** (TDD Goal 7). Extended stalls suspend rotation; Layer 3's at-rest
  retention (if chosen) slightly weakens "old dealt shares become useless." Neither is
  disqualifying; both are bounded by `K` and the alert-driven short stall window.
- **Genesis durability.** The non-destructive repair path (above) is what keeps this
  property intact; re-DKG breaks it and is preprod-only.

## Testing & validation

- **Crypto unit (`pkg/reshare`)**: **this cross-round case does not exist today** —
  `pkg/reshare/dealer_set_agreement_test.go` covers only *within-round* set disagreement.
  Add a *cross-round* test: deal round R+1 from **mixed source versions** and assert
  `ComputeNewKeyShare` yields shares of a *different* secret `S'' ≠ S` (they are mutually
  consistent but wrong — assert `Σ λ_i C_i[0] ≠ MPK(S)`), then assert agreed-source rounds
  preserve `S`.
- **MPK validation unit (`pkg/node`)**: feed finalize a divergent share set and assert it
  aborts (does not persist) rather than carrying the MPK forward.
- **Multi-node integration**: force an abort on one node (inject a share-fetch 503 or drop
  a share), then run several more rounds and assert (a) all nodes stay on a consistent
  secret and (b) decrypt succeeds across the abort and afterward. This is the scenario the
  live soak exercised; it must pass in-harness.
- **Live**: re-run the ECDSA soak (`scripts/testEcdsaEncryptDecrypt.sh` in a loop, genesis
  held constant) for ≥4h under induced partitions; require zero genesis/fresh failures.
  Capture the client's stderr this time (the first soak swallowed it with `2>/dev/null`).

## Rollout

1. Land **Layer 1** first as the minimal corruption stop-gap (loud abort instead of silent
   corruption) and deploy **with a hard alert on the validation-abort log line**. Cluster
   can no longer corrupt; it may permanently stall rotation after a split-inducing abort
   (see Layer-1-alone caveat) — the alert is what makes that operationally acceptable.
2. Land **Layers 2–3 together** to restore subset/lag liveness (Layer 2's abstain path is
   only live-safe with Layer 3's catch-up).
3. Recover the live cluster (see Recovery below). For the *current* poisoned preprod state
   specifically, a re-DKG is acceptable (no real app data); for production, prefer the
   non-destructive repair path.

## Recovery of a poisoned cluster

The proposal's earlier framing ("cannot be repaired in place") is **overstated** and should
not be the production story. Historical versions survive: `RestoreState`
(`node.go:592-612`) reloads **all** persisted key versions, and in the incident op2+op3
both still hold consistent version-`…680` shares of the original `S` (that's `≥ t = 2`).

- **Non-destructive repair (preferred for production):** roll the active-version pointer
  back to the **last version held consistently by ≥ t nodes** (here `…680`), and have the
  lagging node (op1) re-derive its share for that version via the existing new-operator
  rejoin path. `S` — and therefore every existing ciphertext and the genesis-durability
  property — is preserved. This path **must exist** for production, because the alternative
  breaks genesis durability by construction.
- **Re-DKG (destructive):** generates a fresh `S`, invalidating all existing ciphertexts.
  Acceptable only where there is no real app data (current preprod). Do **not** normalize
  it as the general recovery mechanism.

## Open questions

- ~~Is the previous-interval version reliably derivable as a shared value?~~ **Resolved:
  no** — it is local knowledge and the naive derivation reintroduces the bug. Layer 2 now
  uses broadcast-`SourceVersion` + unanimity instead (with the value bound into the
  on-chain `commitmentHash`). Remaining sub-question: is binding into `commitmentHash`
  worth the migration, or is P2P-broadcast unanimity sufficient for v1?
- Layer 3 persistence: memory-only (restarts still abort, simpler, no new at-rest exposure)
  vs. persisted (restart-survivable, but requires encrypt-at-rest and the exposure delta
  argued). Default proposal: **memory-only for v1**.
- Retention bound `K` (Layer 3) and therefore max catch-up depth: last 2–3 rounds is ample
  at a ~2-min interval and second-scale skew; a node past that re-joins via the
  new-operator path.
- Recovery automation: is the non-destructive rollback-and-rejoin worth automating, or is a
  documented manual runbook sufficient until it recurs?
