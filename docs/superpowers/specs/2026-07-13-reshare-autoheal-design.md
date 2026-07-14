# Reshare Auto-Heal + Deterministic Dealer-Set Prevention

## Status

**Design approved** (branch `sm-reshareAutoHeal`, based on `v0.4.2` / `261d5ba`). Addresses a
reshare rotation stall reproduced live on `kms-preprod-sepolia` on 2026-07-13. Supersedes an
earlier draft whose prevention design (a local self-share check + making the ack-fallback fatal)
was rejected in review as targeting the wrong layer; see "Root cause" for the traced mechanism
that replaced it.

## Summary

The preprod cluster's key rotation is **halted but safe**: decrypt works (the master secret is
intact and the served MPK is valid), but every reshare round since 2026-07-13 12:11Z aborts at
Layer-1 MPK validation (`node.go:2424`), so the key never rotates. This is **not** the
`docs/012`/`docs/013` corruption bug returning — it is the documented **"Layer-1-alone caveat:
may permanently stall rotation after a split-inducing abort"** (`docs/012`). The Layer-1 guard is
correctly refusing to build on a bad share; nothing self-corrects because all three nodes agree
on the version *number*, so source-version selection has no laggard to drop.

This design fixes two distinct bugs:

1. **Prevention (Part 1)** — the finalized reshare dealer set is not deterministic across nodes,
   so a degraded round can persist divergent (off-polynomial) shares. Make the dealer set
   provably identical across all honest nodes, or abort.
2. **Auto-heal (Part 2)** — a cluster that is *already* poisoned must recover on its own, without
   manual Redis surgery and without re-DKG (the MPK, and therefore every existing ciphertext, is
   preserved).

## Live evidence (2026-07-13, kms-preprod-sepolia, image v0.4.2_261d5ba)

Three operators (`op1`=`0x144c…99c`, `op2`=`0x0351…95ae`, `op3`=`0x04f6…801d`), 0 restarts,
uptime 2d20h — same binary throughout.

- **Decrypt works right now.** An ECDSA encrypt→decrypt round-trip succeeds; the client recovers
  the app key from 3 operators at threshold 2. Master secret intact, MPK valid.
- **~65 reshares succeeded, then it froze.** From 09:55Z→12:07Z the finalized `source_version`
  advanced every round. At **12:11Z it froze at `1783944564`** and every round since aborts at
  Layer-1 MPK validation. Code did not change; deployed reshare code is byte-identical to
  `v0.4.2`.
- **The round that PRODUCED `1783944564` finalized on DIFFERENT dealer sets per node:**
  - op1 (12:11:01Z): `Finalizing reshare on agreed dealer set … agreed_dealers=2 source_version=1783944444`
  - op3 (12:11:02Z): `Finalizing reshare on agreed dealer set … agreed_dealers=3 source_version=1783944444`
  - accompanied by op3 `Not all acks received but fallback threshold met, proceeding`
    (`node.go:2139`), op3 `Failed to broadcast commitments with proofs … no ack found for
    operator 0x144c…99c` (`node.go:2223`), op2 `Failed to verify operator broadcast … merkle
    proof is empty` (`handlers.go:1087`).
- **All 3 nodes then abort identically** dealing *from* `1783944564`: *"refreshed shares do not
  reconstruct the served master public key."*

## Root cause (traced to code)

`deriveAgreedDealerSet` (`node.go:1156`) is **not cross-node deterministic**, despite its
docstring claiming the result is "uniform across nodes." It polls the on-chain commitment
registry until either every expected dealer has submitted OR a **per-node wall-clock deadline**
(`GetProtocolTimeoutForChain`) fires; on timeout it returns "whoever submitted so far," read at
each node's own L2 chain head. Each node has its own deadline clock and its own registry-read
timing, so under a degraded round (a dealer fails to broadcast, tx-confirmation lag) different
nodes snapshot different participation sets — op1 got 2 dealers, op3 got 3.

`VerifyDealerSourceVersions` (`reshare.go:231`) and `SelectMajoritySourceVersion` (`reshare.go:279`)
then operate on that per-node-different set; they enforce self-consistency *within* a node, not
equality *across* nodes.

Layer-1 MPK validation (`ValidateReshareMasterPublicKey`, `reshare.go:173`) cannot catch it: with
`n=3`, threshold = `⌈2n/3⌉ = 2` (`dkg.CalculateThreshold`), so the reshare source polynomial has
degree `newThreshold-1 = 1` (`reshare.go:46`). **Any ≥2-of-3 subset of a degree-1 polynomial
Lagrange-reconstructs the same constant term S**, so op1's 2-dealer refreshed share and op3's
3-dealer refreshed share *both* satisfy `Σ_{d∈D} λ_d(D)·C_d[0] == MPK` — both pass validation and
persist — yet lie on **different degree-1 polynomials** that share only the constant S. The next
round, dealing from those inconsistent `1783944564` shares, no longer reconstructs MPK → Layer-1
aborts forever.

**Why a local self-share check does not help (rejected earlier approach):** every component share
is already verified against its dealer's commitments via `VerifyNewShare` (`node.go:2057`; on
fetch `node.go:1282`), which is the same polynomial-commitment math as `dkg.VerifyShare`
(`dkg.go:74`). Since `ownShare = Σ_d λ_d·s_{dj}` is built from those already-verified components,
re-verifying the aggregate against the aggregate commitments is algebraically guaranteed to pass —
it cannot detect a *cross-node* divergence. The fix must operate on the dealer set's cross-node
determinism, not on a local share check.

**Why making the ack-fallback fatal does not help (rejected earlier approach):** the ack-fallback
(`node.go:2138`) exists deliberately (KMS-010) and `Test_Reshare_SucceedsWithExactlyThresholdAcks`
(`internal/tests/integration/ack_threshold_integration_test.go:16`) drops one ack and *requires
the round to succeed*. Making it fatal breaks that test and re-opens the offline-tolerance
fragility. The ack-fallback is not the divergence source; the non-deterministic dealer-set cutoff
is.

## Part 1 — Prevention: deterministic dealer set

Replace the wall-clock, local-head dealer-set cutoff with a **block-derived cutoff** that every
node computes from a shared, agreed *block number*. L1 blocks are used only as a rough synchronized
clock (a value all nodes agree on and that advances in real time) — **not** as a finality oracle.
Determinism comes from pinning the registry read to a common computed height and reading it in real
time, not from any finality tag.

### Determinism chain

1. **L1 deadline block (shared clock).** The reshare is triggered at L1 boundary block `N`, where
   `N % interval == 0` (`node.go:688`). All nodes agree on `N` because it is a deterministic block
   *number*, independent of finality — the poller runs on the L1 client at `BlockType_Latest`
   (`main.go:293`), and a shallow tip reorg at the boundary is an accepted risk backstopped by
   Part-2 auto-heal (no finality dependency is claimed or needed). Define the dealer-set cutoff as
   `L1_deadline = N + interval − buffer`. On Sepolia `interval = 10`
   (`GetReshareBlockIntervalForChain`, ~120s); `buffer` is a new per-chain config, default **2**
   (cutoff `N+8`, ~80% into the round). The buffer leaves ~2 L1 blocks (~24s) after the cutoff for
   nodes to read the pinned registry and finalize before the round's final deadline `N + interval`.

2. **Block gate, not time.** Dealer-set derivation runs when the node observes L1 block
   `L1_deadline`. This *replaces* the `GetProtocolTimeoutForChain` wall-clock deadline in
   `deriveAgreedDealerSet` (`node.go:1171,1201`) — removing the per-node clock drift that caused
   the split. The round's overall final deadline (`N + interval`) is the backstop that bounds all
   waiting below (see step 4).

3. **Map L1 deadline → L2 read height by timestamp.** Let `T = timestamp(L1_deadline)`. The L2
   registry read height `cutoffL2` = the first Base block with `timestamp ≥ T`, resolved by binary
   search over L2 headers at `BlockType_Latest` (real-time head; no `safe`/`finalized` tag). Because
   `T` derives from an agreed L1 block *number* and `cutoffL2` is a deterministic function of block
   timestamps, every node resolves the **same** `cutoffL2`. **The wait-until-synced gate applies to
   this resolution step, not only the read below:** a node must not resolve `cutoffL2` until its own
   L2 head satisfies `head.timestamp ≥ T` — otherwise a lagging node would resolve a wrong (lower)
   height against a partial view and diverge. Wait (bounded by the round's final deadline) until
   `head.timestamp ≥ T`, then resolve. `cutoffL2` is only seconds old by construction (the cutoff
   sits ~24s before the final deadline), so it stays well within a non-archive Base node's
   state-retention window.

4. **Derive D at the pinned height, with retry-until-readable.** Read the registry pinned at
   `cutoffL2` (via `GetCommitmentAt`, which already accepts a block height, `commitmentRegistry.go:64`):
   `D = { expected dealers with a commitment present at cutoffL2 }`; `expectedReshareDealers`
   (prior participants) supplies the candidate set. A transient read failure — most importantly
   `missing trie node` / "header not found", meaning *this node has not yet synced to `cutoffL2`* —
   is **retried** (poll until the node's L2 view reaches `cutoffL2`), NOT skipped. This retry loop
   IS the L2 availability gate: a node waits for the canonical `cutoffL2` rather than reading a
   partial view. Two hard rules make this safe:
   - **Never `continue` past a failed dealer read.** The current per-dealer `continue`
     (`node.go:1185-1189`) silently drops a dealer *on one node only* and is the exact split-
     reintroduction path (see Findings). Replace it: any per-dealer read that still fails after the
     retry budget aborts the **whole round** (all nodes fail together), never finalizes on a
     partial set.
   - **Bounded by the final deadline.** All retrying (both the step-3 resolution wait and this read)
     is bounded by the round's final deadline `N + interval`. If `cutoffL2` is not resolvable/readable
     by then, the round aborts and the session is cleaned up. Because `N + interval` is itself the
     next boundary, a round that runs to its deadline will typically resume at `N + 2·interval` (the
     every-other-interval cadence noted under Caveats), not the very next boundary — aborting a block
     or two before the deadline recovers the immediate next boundary if that matters. Require
     `|D| ≥ newThreshold`; else abort+retry (auto-heal backstops a persistent stall).

5. **New-operator join path.** `RunReshareAsNewOperator` (`node.go:2459`) also calls
   `deriveAgreedDealerSet` (`node.go:2648`) but currently receives only `sessionTimestamp`, no
   trigger block. Plumb the trigger block through from the scheduler (already in scope at the call
   site, `node.go:778`) so a joining operator computes the identical `L1_deadline`/`cutoffL2`/`D`
   as existing operators. Without this a joiner would derive D differently and re-split.

Every honest node computes identical `N` → identical `L1_deadline` → identical `T` → identical
`cutoffL2` → identical `D`, or all abort together. No node can finalize on a different dealer subset
than another, so the degree-1 / 2-of-3 reconstruction ambiguity can no longer produce divergent
shares.

### Caveats (documented, accepted)

- **Shallow tip reorgs.** Because reads use `Latest` (by design, for real-time operation), a
  shallow L1 or L2 reorg around the cutoff could momentarily change `N` or `cutoffL2` across nodes.
  This is accepted, and the backstop is **Part-2 auto-heal** — NOT Layer-1 MPK validation. Note
  precisely: for the n=3 / threshold-2 / degree-1 case this whole design addresses, a reorg-induced
  divergent `D` would *pass* `ValidateReshareMasterPublicKey` (any ≥2-of-3 subset reconstructs the
  same constant — see Root cause), so MPK validation cannot catch it; only auto-heal recovers such
  a split. We do not use finality tags because their lag (minutes on OP-stack `finalized`) exceeds
  the round and would stall rotation.
- **Base RPC state retention.** `cutoffL2` is seconds old by construction, so a non-archive Base
  RPC (typical ~128-block / ~4-min retention) still serves state at that height. Archive RPC is
  therefore NOT required; the retry loop covers the only expected failure (local L2 view lagging
  the cutoff).
- **Cadence.** Gating finalize near `N + interval − buffer` can push a round's completion toward
  `N + interval`, occasionally skipping the next boundary (rotation every other interval in the
  worst case). Accepted; `buffer` is per-chain tunable if cadence needs adjustment.
- **New dependencies.** Per-chain `buffer` config; the block handler/poller exposing observation of
  the L1 deadline block; the L2 caller resolving a block by timestamp (binary search over
  `HeaderByNumber`) and the retry-until-readable pinned read.

## Part 2 — Auto-heal

Approach: **source-version demotion**, reusing the existing on-chain source-version agreement and
Layer-1 MPK-validation gate — no new protocol messages, no new endpoints, MPK preserved.

### Detection

A **persisted** counter of **consecutive MPK-validation aborts on the same active source version**.
Resets on any successful reshare (a round that persists) and whenever the active version changes.
At **N = 3** consecutive aborts (~6 min at the 2-min interval) the node declares the current
active source version *poisoned*. Consecutive-same-version tracking means a transient one-round
abort never triggers demotion.

**Persisted, not in-memory** (closes the restart-churn gap, review Finding 7). Store the counter as
the pair `{trackedSourceVersion, consecutiveAborts}` in `NodeState` (`persistence/types.go`) — two
new fields that round-trip through the existing `SaveNodeState`/`LoadNodeState`
(`persistence/interface.go:51,55`), so **no new interface methods and no per-backend work** are
required (unlike the poisoned-version set, which does need a new set-typed surface). On restart,
the loaded count is trusted only if `trackedSourceVersion` still equals the current active source
version; otherwise it resets to 0 — this preserves the "resets when the active version changes"
semantics across a restart, so a node that restarts mid-stall resumes counting instead of losing
~6 min of progress. Persist on each increment (cheap — `SaveNodeState` is already written every
boundary, `node.go:711`).

Increment/reset scope (review Finding 8): the counter increments **only** on the Layer-1
MPK-validation abort (`node.go:2423`). Earlier aborts — dealer-set too small (`node.go:2286`),
verified-set too small (`node.go:2308`), no source-version-agreed (`node.go:2325`), missing-share
(`node.go:2366`), nil-MPK (`node.go:2406`) — neither increment nor reset it (those are separately
unrecoverable / availability states, not the poison signature). This is stated explicitly so
"consecutive" is unambiguous across interleaved non-MPK aborts.

**Majority-gated increment (walk-back convergence).** The counter increments on an MPK-validation
abort **only when the round's agreed majority source version equals this node's active source
version** — i.e. `srcVersion` from `SelectMajoritySourceVersion` (`node.go:2319`) `==` the active
version this node dealt from. This is the coordination that makes staggered rollback safe:

- *Why it is needed.* Detection is not lock-step. Nodes can be a round or two apart (an interspersed
  non-MPK abort on one node, per-node interval jitter), so they demote on different rounds. When an
  early mover has rolled back to `V−1` while the majority is still on poisoned `V`,
  `SelectMajoritySourceVersion` still picks `V` (it has the ≥threshold count), so the round deals
  from poisoned `V` and aborts again. Without gating, the early mover would count that abort against
  its **good** `V−1` and eventually demote `V−1` too — nodes scatter across `V/V−1/V−2`, no version
  reaches threshold, and rotation thrashes worse than the original stall.
- *What gating does.* A node only "blames" (counts against) its active version when the cluster is
  actually attempting that version (`majority srcVersion == active`). The majority still on `V`
  keeps accumulating and will demote `V`; a minority already on `V−1` does **not** increment while
  the majority is on `V`, so it waits on the correct target without over-walking. Once a
  **threshold** of nodes have rolled to `V−1`, `SelectMajoritySourceVersion` picks `V−1`, the round
  deals from good `V−1`, validation passes, and the cluster heals; the last straggler on `V` is
  dropped as a laggard and re-derives its share as a recipient of the `V−1` dealers.

Convergence is therefore **eventual** (once a threshold aligns on the target), not simultaneous —
bounded by the small detection skew at `N=3`. Target *agreement* still relies on nodes holding
identical persisted-version histories (so "next-lower persisted version" resolves to the same
value); a diverging history degrades to liveness thrash toward the floor, never corruption (see
walk-back below). Removing that last dependency by agreeing the target on-chain via the same
verified-majority mechanism is a deferred follow-up.

### Last-known-good (LKG) marker

On every reshare round that passes MPK validation and persists, record the **agreed majority
source version** it validated against — i.e. `srcVersion` from `SelectMajoritySourceVersion`
(`node.go:2319`), the cross-node-consistent quantity — as the LKG marker (a single `int64`
persisted as a `NodeState` field, alongside the abort counter). This is NOT the node-local advertised source (which differs across nodes,
review Finding 4) and NOT "the last version whose finalize passed" (which would point at the
poison, since `1783944564`'s own finalize passed — it dealt from the good `1783944444`). In the
incident LKG = `1783944444`.

### Rollback (shared-state target, review Finding 3)

When a node demotes a poisoned version, it selects the rollback target from **agreed/shared
state**, not local history:

1. **Prefer the LKG marker** — if an LKG marker exists and is strictly below the poisoned version,
   roll the active pointer to it. Because LKG is the agreed `srcVersion`, all stuck nodes hold the
   same LKG and converge on the same target.
2. **Otherwise, agreed walk-back** — if no usable LKG marker exists (e.g. first deploy onto an
   already-poisoned cluster, as in preprod), step the active pointer to the next-lower persisted
   version and let the next round attempt it. The next round's dealer-set derivation and
   source-version agreement (Part-1-deterministic) plus Layer-1 validation decide whether that
   target heals; if it too is poisoned, demote and step again. Staggered rollback is safe because
   of the **majority-gated increment** (see Detection): a node that has already stepped to `V−1`
   does not keep counting aborts while the majority is still attempting `V`, so early movers wait
   on the correct target instead of over-walking to `V−2`. **Safety** is fully enforced by the
   shared on-chain agreement + MPK gate — a node can never persist a target the others reject.
   **Liveness** relies on nodes having matching persisted-version histories: persisted version
   *numbers* are session timestamps written only on cross-node-validated rounds, so histories
   normally match (this is why preprod's three 0-restart nodes all hold `1783944444`). If local
   histories diverge (a late joiner, a restore gap), nodes can step to different versions and fail
   to assemble `≥ threshold` on one — a liveness thrash toward the floor, never corruption (review
   Finding 7). If this proves a real risk in practice, the walk-back target can be agreed via the
   same majority-over-verified-state mechanism rather than chosen locally; deferred until observed.
3. Mark the demoted version poisoned (persisted set, review Finding 7) so the walk never re-selects
   it, even across a restart.

Rollback only re-points the active version; it never persists a new share by itself. The existing
**Layer-1 MPK validation remains the backstop**: if nodes momentarily disagree on the step-back,
the next round's validation fails and nobody persists — worst case a few more retry rounds, never
corruption.

### Poisoned versions and time-indexed lookup (review Finding 5)

Demoting the active pointer does not by itself remove a poisoned version from `GetKeyVersionAtTime`
(`keystore.go:138`), which returns the latest version `≤ timestamp` and would still return the
poisoned `1783944564` for attestation times in `[1783944564, next_good)`. A poisoned version MUST
be excluded from time-indexed lookup so attestation-time decrypts never resolve onto divergent
shares. The exclusion is enforced consistently across **every** version-resolution accessor that
consults the persisted poisoned-version set (review Finding 8): `GetKeyVersionAtTime`
(`keystore.go:138`), `GetActiveVersion` (`keystore.go:53`, so a poisoned version can never be
re-activated or served at `/pubkey`, `handlers.go:1017`), and `GetPrivateShareForVersion`
(`keystore.go:123`). Falling back to the next-lower good version is safe because MPK is invariant
across versions, so it reconstructs the same app key.

### Floor

If the walk-back reaches the genesis/oldest persisted version with nothing that heals, the node
**halts rotation, keeps serving decrypts (MPK intact), and emits a loud error/alert** for human
intervention. Auto-heal never triggers an automatic re-DKG (that would change the MPK and
permanently invalidate existing ciphertexts).

### Observability

Emit distinct, greppable log lines (and, where metrics exist, counters) on: demotion of a source
version, rollback target selection, successful heal (rotation resumes), and the genesis-floor
halt. Operators must be able to distinguish "auto-heal in progress" from "genuinely stalled."

### Transient rollback window (review Finding 6)

If nodes demote at staggered times (e.g. a non-atomic rollout, or clock-independent per-node
interval jitter), there is a bounded window where some nodes serve/sign with the rolled-back
version and others with the poisoned one. (A single node restarting mid-stall no longer resets its
progress, since the counter is now persisted — see Detection.) `/pubkey` MPK is unaffected (carried-forward MPK is
identical and served directly), but app-signing partial-signature reconstruction may transiently
fail until the window closes. This is bounded and non-corrupting; clients already retry. The spec
acknowledges it rather than asserting simultaneity.

## Testing

All via `./scripts/goTest.sh`.

- **Prevention — determinism.** Simulate a degraded round where dealers submit at different L2
  heights; assert all nodes derive the identical `D` from the pinned `cutoffL2`, and that a round
  which cannot reach `|D| ≥ threshold` by the cutoff aborts (rather than finalizing a partial
  set). Include a direct reproduction of the incident's asymmetry (op1 sees 2, op3 sees 3 at head)
  and assert the pinned-height derivation makes them agree.
- **Prevention — retry vs abort (no silent drop).** Assert a transient pinned-read failure
  (`missing trie node` / node not yet synced to `cutoffL2`) is retried and then succeeds; and that
  a read still failing after the final-deadline budget aborts the whole round rather than dropping
  a dealer and finalizing a partial set. Assert the round-final-deadline backstop cleans up the
  session (next interval not skipped).
- **Prevention — new-operator parity.** Assert a joining operator (`RunReshareAsNewOperator`) with
  the trigger block plumbed computes the identical `cutoffL2`/`D` as existing operators.
- **Prevention — liveness preserved.** `Test_Reshare_SucceedsWithExactlyThresholdAcks` and the
  existing dealer-agreement integration tests still pass (the ack-fallback is untouched).
- **Auto-heal — detection + rollback.** N consecutive MPK-validation aborts on the same active
  source version trigger demotion; assert active rolls back to the LKG (agreed `srcVersion`) and
  the next round validates and persists.
- **Auto-heal — walk-back.** No usable LKG (first-deploy-onto-poison): assert the node steps to
  the next-lower persisted version, skips persisted-poisoned versions, and converges.
- **Auto-heal — majority-gated increment (staggered rollback).** A node that has rolled back to
  `V−1` while the majority is still on poisoned `V` does NOT increment its counter (majority
  `srcVersion == V ≠ active V−1`), so it does not over-walk to `V−2`; assert it holds `V−1` until a
  threshold aligns, then the round deals from `V−1` and heals. Include the skewed-detection case
  (one node at 2 aborts, another at 3) and assert eventual convergence without scatter.
- **Auto-heal — poisoned-version exclusion.** Assert a poisoned version is never returned by
  `GetKeyVersionAtTime`, never re-activated by `GetActiveVersion`/served at `/pubkey`, and never
  returned by `GetPrivateShareForVersion`.
- **Auto-heal — floor.** History exhausted with no healing version: assert rotation halts,
  decrypt still works, and a loud error is logged (no auto-re-DKG).
- **Auto-heal — restart durability.** Assert the poisoned-version set AND the abort counter
  survive a restart: the persisted `{trackedSourceVersion, consecutiveAborts}` is honored when the
  active source version is unchanged, and reset to 0 when it differs.

## Scope / non-goals

- No new P2P protocol messages, no new HTTP endpoints, no manual Redis surgery.
- MPK is preserved; all existing ciphertexts remain decryptable (subject to the bounded transient
  window above).
- Once deployed, preprod heals on its own: Part 1 makes future rounds deterministic; Part 2
  demotes `1783944564`, walks back to `1783944444`, and rotation resumes.
- **Not in scope:** pruning old key versions; changing the reshare interval; altering the on-chain
  commitment-registry schema; introducing finality-tag (`safe`/`finalized`) reads — the design
  deliberately uses real-time `Latest` reads pinned to a common computed height.
- **Deferred follow-up:** if subset-liveness under a genuinely-down operator (one that never
  submits within a round) becomes a requirement, the "abort if `|D| < threshold`" rule can be
  relaxed to finalize on the deterministic sub-threshold set; not needed now.

## Implementation notes (for the plan)

Carried forward from design review as concrete inputs the implementation plan must resolve — none
are design changes, but each is real work or a decision the plan must make explicit:

- **Reliable height observation (no hang).** The block-gate (observe `N + interval − buffer`) and
  the final-deadline bound (`N + interval`) must not depend on the lossy single-consumer block
  channel (`blockHandler.HandleBlock` drops blocks when full, `blockHandler.go:64`;
  `checkScheduledOperations` is already its consumer, `node.go:675`). Poll the L1 client height
  instead — polling a block *number* is deterministic and does NOT reintroduce the wall-clock drift
  that caused the bug (all nodes converge on the same number). The wait must have a bound that
  cannot itself hang (ctx + the `N + interval` deadline).
- **Source of `T`.** Prefer the timestamp of the observed `N + interval − buffer` block object
  (`ethereum.EthereumBlock.Timestamp`, already available at `node.go:682`) over a separate L1
  `HeaderByNumber` read, to avoid an extra call and interface method.
- **L2 header access.** The timestamp→height binary search needs L2 `HeaderByNumber`; it exists on
  the underlying client but is NOT on `IContractCaller` — a new interface method + mock is required.
- **New persistence surface.** Split by shape:
  - The **abort counter** `{trackedSourceVersion, consecutiveAborts}` and the **LKG marker** (a
    single `int64`) are scalars — add them as `NodeState` fields
    (`persistence/types.go`), reusing the existing `SaveNodeState`/`LoadNodeState`. No new interface
    methods, no per-backend work.
  - The **poisoned-version set** is a set/collection and does need new `INodePersistence` methods
    (interface + redis + memory + badger + mock). Budget this explicitly.
- **L2-freshness tolerance / buffer sizing.** With `buffer = 2`, the resolve+read budget is
  ~`N+8 → N+10` ≈ 24s (Sepolia), much tighter than the old 90s protocol timeout. A node whose Base
  RPC lags > ~24s aborts every round and becomes a permanent laggard; with n=3, two such nodes
  stall rotation. Validate 24s against preprod's Base RPC latency during implementation and raise
  `buffer` if needed (it is per-chain config precisely so this is tunable without code change).

## Rollout

1. Land Part 1 (deterministic dealer set) + Part 2 (auto-heal) together with unit + integration
   suites green (`./scripts/goTest.sh`).
2. Deploy the new image to preprod. Part 1 makes new rounds deterministic; Part 2 demotes the
   poisoned `1783944564`, rolls back to `1783944444`, and rotation resumes automatically (no manual
   intervention).
3. Re-run the ECDSA soak (`scripts/testEcdsaEncryptDecrypt.sh` in a loop, genesis held constant)
   to confirm sustained liveness + durability while `source_version` advances again.
