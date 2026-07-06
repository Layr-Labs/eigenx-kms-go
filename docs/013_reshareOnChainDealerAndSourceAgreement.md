# 013 — Reshare: On-Chain Dealer-Set and Source-Version Agreement ("B-lite")

## Status

Proposed. Fast-follow correction to PR #118 (docs/012). Fixes a **livelock** and a
latent **corruption vector**, both traced to the same root cause: reshare consensus
inputs (dealer set + source version) derived from **per-node local/P2P state** rather than
shared on-chain state.

## Background

Two prior designs got us here:

- **docs/011** (PR #110): derive the reshare **dealer set** from the on-chain commitment
  registry so all nodes finalize on the identical set `D`. Correct in intent.
- **docs/012** (PR #118): add **source-version agreement** (`SelectMajoritySourceVersion`)
  + MPK validation (Layer 1) + share retention (Layer 3a) to stop a cross-round
  version-split from corrupting the master secret.

docs/012 Layer 2 **regressed liveness** and, on closer analysis, **weakened the docs/011
safety invariant**. This doc supersedes Layer 2's approach.

## Two bugs, one root cause

### Bug 1 — Livelock (observed live, kms-preprod-sepolia, v0.3.3_7a48a9a)

180+ minutes, ~102 consecutive reshare aborts, zero completions, all
`ambiguous source-version majority (tie at 1 dealers)`. Decrypt kept working (Layer 1
held; no corruption) — a *safe* livelock.

Mechanism: at finalize (`pkg/node/node.go:2051,2067`) two sets come from two independent
channels:

- `agreedDealers` ← `deriveAgreedDealerSet` (`node.go:942`): reads the **on-chain**
  commitment registry (Base L2) at head per dealer; converges or, at a bounded deadline,
  returns whoever submitted. **Partition-sensitive** — under an intermittent partition it
  frequently returns a 2-of-3 subset (log: `Dealer-set convergence deadline reached:
  submitted 1, expected 2`).
- `observedSourceVersions` ← `session.GetSourceVersions()`: the **P2P** commitment
  broadcasts (`handlers.go:592`) + self (`node.go:1723`). Holds all three nodes' versions.

`SelectMajoritySourceVersion` (`reshare.go:243`) **tallies over `agreedDealers`, not over
the observed map**. Cluster state was a 2-vs-1 split (op1=op2=`464`, op3=`212`, formed
earlier by successful reshares completing on 2-dealer subsets). When the on-chain read
handed Layer 2 the mismatched pair `{op1,op3}` or `{op2,op3}`, the tally was
`{464:1, 212:1}` → tie at 1 → abort. The node *knew* (via P2P) the third node's version,
but that knowledge was never consulted. It livelocks because op3 can only resync via a
**completed** round, and every round aborts before finalize (Layer 3b catch-up was
deferred).

### Bug 2 — Latent corruption vector (code analysis; not yet triggered in prod)

**This is the more serious finding.** docs/011's safety property is that `D` comes from
**shared on-chain state**, so every node finalizes on the *identical* `D`. Layer 2
re-filters that shared `D` down to `kept` (dealers on the winning source version) using
`session.GetSourceVersions()` — a **per-node, unauthenticated, P2P** map:

- If a node misses one dealer's P2P commitment broadcast (but that dealer *did* submit
  on-chain), it reads `sourceVersion == 0`, is treated as "unknown", and is **silently
  dropped** from `kept` (`reshare.go` tally skips `v == 0`; kept-loop excludes it).
- Two honest nodes can thus finalize on **different same-source subsets** of `D`. Both
  reconstruct the same secret `S`, but on **different combined polynomials** → mutually
  inconsistent refreshed shares → cluster-wide decrypt failure. This is exactly the
  mixed-dealer-set poisoning docs/011 was built to prevent, silently reintroduced.
- **Layer 1 does not catch it.** `ValidateReshareMasterPublicKey` (`reshare.go:173`) checks
  only that the node's *own* `kept` set reconstructs the carried MPK — which any
  same-source threshold subset does. It catches source-version *mixing*; it cannot catch
  two nodes on *different same-source subsets*. Nothing cross-checks `D` between nodes
  (completion signatures cover only epoch + commitmentHash, `reshare.go:295`).
- Pre-Layer-2, a missing broadcast for an on-chain dealer triggered **fetch-or-abort**
  (`fetchAndVerifyReshareShare`), never a silent drop. Layer 2 introduced the silent-drop
  path.
- **`SourceVersion` is not bound on-chain.** `HashCommitment` hashes only the G2 commitment
  bytes (`pkg/crypto/bls.go:169`); `submitCommitment` stores only
  `(epoch, commitmentHash, merkleRoot)`. `SourceVersion` lives solely in the
  per-recipient-signed P2P `CommitmentMessage` (`pkg/types/messages.go:52`). So a dealer
  can validly sign **different** `SourceVersion`s to different peers — deliberate
  equivocation triggers Bug 2 even at n=3.

Invisible at n=3 by pigeonhole (any 2-of-3 same-version subset is unique, so all nodes
that pick that version pick the same pair). **Goes live at n ≥ 4, or under P2P receipt
skew, or via one equivocating dealer.**

### The shared root cause

Reshare consensus inputs are derived from **non-shared state**:

1. `expectedReshareDealers` (`node.go:902`) scopes the dealer set to the **local**
   `activeVersion.ParticipantIDs`.
2. finalize writes `ParticipantIDs = participantIDsForFinalize` (`node.go:2140`) — so every
   laggard-drop round **ratchets** the next round's expected set down, per-node
   divergently. This is what let the 2-vs-1 split form and freeze.
3. the source-version tally input is the **P2P** map (`handlers.go:592`), not on-chain.

## Non-goals

- Fixing the underlying operator-to-operator network partitions (ops issue).
- A separate on-chain "last-committed version pointer" with threshold attestation
  (considered and rejected — see Alternatives). The per-epoch registry is already the
  durable shared truth; we extend its *content*, not add a new pointer + its
  "when-does-it-advance" consensus problem.
- Cross-round out-of-band catch-up (docs/012 Layer 3b) beyond what recipient-side
  reconciliation already gives.

## Design (B-lite): derive BOTH the dealer set and the source version from shared on-chain state

Three changes, zero contract deployments (we reuse the existing commitment registry; only
the *preimage* of the already-stored `commitmentHash` changes).

### Change 1 — Dealer set = full current on-chain operator set

`expectedReshareDealers` returns the **full current on-chain operator set**, dropping the
`activeVersion.ParticipantIDs` intersection (`node.go:903-923`). Non-share-holders are
naturally excluded downstream: they cannot produce a valid polynomial commitment for this
epoch, so they never appear as on-chain submitters in `deriveAgreedDealerSet`. This removes
the ratchet (root cause #1/#2): the expected set no longer shrinks per-node as subset
rounds complete.

### Change 2 — Bind `SourceVersion` into the on-chain commitment hash

`HashCommitment` incorporates the source version:
`commitmentHash = keccak256(commitmentBytes ‖ sourceVersion)`. The contract stores an
opaque `bytes32`, so **no Solidity change** is needed — only the Go preimage and its
verification.

Then, when a node reads an on-chain submitter's `commitmentHash` and receives that dealer's
P2P `CommitmentMessage`, it **verifies** the advertised `(commitments, SourceVersion)`
against the on-chain hash. Consequences:

- **Equivocation impossible:** a dealer cannot advertise a `SourceVersion` over P2P that
  differs from the one committed on-chain — the hash won't match, the share is rejected.
- **No silent drop:** an on-chain submitter whose P2P version is missing/mismatched is a
  **fetch-or-abort** condition (as in the pre-Layer-2 push path), not a silent exclusion.
  This is what actually restores kept-set determinism.

### Change 3 — Tally source version over on-chain submitters with verified versions

`SelectMajoritySourceVersion` tallies over the **on-chain-agreed dealers** whose
`SourceVersion` has been **verified against the on-chain hash** (Change 2), not over the
raw P2P map. Keep the `bestCount < threshold` abort. Replace the tie-abort with a
**deterministic highest-version tie-break** — now safe, because every node computes the
tally from identical shared/verified data, so all nodes select the same version and the
same `kept` set. Layer 1 remains the cryptographic backstop.

### Why this fixes both bugs

- **Livelock:** the dealer set no longer ratchets down (Change 1), and the tally is over a
  consistent, shared, verified set (Changes 2–3) — so the mismatched-pair tie that froze
  the cluster cannot arise. A genuine laggard is dropped deterministically (all nodes agree
  who), finalizes as a recipient, and resyncs.
- **Corruption vector:** `kept` is now a deterministic function of shared on-chain state +
  on-chain-verified versions. Two honest nodes cannot land on different subsets from P2P
  skew (a missing broadcast → fetch-or-abort, not silent drop), and equivocation is
  cryptographically prevented. The docs/011 "identical `D` on every node" invariant is
  restored and now actually enforced.

## Correctness / determinism argument

- On-chain submitters for an epoch are append-only, epoch-keyed, identical across nodes
  (docs/011). Binding `SourceVersion` into the committed hash makes each submitter's
  version a **shared, verifiable** value, not per-node P2P state.
- "Highest version with ≥ threshold verified submitters" is a deterministic predicate over
  that shared data → all honest nodes select the same version and the same `kept` set.
- Threshold secret-sharing: any ≥ threshold same-source subset reconstructs the same `S`,
  so the served MPK is preserved and Layer 1 passes.
- Worst case under partition: too few verified same-version submitters → sub-threshold
  abort-and-retry (safe, isolated), never a divergent finalize.

## Recovery of the wedged cluster

Re-DKG the current preprod cluster (no real app data) to clear the frozen 2-vs-1 split;
service is restored immediately at zero cost. **Re-DKG alone is not a fix** — the split
re-forms the first time 2-of-3 complete a round and the ratchet re-arms (root cause #1/#2)
— so B-lite must land before the cluster is relied on. For production, prefer a
non-destructive rollback to the last version held by ≥ threshold nodes (docs/012 Recovery
section) over re-DKG.

## Alternatives considered

- **Path A (docs/012 review): tally over the P2P observed universe + highest-version
  tie-break.** Un-wedges n=3 by pigeonhole, but leans *harder* on the unshared P2P map as
  the primary dealer-set input, leaves the ratchet intact, and leaves Bug 2 live (widening
  at n ≥ 4). Rejected: treats the symptom, ~as much code as B-lite once you add the
  determinism it needs.
- **Full Path B: on-chain "last-committed version pointer" with threshold attestation.**
  Adds a when-does-the-pointer-advance consensus problem and provides nothing the per-epoch
  registry majority doesn't already: the winning version each round *is* the catch-up
  target. Rejected as over-engineering.

## Testing & validation (as built)

docs/011 noted the in-memory `TestCluster` shares one registry and "cannot reproduce
cross-node divergence." That gap is exactly why both bugs shipped. As-built coverage:

- **Unit (`pkg/crypto`)**: a **golden-vector** test pins `HashCommitment`'s bytes so DKG +
  ack hashing cannot change; `HashReshareCommitment` binds the source version (differs from
  `HashCommitment` and across versions).
- **Unit (`pkg/reshare`) — the Bug 2 teeth**: `VerifyDealerSourceVersions` (the finalize
  gate, extracted as a pure function) **rejects an equivocated version** (P2P version ≠
  on-chain-committed version → hash mismatch → dropped), **rejects a wrong/skewed version**
  a node might receive, and **drops an unreceived dealer** — so an unauthenticated P2P
  version can never enter the tally, which is precisely what closes the divergent-subset
  corruption vector. Plus `SelectMajoritySourceVersion`: preprod case `{464,464,212}` →
  keep `{op1,op2}` on 464; highest-version tie-break; sub-threshold abort.
- **Integration (`internal/tests/integration`)**: `Test_ReshareParticipantIDs_DoNotRatchet-
  DownOnSubsetRounds` drives subset rounds (one operator suppressed on-chain) and asserts
  every node keeps the **full** `ParticipantIDs` — teeth-verified (fails on the pre-Change-1
  code: "ratcheted to 2"). The existing partition test
  (`Test_ReshareDealerAgreement_PartitionedRoundDoesNotPoison`) confirms share/MPK
  consistency across partitioned + healed rounds with the new verified-tally path.

**Harness limitation (documented, not papered over).** A true *per-node finalize
divergence* integration test — one node admitting a different same-source subset than its
peers *while liveness is preserved* — is **not achievable** in the current in-memory
harness: the ack→merkle→on-chain-submit chain is coupled, so dropping a node's inbound
commitments stalls the whole cluster's submission (breaks liveness) instead of producing a
divergent finalize. We therefore cover Bug 2 at the **verification-function layer**
(`VerifyDealerSourceVersions` unit tests above), which is the exact mechanism that admits
or rejects a dealer's version — a divergent finalize is impossible iff that gate is correct,
and it is unit-proven to reject every mismatched/equivocated/unreceived case. A
harness that decouples ack-collection from on-chain submission (to drive finalize-time
divergence directly) is a worthwhile follow-up but is not a prerequisite for this fix.

- **Live**: re-run the 24h ECDSA soak under induced partition on a re-DKG'd cluster;
  require zero finalize aborts sustained and zero decrypt failures.

## Rollout

1. Land B-lite (Changes 1–3) with the unit + integration suites green.
2. Re-DKG the preprod cluster under the fixed binary.
3. Re-run the soak to confirm sustained liveness + durability under partition.
