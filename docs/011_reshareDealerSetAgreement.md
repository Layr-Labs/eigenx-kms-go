# 011 — Reshare Dealer-Set Agreement

## Status

Proposed. Implements the fix for the reshare-induced master-secret corruption observed
on preprod-sepolia (`kms-preprod-sepolia`, cluster `protocol-blastpad`).

## Problem

Reshare finalization has **no agreement step** on the dealer set. Each operator decides
which dealers to include in `ComputeNewKeyShare` from its **own local view**
(`session.verifiedOperators`, populated only from P2P broadcasts it happened to receive
and verify before its finalize deadline). Nothing forces all operators to finalize on
the same set.

### Why that corrupts the master secret

`ComputeNewKeyShare` reconstructs each refreshed share via Lagrange interpolation over
the dealer set `D`:

```
x'_j = Σ_{i∈D} λ_i(D) · s'_{ij}
```

The Lagrange coefficients `λ_i(D)` depend on **which** dealers are in `D`. For the new
shares across all operators to lie on one common polynomial — the prerequisite for them
being a valid threshold sharing of the same secret `S` — **every operator must use the
identical `D`**. Same *cardinality* is not enough; it must be the same *set*.

If two operators finalize on different sets (e.g. one is briefly partitioned and misses
a dealer's share before its deadline), they land on different polynomials. Their
refreshed shares become mutually inconsistent: no threshold subset recovers a consistent
key, every `VerifyAppPrivateKey` fails ("all combinations exhausted"), and
`Σcommitments[0]` no longer equals the served `MasterPublicKey`. A single mixed-set
round permanently poisons the cluster.

### Evidence

- **Live (Datadog, service `eigenx-kms`, 2026-06-23):** over 2h, 62% of rounds finalized
  on the full 3-operator set, but **34% finalized on a 2-of-3 subset** with the excluded
  operator **rotating** round-to-round. Failing operators timed out at exactly the 90s
  protocol timeout with `got 0/2` acks — i.e. transient total comms blackouts, not a
  millisecond race. The 90s timeout is not the issue (healthy rounds finish in ~3s).
- **Real-code simulation (`pkg/reshare`, throwaway probe):** classified
  `ComputeNewKeyShare` outcomes by dealer-set pattern:
  - all operators use full set → ✅ S preserved, all subsets consistent.
  - all operators use the *same* 2-subset → ✅ consistent (S preserved).
  - **mixed sets in one round (some full, one straggler on a 2-subset) → ❌
    INCONSISTENT, undecryptable** — exactly the live symptom.
  - symmetric "each excludes a different dealer" → consistent but shifted `S'`.

  Key insight: breakage is **not** partial-vs-full; it is operators **disagreeing** on
  the set within a round. Uniform rounds (all-full OR all-same-subset) are always safe.

## Goal

Make the finalize dealer set a value **all operators agree on**, derived from shared
state, rather than each node's local receipt timing — while preserving the
KMS-010 liveness intent (resharing should proceed when one operator is genuinely
offline, as long as ≥ threshold remain).

## Non-goals

- Fixing the underlying operator-to-operator network partitions (separate ops issue;
  this change makes the protocol *correct* regardless of partitions).
- Changing the share/commitment verification crypto (polynomial + merkle checks stay).
- Recovering the already-poisoned live cluster (handled separately by a state reset /
  re-DKG; this cluster has no real app data).

## Design

### Source of agreement: the on-chain commitment registry

`EigenKMSCommitmentRegistry` already stores, per epoch, each operator's
`(commitmentHash, ackMerkleRoot, submittedAt=block.number)` via `submitCommitment`,
**before** finalization (Phase 2 precedes Phase 5). It is append-only per epoch
(one submission per operator, no deletes — verified in the Solidity). `getCommitment`
and the `CommitmentSubmitted` event let every node read the **same** set of submitters.

This is the shared state to agree on: **a dealer is eligible for round `epoch` iff it
submitted a commitment for `epoch` on-chain.** Because all nodes read the same chain,
they derive the same eligible set.

> **Chain note (important):** the commitment registry lives on **Base (L2)**, while the
> reshare interval boundary that triggers a round is an **Ethereum (L1)** block (the
> node's poller watches L1). The two block-number spaces are unrelated, so we CANNOT pin
> the L2 registry read to the L1 trigger block. The node has no L2 block-height feed.
> Agreement therefore relies on **set convergence + abort-retry**, not a pinned height
> (see below). `commitments[epoch]` being append-only and epoch-isolated is what makes
> convergence safe: the eligible set only ever grows within an epoch, never changes a
> past entry. `GetCommitmentAt(blockNumber)` is implemented for completeness/L2-pinning
> if an L2 height becomes available, but the default path reads at L2 head.

### Algorithm (replaces the local-view dealer filtering at finalize)

1. **Derive the candidate dealer set from the registry.** For each existing operator
   `op` (= on-chain operators ∩ previous version's participants, deterministic), read
   `getCommitment(epoch, op)` at Base head. The eligible set is
   `D = { op : commitmentHash != 0 }`, ordered by the on-chain operator slice.

2. **Converge on the full eligible set.** Because reads happen at head, a node might
   observe a peer's submission slightly before/after another node does. To converge, a
   node requires `D` to include **every** expected dealer that is reachable, polling the
   registry until either all expected dealers have submitted or a bounded deadline
   passes. This drives all honest nodes toward the same `D` = "all dealers that
   submitted for this epoch." Require `|D| ≥ threshold`. A genuinely-offline operator
   never submits → absent from `D` on **all** nodes → uniform smaller `D` (liveness).

3. **Ensure local shares cover `D` (on-demand fetch).** A node finalizes on exactly `D`,
   so it needs a verified share from every dealer in `D`. If it is missing one (it was
   lagging / dropped that send), it **fetches the share on demand** from the dealer via a
   new authenticated RPC (below), then runs the existing polynomial-commitment
   verification on it. If after fetching it still cannot verify a dealer in `D`, it
   **aborts and retries next interval** (it must not finalize on a different set).

4. **Finalize on `D`.** Call `ComputeNewKeyShare(D, shares, …)`. Since every honest node
   converges to the same `D`, the refreshed shares are mutually consistent and preserve
   `S`.

5. **Validate before commit.** After finalize, never blindly carry forward a stale MPK;
   recompute/validate the served MPK against the post-reshare commitments. If validation
   fails, abort the round.

### Why head-read + convergence is safe (no pinned height needed)

The only cross-node disagreement at head is **timing** — a node reads before a peer's
submission lands. It can never see a *different* value (append-only, one-per-operator,
epoch-keyed). The convergence wait (step 2) collapses timing skew to the same full set;
the abort-retry (step 3) is the backstop if a node still can't match `D` this round. The
worst case is a wasted round (liveness cost), never finalizing on divergent sets
(no corruption). A pinned L2 height would tighten step 2 but is not required for
correctness and is unavailable without an L2 block feed.

### New transport RPC: on-demand share fetch

Push-only transport today (`Send*`/`Broadcast*`). Add a request/response:

- `POST /reshare/share/request` — body: authenticated `ShareRequestMessage{ epoch,
  requester, dealer }`. The dealer looks up the per-recipient share it generated
  (now retained in `session.myGeneratedShares`) and returns it as an authenticated
  `ShareMessage`.
- Auth: identical BN254 authenticated-message scheme as all other RPCs
  (`validateAuthenticatedMessage`). The responder only serves the share **destined for
  the authenticated requester** (`share[requester]`) — never another operator's share.
- Security note: reshare shares already travel plaintext over the BN254-authenticated
  channel (same as the original send); the fetch exposes nothing the original send
  didn't. Equivocation remains detectable via the existing merkle-ack fraud proof.

### Read consistency (pinned block)

`getCommitment` currently hardcodes `CallOpts{Context: ctx}` (chain head). We thread an
optional block height through the contractCaller interface (`GetCommitmentAt(...,
blockNumber)`), so all nodes read as-of `H`. Nodes compute `H` from the same signal
(the block at the wait-phase deadline, surfaced by the existing block handler), so they
converge on the same submitter set. If a node's `H` differs (clock/poller skew) and it
derives a different `D`, the consistency check + abort-retry is the backstop: it simply
retries; it never finalizes on a divergent set.

## Why this is correct where the old code was not

Old: `D` = function of **local receipt timing** → diverges under jitter/partition.
New: `D` = function of **shared chain state at a pinned height** → identical across
honest nodes by construction. Divergence can no longer silently produce inconsistent
shares; the worst case is an abort-and-retry (a liveness cost), never corruption.

## Liveness

- One operator genuinely offline → it never submits a commitment → absent from `D` on
  **all** nodes uniformly → remaining ≥ threshold operators finalize on the same smaller
  `D`. Resharing proceeds (KMS-010 intent preserved). ✅
- One operator briefly lagging (submitted on-chain, but a peer missed its share) → peer
  fetches on demand → finalizes on full `D`. ✅
- Genuine disagreement / unreachable dealer that *did* submit → abort-and-retry next
  interval. Costs one round; never corrupts. ✅

## Implementation layers

1. **Dealer share retention** — `session.myGeneratedShares` + accessors. *(done)*
2. **Share-fetch RPC** — `ShareRequestMessage` type, client `RequestReshareShare`,
   server `handleReshareShareRequest`, route registration.
3. **Block-pinned reads** — `GetCommitmentAt(ctx, registry, epoch, op, blockNumber)` on
   `IContractCaller` (+ mock regen); keep `GetCommitment` as head-read wrapper.
4. **Finalize rewrite** — derive `D` from registry at `H`; fetch missing; verify;
   finalize on `D`; validate. Replaces the `trustedDealerIDs(validShares, verifiedOps)`
   local-view logic.

## Testing & validation

- **Unit:** the `pkg/reshare` consistency tests (mixed-set breaks, uniform preserves)
  already guard the crypto invariant. Add: `expectedReshareDealers`/`D`-derivation
  determinism; share-fetch RPC auth (serves only requester's share); abort-retry on
  missing dealer.
- **Harness gap:** the current in-memory `TestCluster` shares one `MockChainPoller`, so
  all nodes get identical timing — it **cannot** reproduce cross-node divergence or
  partition. To validate this fix we must extend the harness to (a) drive per-node block
  views / timing skew and (b) inject share-drop / partition per node, then assert all
  nodes finalize on the same `D` and decrypt succeeds across many rounds including
  partitioned ones. This simulation is part of the deliverable, not an afterthought.
- **Live:** final validation on a 3-node cluster (post-reset) — sustained reshares under
  induced partitions with periodic encrypt→decrypt round-trips.

## Rollout

1. Land the **strict guard** (require-all-existing-dealers, abort otherwise) first as the
   minimal safe stop-gap — already implemented; converts silent corruption into a loud
   retryable abort. *(branch `taras/reshare-uniform-dealer-set`)*
2. Land this agreement design on top (restores subset liveness).
3. Reset / re-DKG the live cluster under the fixed binary.
