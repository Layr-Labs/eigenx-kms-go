# Reshare Auto-Heal + Degraded-Round Prevention

## Status

**Design approved** (branch `sm-reshareAutoHeal`, based on `v0.4.2` / `261d5ba`). Addresses a
reshare rotation stall reproduced live on `kms-preprod-sepolia` on 2026-07-13.

## Summary

The preprod cluster's key rotation is **halted but safe**: decrypt works (the master secret is
intact and the served MPK is valid), but every reshare round since 2026-07-13 12:11Z aborts at
Layer-1 MPK validation (`node.go:2424`), so the key never rotates. This is **not** the
`docs/012`/`docs/013` corruption bug returning — it is the documented **"Layer-1-alone caveat:
may permanently stall rotation after a split-inducing abort"** (`docs/012`). The Layer-1 guard is
correctly refusing to build on a bad share; nothing self-corrects because all three nodes agree
on the version *number*, so source-version selection has no laggard to drop.

This design fixes two distinct bugs:

1. **Prevention** — a degraded reshare round (lost acks / broadcasts) must not be able to persist
   a divergent (off-polynomial) share in the first place.
2. **Auto-heal** — a cluster that is *already* poisoned must recover on its own, without manual
   Redis surgery and without re-DKG (the MPK, and therefore every existing ciphertext, is
   preserved).

## Live evidence (2026-07-13, kms-preprod-sepolia, image v0.4.2_261d5ba)

Three operators (`op1`=`0x144c…99c`, `op2`=`0x0351…95ae`, `op3`=`0x04f6…801d`), 0 restarts,
uptime 2d20h — same binary throughout.

- **Decrypt works right now.** An ECDSA encrypt→decrypt round-trip succeeds; the client recovers
  the app key from 3 operators at threshold 2. Master secret intact, MPK valid.
- **~65 reshares succeeded, then it froze.** From 09:55Z→12:07Z the finalized `source_version`
  advanced every round (…936428 → …944324). At **12:11Z it froze at `1783944564`** and every
  round since aborts at MPK validation. Code did not change; deployed reshare code is
  byte-identical to `v0.4.2`.
- **The trigger round (12:11:01Z, which produced version `1783944564`) ran degraded:**
  - op3: `Not all acks received but fallback threshold met, proceeding` (`node.go:2139`)
  - op3: `Failed to broadcast commitments with proofs in reshare … no ack found for operator
    0x144c…99c` (`node.go:2223`)
  - op2: `Failed to verify operator broadcast … merkle proof is empty` (`handlers.go:1087`)
- **All 3 nodes abort identically** with `agreed_dealers: 3`, identical frozen `source_version`,
  acks + broadcasts otherwise "verified": *"refreshed shares do not reconstruct the served master
  public key"*.

### Mechanism

`reshare.ValidateReshareMasterPublicKey` (`reshare.go:173`) sums the **dealers' source
commitments** `Σ_{d∈D} λ_d(D)·C_d[0]` and requires the result to equal the carried-forward MPK.
It confirms the *dealers' source shares* reconstruct MPK — but it does **not** verify that *this
node's own refreshed share* lies on the reshared polynomial. In the degraded round the
ack-fallback (`node.go:2138`) plus the two "continue — not fatal" branches (broadcast
`node.go:2224`, verify `node.go:2234`) let recipients finalize version `1783944564` over
*effectively different dealer sets*. Each node's source-side MPK check passed, but one node's
stored `PrivateShare` for `1783944564` landed on a different degree-t polynomial (same constant
term S, divergent above it). Decrypt tolerates it (any 2 consistent shares meet threshold 2);
dealing *from* `1783944564` in the next round does not — the Lagrange sum no longer reconstructs
MPK, so Layer-1 aborts. Forever, because the poisoned version stays active and all nodes agree on
its number.

**The trap for any fix:** version `1783944564` *passed* its own finalize validation (it dealt
from the good `1783944444`). Only rounds dealing *from* `1783944564` fail. So "last version whose
finalize passed" is NOT a safe rollback marker — it would point at the poison. The correct notion
is *the last source version we successfully dealt **from***, which in this incident is
`1783944444`.

## Part 1 — Prevention

Stop a degraded/divergent round from ever persisting an off-polynomial share.

**Tooth 1 — self-share verification before persist.** After `ComputeNewKeyShare` produces this
node's refreshed share, verify that share against the reshared commitments *before* persisting.
The polynomial-commitment check already exists as `dkg.VerifyShare(share, commitments)`
(`dkg.go:74`): `share·G2 == Σ_k commitment_k · j^k`. If it fails, abort the round (retry next
interval) exactly like the existing Layer-1 abort. A node can no longer persist a share it cannot
prove is on-polynomial.

**Tooth 2 — make finalize-critical gaps fatal.** A round we actually finalize from must not have
proceeded past a lost broadcast/verify ("continue — not fatal", `node.go:2224`/`2234`) or an
ack-fallback (`node.go:2138`) when that gap affects the dealer set we finalize on. The precise
enforcement point is fixed by a failing test that reproduces the divergent-recipient round (see
Testing); the guard converts "proceed degraded" into "abort and retry" for the paths that can
produce an inconsistent finalize set.

Prevention alone does **not** un-stick preprod (the active version genuinely holds inconsistent
shares) — that is what Part 2 is for. Prevention stops *new* poison; auto-heal recovers *existing*
poison and backstops anything prevention misses.

## Part 2 — Auto-heal

Approach: **source-version demotion.** Reuse the existing on-chain source-version agreement and
Layer-1 MPK-validation gate — do not add a new protocol.

### Detection

An in-memory counter of **consecutive MPK-validation aborts on the same active source version**.
The counter resets on any successful reshare (a round that persists) and whenever the active
version changes. At a threshold of **N = 3** consecutive aborts (~6 min at the 2-min interval)
the node declares the current active source version *poisoned*. Consecutive-same-version tracking
means a transient one-round abort never triggers demotion.

### Last-known-good (LKG) marker

On every reshare round that passes MPK validation and persists, record **the source version it
dealt from** as the LKG marker (persisted via the existing `INodePersistence`). This is the
version proven safe *as a source*, which sidesteps the trap above. In the incident LKG =
`1783944444`.

### Rollback (hybrid target selection)

When a node demotes a poisoned version:

1. **Prefer the LKG marker** — if an LKG marker exists and is strictly below the poisoned
   version, roll the active pointer to it.
2. **Otherwise walk back** — scan persisted versions (never pruned) in descending order, skipping
   any locally-marked-poisoned version, and select the highest one strictly below the poisoned
   version. This handles the case where several consecutive versions are bad, or where no LKG
   marker exists yet (e.g. the marker was introduced after the poison).
3. Mark the demoted version poisoned (in-memory set) so the walk / selection never lands on it
   again this process lifetime.

After rollback the node re-points its active version. The *next* scheduled reshare then deals
from the older source version and advertises it through the **existing on-chain source-version
agreement** (`docs/013` Change 2/3). All nodes are stuck identically and demote near-
simultaneously, so agreement re-forms on the older version and the round validates and persists →
healed.

### Convergence & safety

Rollback only re-points the active version; it never persists a new share by itself. The existing
**Layer-1 MPK validation remains the backstop**: if nodes momentarily disagree on the step-back,
the next round's validation fails and nobody persists — worst case a few more retry rounds, never
corruption. This is the same machinery already proven safe in the incident logs. No new protocol
messages, no new endpoints, MPK preserved throughout.

### Floor

If the walk-back reaches the genesis/oldest persisted version with nothing that heals, the node
**halts rotation, keeps serving decrypts (MPK intact), and emits a loud error/alert** for human
intervention. Auto-heal never triggers an automatic re-DKG (that would change the MPK and
permanently invalidate existing ciphertexts).

## Testing

All via `./scripts/goTest.sh`.

- **Prevention regression** — reproduce the degraded round in which a recipient computes an
  off-polynomial refreshed share; assert the round now aborts before persist (self-share
  verification fails / finalize-critical gap is fatal), and that a clean round still persists.
- **Auto-heal detection + rollback** — N consecutive MPK-validation aborts on the same active
  source version trigger demotion; assert active rolls back to the LKG marker and the next round
  (dealing from the good source) validates and persists.
- **Walk-back path** — no LKG marker (or LKG also poisoned): assert the descending scan skips
  poisoned versions and selects the highest good version below the poison.
- **Floor** — history exhausted with no healing version: assert rotation halts, decrypt still
  works, and a loud error is logged (no auto-re-DKG).

## Scope / non-goals

- No new P2P protocol messages, no new HTTP endpoints, no manual Redis surgery.
- MPK is preserved; all existing ciphertexts remain decryptable.
- Once deployed, preprod heals on its own: it demotes `1783944564` and falls back to
  `1783944444`, then resumes rotation.
- Not in scope: pruning old key versions, changing the reshare interval, or altering the
  on-chain commitment-registry schema.

## Rollout

1. Land Part 1 (prevention) + Part 2 (auto-heal) together with unit + integration suites green.
2. Deploy the new image to preprod. Nodes demote the poisoned `1783944564`, roll back to
   `1783944444`, and rotation resumes automatically (no manual intervention).
3. Re-run the ECDSA soak (`scripts/testEcdsaEncryptDecrypt.sh` in a loop, genesis held constant)
   to confirm sustained liveness + durability while `source_version` advances again.
