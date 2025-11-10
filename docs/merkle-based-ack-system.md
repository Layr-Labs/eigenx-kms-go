# Merkle-Based Acknowledgement System for Fully Distributed DKG

## Key Difference: Everyone Deals to Everyone

### Centralized Dealer (Not your design)
```
         ┌──────────┐
         │  Dealer  │ ──→ generates all shares
         └────┬─────┘
              │
         ┌────┴────┬────────┬────────┐
         ▼         ▼        ▼        ▼
     Player1   Player2  Player3  Player4
```

### Distributed DKG (Your actual design)
```
      Op1    Op2    Op3    Op4
       │      │      │      │
       │ Each operator generates their own polynomial
       │      │      │      │
       ├──────┼──────┼──────┤  Op1 sends shares to everyone
       │      ├──────┼──────┤  Op2 sends shares to everyone
       │      │      ├──────┤  Op3 sends shares to everyone
       │      │      │      │
       ▼      ▼      ▼      ▼
     Everyone has n shares (one from each operator)
```

---

## Revised Architecture

### Smart Contract State

Each operator submits THEIR OWN commitment + ack Merkle root:

**Epoch 5:**
- **Operator1:**
  - commitmentHash: `0xabc...` (Op1's polynomial)
  - ackMerkleRoot: `0xdef...` (acks from all players)

- **Operator2:**
  - commitmentHash: `0x123...` (Op2's polynomial)
  - ackMerkleRoot: `0x456...` (acks from all players)

- **Operator3:**
  - commitmentHash: `0x789...` (Op3's polynomial)
  - ackMerkleRoot: `0xabc...` (acks from all players)

- ... (one entry per operator)

**Total:** n operators × 64 bytes each

---

## Phase 1: Every Operator Deals to Everyone

### All Operators Simultaneously

```
Operator 1              Operator 2              Operator 3
    │                       │                       │
    │ Generate f₁(x)        │ Generate f₂(x)        │ Generate
    │ polynomial            │ polynomial            │ f₃(x)
    │                       │                       │
    ├───────────────────────┼───────────────────────┤
    │ Send s₁₂ to Op2 ─────→                       │
    │ Send s₁₃ to Op3 ──────┼──────────────────────→
    │                       │                       │
    ← Receive s₂₁ from Op2 ─┤                       │
    ← Receive s₃₁ from Op3 ─┼───────────────────────┤
    │                       │                       │
    │                       ├───────────────────────┤
    │                       │ Send s₂₃ to Op3 ─────→
    │                       ← Receive s₃₂ from Op3 ─
    │                       │                       │
    ▼                       ▼                       ▼
```

**Each operator now has:**
- Their own polynomial (secret)
- n-1 shares received from others
- n-1 commitments received from others

---

## Phase 2: Acknowledgement Collection (Symmetric)

### Operator 1's Perspective (as dealer)

Op1 sent shares to everyone. Now collecting acks:

**Operator 2:**
1. Received share `s₁₂` from Op1
2. Verified: `s₁₂·G2 == Σ(C₁ₖ·nodeID₂^k)` ✓
3. Signs Ack:
   ```
   {
     player: Op2,
     dealer: Op1,
     shareHash: hash(s₁₂),
     signature: BN254_sign(...)
   }
   ```
4. Sends `Ack₂₁` to Op1

**Operator 3:**
1. Received share `s₁₃` from Op1
2. Verified & signed `Ack₃₁`
3. Sends `Ack₃₁` to Op1

Op1 collects: `[Ack₂₁, Ack₃₁, ... Ackₙ₁]`
(n-1 acks, one from each other operator)

### Simultaneously: Op1 also playing (receiving)

Op1 receives shares from everyone else:
- Share from Op2 → Verify → Send `Ack₁₂` to Op2
- Share from Op3 → Verify → Send `Ack₁₃` to Op3
- Share from Op4 → Verify → Send `Ack₁₄` to Op4

**Op1 is BOTH:**
- Dealer (collecting acks for shares it sent)
- Player (sending acks for shares it received)

---

## Acknowledgement Structure

### From Player's Perspective

"I (player) acknowledge receiving a valid share from dealer"

```go
Ack {
  player: my_address           // Who is acknowledging
  dealer: sender_address       // Who sent the share
  epoch: 5                     // Which reshare round
  shareHash: keccak256(share)  // Commits to received share
  commitmentHash: hash(C₀...)  // Commits to commitments
  signature: BN254_sig(above)  // Player signs all above
}
```

**Key Point:** Each operator collects n-1 acks (one from each OTHER operator for shares they sent)

---

## Phase 3: Each Operator Builds Their Own Merkle Tree

### Operator 1 (as dealer)

Collected acks: `[Ack₂₁, Ack₃₁, Ack₄₁, ... Ackₙ₁]`

**Step 1:** Sort by player address
```
┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐
│Ack₂₁ │  │Ack₃₁ │  │Ack₄₁ │  │Ackₙ₁ │
└───┬──┘  └───┬──┘  └───┬──┘  └───┬──┘
    │         │         │         │
    └─────────┴─────────┴─────────┘
              │
```

**Step 2:** Build Merkle tree
```
         ┌────┴────┐
         │ Root₁   │ ← Op1's Merkle root
         └─────────┘
```

### Operator 2 (as dealer)

Collected acks: `[Ack₁₂, Ack₃₂, Ack₄₂, ... Ackₙ₂]`

Builds own Merkle tree:
```
         ┌─────────┐
         │ Root₂   │ ← Op2's Merkle root (different!)
         └─────────┘
```

**Each operator submits THEIR OWN:**
- commitmentHash (their polynomial commitments)
- ackMerkleRoot (acks they collected as dealer)

---

## Phase 4: Contract Submission (All Operators)

### Smart Contract State - Epoch 5 commitments

**Operator1:**
- commitmentHash: `hash(Op1's C₀, C₁, C₂, C₃)`
- ackMerkleRoot: `root([Ack₂₁, Ack₃₁, Ack₄₁])`
- submittedAt: block 1000

**Operator2:**
- commitmentHash: `hash(Op2's C₀, C₁, C₂, C₃)`
- ackMerkleRoot: `root([Ack₁₂, Ack₃₂, Ack₄₂])`
- submittedAt: block 1000

**Operator3:**
- commitmentHash: `hash(Op3's C₀, C₁, C₂, C₃)`
- ackMerkleRoot: `root([Ack₁₃, Ack₂₃, Ack₄₃])`
- submittedAt: block 1001

... (one entry per operator)

Each operator independently submits their dealing information

---

## Phase 5: Broadcast & Verification (Symmetric)

### Every Operator Broadcasts to Every Other

**Operator 1 broadcasts:**
```
From: Operator1
Commitments: [C₁₀, C₁₁, C₁₂, C₁₃]
All acks: [Ack₂₁, Ack₃₁, Ack₄₁, ...]

To Operator2: Include Merkle proof for Ack₂₁
To Operator3: Include Merkle proof for Ack₃₁
To Operator4: Include Merkle proof for Ack₄₁
```

**Operator 2 broadcasts:**
```
From: Operator2
Commitments: [C₂₀, C₂₁, C₂₂, C₂₃]
All acks: [Ack₁₂, Ack₃₂, Ack₄₂, ...]

To Operator1: Include Merkle proof for Ack₁₂
To Operator3: Include Merkle proof for Ack₃₂
To Operator4: Include Merkle proof for Ack₄₂
```

... (every operator broadcasts)

---

## Verification Flow (Each Operator Verifies All Others)

### Operator 1 Verifies Operator 2's Broadcast

**Step 1:** Query contract for Op2's commitment
```
contract.getCommitment(epoch=5, dealer=Op2)
Returns: {
  commitmentHash: 0x123...,
  ackMerkleRoot:  0x456...
}
```

**Step 2:** Verify commitment hash matches broadcast
```
hash(Op2's broadcast commitments) == 0x123... ✓
```

**Step 3:** Find MY ack in Op2's ack list
```
Find Ack₁₂ where:
  player = Op1
  dealer = Op2
  shareHash = hash(s₂₁) ← share I received from Op2
```

**Step 4:** Verify MY ack is correct
```
Ack₁₂.shareHash == hash(s₂₁) ✓
(s₂₁ is the share I originally received from Op2)
```

**Step 5:** Verify Merkle proof
```
verifyMerkleProof(
  proof = Op2's provided proof,
  root = 0x456...,  ← from contract
  leaf = hash(Ack₁₂)
) == true ✓
```

✓ Op2's broadcast is valid!
Accept Op2's commitments for finalization

**Repeat this process for ALL operators:**
- Op1 verifies Op2's broadcast
- Op1 verifies Op3's broadcast
- Op1 verifies Op4's broadcast
- ... etc

**EVERY operator verifies EVERY other operator's broadcast**

---

## Finalization (Each Operator Computes Locally)

### Local Finalization (Op1's view)

After verifying all broadcasts, Op1 has:

**Valid commitments from all operators:**
- Op1's commitments (own)
- Op2's commitments (verified ✓)
- Op3's commitments (verified ✓)
- Op4's commitments (verified ✓)
- ... (n total)

**Received shares from all operators:**
- `s₁₁` (own share from own polynomial)
- `s₂₁` (share from Op2)
- `s₃₁` (share from Op3)
- `s₄₁` (share from Op4)
- ... (n total shares)

**Compute final share (summation):**
```
x₁ = s₁₁ + s₂₁ + s₃₁ + s₄₁ + ... + sₙ₁

(Sum of all shares received from all operators)
```

**Compute master public key (commitment aggregation):**
```
MPK = Σ(Op1_C₀ + Op2_C₀ + Op3_C₀ + ... + Opₙ_C₀)

(Sum of constant terms from all commitments)
```

**Store new KeyShareVersion:**
- version: epoch 5
- privateShare: x₁
- commitments: [all verified commitments]
- isActive: true

✓ DKG Complete!

**EVERY operator performs this same computation independently**

**Result:** All operators compute identical master public key, but each has unique private share `x₁, x₂, x₃, x₄...`

---

## Fraud Detection (Revised for Distributed)

### Fraud: Op2 sends different shares to different players

Op2's polynomial: `f₂(x) = 3 + 2x`

- Op2 sends to Op1: `s₂₁ = 5` (from polynomial f₂(x))
- Op2 sends to Op3: `s₂₃ = 11` (from DIFFERENT polynomial!)

Both verify individually against Op2's commitments!

### Fraud Detection via Gossip

Op1 and Op3 gossip:

- Op1 tells Op3: "I received s₂₁=5 from Op2"
- Op3 tells Op1: "I received s₂₃=11 from Op2"

Verification:
- Op1 checks: `hash(s₂₁)` in Op2's `Ack₁₂`
- Op3 checks: `hash(s₂₃)` in Op2's `Ack₃₂`

Both acks are in Op2's Merkle tree on contract!

But:
- `Ack₁₂.shareHash ≠ Ack₃₂.shareHash`
- AND: Both shares verify against Op2's commitments

→ **EQUIVOCATION DETECTED!**

### Fraud Proof Construction

Either Op1 or Op3 can construct proof:

```
Proof {
  dealer: Op2
  commitments: Op2's [C₀, C₁, C₂, C₃]

  // First player's data
  ack1: Ack₁₂
  merkleProof1: [proof for Ack₁₂ in Op2's tree]
  share1: s₂₁ = 5

  // Second player's data
  ack2: Ack₃₂
  merkleProof2: [proof for Ack₃₂ in Op2's tree]
  share2: s₂₃ = 11
}
```

Submit to contract: `proveEquivocation(proof)`

### Contract Verification & Slashing

Contract verifies:
1. Both acks in Op2's Merkle tree ✓
2. Both acks have valid signatures ✓
3. Both shares verify against commitments ✓
4. But shareHashes are different ✓

→ Slash Op2 via EigenLayer
→ Other operators exclude Op2 from finalization

---

## Complete Timeline (Distributed DKG)

### Epoch 5 Reshare Timeline

**Block 1000 (Trigger)**

↓

### Phase 1: Share Distribution (Blocks 1000-1010)

**EVERY operator:**
- Generates own polynomial
- Sends shares to all other operators
- Receives shares from all other operators
- Verifies received shares
- Sends acks back to dealers
- Collects acks from players

↓

### Phase 2: Merkle Tree & Contract (Blocks 1010-1015)

**EVERY operator:**
- Builds Merkle tree from collected acks
- Hashes own commitments
- Submits commitmentHash + ackMerkleRoot to contract

↓

### Phase 3: Broadcast & Verify (Blocks 1015-1025)

**EVERY operator:**
- Broadcasts commitments + acks to everyone
- Verifies broadcasts from all others
- Checks acks against contract Merkle roots
- Gossips to detect any equivocation

↓

### Phase 4: Finalization (Block 1100 - epoch boundary)

**EVERY operator:**
- Sums all received shares → new private share
- Aggregates all commitments → master public key
- Stores new KeyShareVersion
- Marks epoch complete

↓

✓ Reshare Complete - Ready for next epoch

---

## Cost Analysis (Corrected)

### Cost Per Epoch

**With 10 operators:**

**Per operator submission:**
- commitmentHash: 32 bytes
- ackMerkleRoot: 32 bytes
- Gas: ~21,000
- Cost: ~$0.0004 @ 20 gwei

**Total per epoch:**
- 10 operators × $0.0004 = $0.004

**Monthly (6 epochs/hour × 24 hours × 30 days):**
- $0.004 × 4,320 epochs = ~$17/month

**Comparisons:**
- vs Full acks on-chain: ~$43,000/month
- vs No acks (insecure): ~$15/month (but vulnerable!)

**Extra cost for security:** $2/month
→ Absolute bargain for fraud detection!

---

## Key Corrections Summary

1. **Every operator is both dealer AND player** - they all generate polynomials and exchange shares symmetrically

2. **Each operator submits their own commitment** - contract stores n entries (one per operator), not just one

3. **Each operator builds their own Merkle tree** - from the n-1 acks they collected as a dealer

4. **Every operator verifies every other operator** - O(n²) verification but all done off-chain

5. **Finalization is summation** - each operator sums all received shares to get their final share

6. **Fraud detection requires gossip** - operators must communicate to detect equivocation since no single operator sees all shares

The fundamental security properties remain the same, but the architecture is fully symmetric rather than centralized!
