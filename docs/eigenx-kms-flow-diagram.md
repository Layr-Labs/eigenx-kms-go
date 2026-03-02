# EigenX KMS AVS — High-Level Process Flow

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            EigenX Platform Layers                               │
│                                                                                 │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │  Developer   │    │  Blockchain  │    │   KMS AVS    │    │  TEE (Intel  │   │
│  │  (CLI/App)   │    │  (Ethereum)  │    │  (Operators) │    │    TDX)      │   │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘   │
│         │                   │                   │                   │            │
│    Deploys apps        Source of truth     Threshold crypto     Runs apps in    │
│    & secrets           for operator sets   & key management     hardware-       │
│                        & app configs                            isolated VMs    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Operator Lifecycle

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         OPERATOR REGISTRATION                                │
│                                                                              │
│   Operator                    EigenLayer Contracts              KMS AVS      │
│      │                              │                             │          │
│      │  1. Register as EigenLayer   │                             │          │
│      │     operator (stake ETH)     │                             │          │
│      ├─────────────────────────────→│                             │          │
│      │                              │                             │          │
│      │  2. Register BN254 public    │                             │          │
│      │     key to KeyRegistrar      │                             │          │
│      ├─────────────────────────────→│                             │          │
│      │                              │                             │          │
│      │  3. Register socket address  │                             │          │
│      │     (HTTP endpoint URL)      │                             │          │
│      ├─────────────────────────────→│                             │          │
│      │                              │                             │          │
│      │  4. Join AVS operator set    │                             │          │
│      ├─────────────────────────────→│                             │          │
│      │                              │                             │          │
│      │  5. Start KMS node ──────────┼────────────────────────────→│          │
│      │     (polls blockchain)       │                             │          │
│      │                              │                             │          │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Distributed Key Generation (DKG) — Genesis

Triggered when operators start for the first time with no existing key shares.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    BLOCK-BASED DKG TRIGGER                                   │
│                                                                              │
│   KMS Node               Ethereum RPC                                        │
│      │                       │                                               │
│      │  Poll finalized block │                                               │
│      ├──────────────────────→│                                               │
│      │                       │                                               │
│      │  blockNumber          │                                               │
│      │◄──────────────────────┤                                               │
│      │                       │                                               │
│      │  blockNumber % reshareInterval == 0 ?                                 │
│      │  YES → No local shares + no cluster keys?                             │
│      │         YES → Trigger Genesis DKG (session = blockNumber)             │
│      │         NO  → Has local shares?                                       │
│      │                YES → Trigger Reshare                                  │
│      │                NO  → Trigger Join (passive reshare)                   │
│      │                                                                       │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                           DKG PROTOCOL                                       │
│                                                                              │
│   Operator A          Operator B          Operator C          Operator N     │
│      │                   │                   │                   │           │
│      │   ┌───────────────────────────────────────────────────┐   │           │
│      │   │  PHASE 1: Share Distribution                      │   │           │
│      │   └───────────────────────────────────────────────────┘   │           │
│      │                   │                   │                   │           │
│      │  Generate random polynomial f_A(z) of degree t-1         │           │
│      │  Compute commitments C_k = a_k · G2                      │           │
│      │                   │                   │                   │           │
│      │── Broadcast commitments (POST /dkg/commitment) ─────────→│           │
│      │── Send share s_AB = f_A(nodeID_B)  (POST /dkg/share) ──→│           │
│      │── Send share s_AC = f_A(nodeID_C) ──────────────────────→│           │
│      │                   │                   │                   │           │
│      │◄── Receive commitments & shares from B, C, ..., N ───────│           │
│      │                   │                   │                   │           │
│      │   ┌───────────────────────────────────────────────────┐   │           │
│      │   │  PHASE 2: Verification & Acknowledgement          │   │           │
│      │   └───────────────────────────────────────────────────┘   │           │
│      │                   │                   │                   │           │
│      │  Verify each share: s · G2 == Σ(C_k · nodeID^k) ?       │           │
│      │  If valid → send signed acknowledgement (POST /dkg/ack)  │           │
│      │  If invalid → report fraud proof to slashing contract    │           │
│      │                   │                   │                   │           │
│      │── Send ack to B ─→│                   │                   │           │
│      │── Send ack to C ──────────────────────→                   │           │
│      │◄── Receive acks from B, C, ..., N ────────────────────────│           │
│      │                   │                   │                   │           │
│      │  Wait for 100% acknowledgements (all operators must ack) │           │
│      │                   │                   │                   │           │
│      │   ┌───────────────────────────────────────────────────┐   │           │
│      │   │  PHASE 3: Finalization                            │   │           │
│      │   └───────────────────────────────────────────────────┘   │           │
│      │                   │                   │                   │           │
│      │  Compute final share: x_A = Σ(s_iA) for all operators i │           │
│      │  Store KeyShareVersion(version=blockNumber, share=x_A)   │           │
│      │  Mark as active                                           │           │
│      │                   │                   │                   │           │
│      │   Master secret S = Σ f_i(0) — NEVER computed anywhere   │           │
│      │   Each operator only knows their share x_j                │           │
│      │                   │                   │                   │           │
└──────────────────────────────────────────────────────────────────────────────┘

    KEY PROPERTY: threshold t = ⌈2n/3⌉
    ─────────────────────────────────────
    n=3  → t=2  (tolerate 1 failure)
    n=7  → t=5  (tolerate 2 failures)
    n=10 → t=7  (tolerate 3 failures)
```

---

## 3. Key Resharing (Periodic Rotation)

Reshare runs automatically at every block interval. Preserves the master secret while rotating all shares.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          RESHARE PROTOCOL                                    │
│                                                                              │
│  Trigger: blockNumber % reshareInterval == 0                                 │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ Existing operators (have shares)           New operators (no shares)   │  │
│  │                                                                        │  │
│  │  For each existing operator i:             Passive receivers:          │  │
│  │                                                                        │  │
│  │  1. Create polynomial f'_i(z) where:      1. Receive shares from      │  │
│  │     f'_i(0) = current_share_i  ← KEY!        all existing operators   │  │
│  │     (higher-degree terms random)                                       │  │
│  │                                            2. Verify against           │  │
│  │  2. Evaluate & send shares to ALL             commitments              │  │
│  │     operators (existing + new)                                         │  │
│  │                                            3. Compute initial share    │  │
│  │  3. Broadcast new commitments                 via Lagrange interp.     │  │
│  │                                                                        │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  All operators (existing + new):                                             │
│                                                                              │
│    1. Compute Lagrange coefficients λ_i for existing operator set            │
│    2. Compute new share: x'_j = Σ(λ_i × received_share_ij)                  │
│    3. Store new KeyShareVersion, mark previous inactive                      │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ Master secret preservation:                                            │  │
│  │                                                                        │  │
│  │   S' = Σ(λ_i × f'_i(0)) = Σ(λ_i × x_i) = S  ← SAME master secret   │  │
│  │                                                                        │  │
│  │ Old shares become cryptographically independent (forward secrecy)      │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  Reshare Intervals:                                                          │
│  ┌──────────────────┬────────────────┬───────────┐                           │
│  │ Chain            │ Block Interval │ Real Time │                           │
│  ├──────────────────┼────────────────┼───────────┤                           │
│  │ Ethereum Mainnet │ 50 blocks      │ ~10 min   │                           │
│  │ Sepolia Testnet  │ 10 blocks      │ ~2 min    │                           │
│  │ Anvil Devnet     │ 5 blocks       │ ~5 sec    │                           │
│  └──────────────────┴────────────────┴───────────┘                           │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Application Deployment & Secret Delivery (End-to-End)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    APPLICATION DEPLOYMENT FLOW                                │
│                                                                              │
│  Developer        Blockchain       Coordinator       KMS Operators    TEE    │
│     │                │                │                  │             │      │
│     │ 1. Build Docker│                │                  │             │      │
│     │    image &     │                │                  │             │      │
│     │    push to     │                │                  │             │      │
│     │    registry    │                │                  │             │      │
│     │                │                │                  │             │      │
│     │ 2. Deploy app  │                │                  │             │      │
│     │    on-chain:   │                │                  │             │      │
│     │    - image     │                │                  │             │      │
│     │      digest    │                │                  │             │      │
│     │    - encrypted │                │                  │             │      │
│     │      secrets   │                │                  │             │      │
│     ├───────────────→│                │                  │             │      │
│     │                │                │                  │             │      │
│     │                │ 3. Emit        │                  │             │      │
│     │                │  AppDeployed   │                  │             │      │
│     │                │  event ───────→│                  │             │      │
│     │                │                │                  │             │      │
│     │                │                │ 4. Provision     │             │      │
│     │                │                │    Intel TDX VM  │             │      │
│     │                │                │    on GCP ──────────────────→ │      │
│     │                │                │                  │             │      │
│     │                │                │                  │  5. TEE     │      │
│     │                │                │                  │  generates  │      │
│     │                │                │                  │  attestation│      │
│     │                │                │                  │  JWT (TDX   │      │
│     │                │                │                  │  quote)     │      │
│     │                │                │                  │◄────────────│      │
│     │                │                │                  │             │      │
│     │                │                │                  │  6. Request │      │
│     │                │                │                  │  secrets    │      │
│     │                │                │                  │  POST       │      │
│     │                │                │                  │  /secrets   │      │
│     │                │                │                  │◄────────────│      │
│     │                │                │                  │             │      │
│     │                │ 7. Query       │                  │             │      │
│     │                │ expected image │                  │             │      │
│     │                │ digest for     │                  │             │      │
│     │                │ appID          │                  │             │      │
│     │                │◄──────────────────────────────────│             │      │
│     │                │                │                  │             │      │
│     │                │ 8. Return      │                  │             │      │
│     │                │ expected digest│                  │             │      │
│     │                ├──────────────────────────────────→│             │      │
│     │                │                │                  │             │      │
│     │                │                │       9. VERIFY: │             │      │
│     │                │                │       - Attest.  │             │      │
│     │                │                │         signature│             │      │
│     │                │                │       - Image    │             │      │
│     │                │                │         digest   │             │      │
│     │                │                │         matches  │             │      │
│     │                │                │       - RTMR     │             │      │
│     │                │                │         values   │             │      │
│     │                │                │                  │             │      │
│     │                │                │       10. Generate│            │      │
│     │                │                │       partial sig │            │      │
│     │                │                │       σ_i =      │             │      │
│     │                │                │       H(appID)^  │             │      │
│     │                │                │       (share_i)  │             │      │
│     │                │                │                  │             │      │
│     │                │                │       11. Return │             │      │
│     │                │                │       encrypted  │             │      │
│     │                │                │       response   │             │      │
│     │                │                │                  ├────────────→│      │
│     │                │                │                  │             │      │
│     │                │                │                  │ 12. TEE     │      │
│     │                │                │                  │ collects    │      │
│     │                │                │                  │ t=⌈2n/3⌉   │      │
│     │                │                │                  │ partial     │      │
│     │                │                │                  │ sigs        │      │
│     │                │                │                  │             │      │
│     │                │                │                  │ 13. Recover │      │
│     │                │                │                  │ app private │      │
│     │                │                │                  │ key via     │      │
│     │                │                │                  │ Lagrange    │      │
│     │                │                │                  │ interpolat. │      │
│     │                │                │                  │             │      │
│     │                │                │                  │ 14. Decrypt │      │
│     │                │                │                  │ secrets +   │      │
│     │                │                │                  │ derive      │      │
│     │                │                │                  │ mnemonic    │      │
│     │                │                │                  │             │      │
│     │                │                │                  │ 15. Inject  │      │
│     │                │                │                  │ MNEMONIC +  │      │
│     │                │                │                  │ secrets as  │      │
│     │                │                │                  │ env vars    │      │
│     │                │                │                  │             │      │
│     │                │                │                  │ 16. Start   │      │
│     │                │                │                  │ app         │      │
│     │                │                │                  │ container   │      │
│     │                │                │                  │             │      │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. KMS Client Workflows (Encrypt / Decrypt / Secrets)

### CLI Usage

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Global Flags (all commands)                                                 │
│  ──────────────────────────────────────────────────────────────────────────  │
│  --rpc-url           Ethereum RPC URL (default: http://localhost:8545)       │
│  --avs-address       AVS contract address (required)                         │
│  --operator-set-id   Operator set ID (default: 0)                            │
│                                                                              │
│  Commands                                                                    │
│  ──────────────────────────────────────────────────────────────────────────  │
│  get-pubkey   --app-id "my-app"                                              │
│  encrypt      --app-id "my-app" --data "secret" [--output file.hex]          │
│  decrypt      --app-id "my-app" --encrypted-data file.hex [--output out.txt] │
└──────────────────────────────────────────────────────────────────────────────┘

  Example:

  # Encrypt
  ./bin/kms-client --avs-address "0xAVS..." --operator-set-id 0 \
    encrypt --app-id "my-app" --data "DB_PASS=secret;API_KEY=key456" \
    --output encrypted.hex

  # Decrypt
  ./bin/kms-client --avs-address "0xAVS..." --operator-set-id 0 \
    decrypt --app-id "my-app" --encrypted-data encrypted.hex
```

---

### 5a. Operator Discovery

All client workflows begin by discovering the current operator set from the blockchain.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        OPERATOR DISCOVERY                                    │
│                                                                              │
│  kms-client                       Blockchain (EigenLayer Contracts)           │
│     │                                    │                                   │
│     │  GetOperatorSetMembersWithPeering( │                                   │
│     │    avsAddress, operatorSetID)       │                                   │
│     ├───────────────────────────────────→│                                   │
│     │                                    │                                   │
│     │  ┌─────────────────────────────────┤                                   │
│     │  │  1. OperatorSetRegistrar        │                                   │
│     │  │     → list operator addresses   │                                   │
│     │  │                                 │                                   │
│     │  │  2. KeyRegistrar (per operator) │                                   │
│     │  │     → BN254 public key          │                                   │
│     │  │                                 │                                   │
│     │  │  3. Socket Registry (per op.)   │                                   │
│     │  │     → HTTP endpoint URL         │                                   │
│     │  └─────────────────────────────────┤                                   │
│     │                                    │                                   │
│     │  ◄─── OperatorSetPeers[] ──────────┤                                   │
│     │       [                            │                                   │
│     │         {                           │                                   │
│     │           operatorAddress: 0xABC..  │                                   │
│     │           socketAddress: http://..  │                                   │
│     │           bn254PublicKey: (G1)      │                                   │
│     │         },                          │                                   │
│     │         ...                         │                                   │
│     │       ]                            │                                   │
│     │                                    │                                   │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

### 5b. Encryption Workflow (Boneh-Franklin IBE)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│              CLIENT ENCRYPTION — STEP-BY-STEP                                │
│                                                                              │
│  kms-client              Operator 1       Operator 2       Operator N        │
│     │                       │                │                │              │
│     │                                                                        │
│     │  ┌─────────────────────────────────────────────────────────────────┐   │
│     │  │ STEP 1: Collect public key commitments (concurrent)             │   │
│     │  └─────────────────────────────────────────────────────────────────┘   │
│     │                       │                │                │              │
│     │── GET /pubkey ───────→│                │                │              │
│     │── GET /pubkey ────────────────────────→│                │              │
│     │── GET /pubkey ─────────────────────────────────────────→│              │
│     │                       │                │                │              │
│     │◄── {commitments:      │                │                │              │
│     │     [C_1,0, C_1,1,..],│                │                │              │
│     │     version, isActive} │               │                │              │
│     │                       │                │                │              │
│     │◄──────────────────────────── responses from all ────────│              │
│     │                                                                        │
│     │  ┌─────────────────────────────────────────────────────────────────┐   │
│     │  │ STEP 2: Compute master public key                               │   │
│     │  └─────────────────────────────────────────────────────────────────┘   │
│     │                                                                        │
│     │  masterPubKey = Σ( commitments[i][0] )  for all operators i            │
│     │                                                                        │
│     │  Each commitments[i][0] is a_i,0 · G2 (constant term)                 │
│     │  Sum = (Σ a_i,0) · G2 = S · G2  where S is the master secret          │
│     │                                                                        │
│     │  ┌─────────────────────────────────────────────────────────────────┐   │
│     │  │ STEP 3: IBE Encrypt (Boneh-Franklin scheme)                     │   │
│     │  └─────────────────────────────────────────────────────────────────┘   │
│     │                                                                        │
│     │  a) Q_ID = HashToG1(appID)           // app "public key" in G1        │
│     │                                                                        │
│     │  b) r ← random ∈ Fr                  // fresh randomness              │
│     │                                                                        │
│     │  c) C1 = r · G2                      // ephemeral public key (96 B)   │
│     │                                                                        │
│     │  d) g_ID = e(Q_ID, masterPubKey)^r   // pairing → GT element          │
│     │     ────────────────────────────────────────────────────               │
│     │     This is the shared secret between encryptor and                    │
│     │     whoever can reconstruct the app private key [S]·Q_ID              │
│     │                                                                        │
│     │  e) symKey = HKDF-SHA256(                                              │
│     │       ikm   = g_ID bytes,                                              │
│     │       salt  = "eigenx-kms-go-ibe-encryption",                          │
│     │       info  = "IBE-encryption|v1|{appID}",                             │
│     │       len   = 32 bytes                // AES-256 key                   │
│     │     )                                                                  │
│     │                                                                        │
│     │  f) nonce ← random 96 bits            // AES-GCM nonce                │
│     │                                                                        │
│     │  g) AAD = appID ‖ 0x01 ‖ C1_bytes     // additional authenticated     │
│     │                                       // data (binds to app + C1)      │
│     │                                                                        │
│     │  h) encryptedData = AES-GCM-Encrypt(symKey, nonce, plaintext, AAD)     │
│     │                                                                        │
│     │  ┌─────────────────────────────────────────────────────────────────┐   │
│     │  │ STEP 4: Assemble ciphertext                                     │   │
│     │  └─────────────────────────────────────────────────────────────────┘   │
│     │                                                                        │
│     │  Final ciphertext format:                                              │
│     │  ┌────────┬─────────┬──────────────┬───────┬──────────────────────┐    │
│     │  │ "IBE"  │ 0x01    │ C1           │ Nonce │ Encrypted + GCM Tag │    │
│     │  │ 3 B    │ 1 B     │ 96 B (G2)   │ 12 B  │ len(data) + 16 B   │    │
│     │  └────────┴─────────┴──────────────┴───────┴──────────────────────┘    │
│     │                                                                        │
│     │  Output: hex-encoded ciphertext → file or stdout                       │
│     │                                                                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

### 5c. Decryption Workflow (Threshold Recovery)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│              CLIENT DECRYPTION — STEP-BY-STEP                                │
│                                                                              │
│  kms-client              Operator 1       Operator 2       Operator N        │
│     │                       │                │                │              │
│     │  threshold = ⌈2n/3⌉ = (2*n + 2) / 3                                   │
│     │                                                                        │
│     │  ┌─────────────────────────────────────────────────────────────────┐   │
│     │  │ STEP 1: Collect partial signatures (concurrent)                 │   │
│     │  └─────────────────────────────────────────────────────────────────┘   │
│     │                       │                │                │              │
│     │── POST /app/sign ────→│                │                │              │
│     │   {                   │                │                │              │
│     │     "app_id": "my-app",               │                │              │
│     │     "attestation_time": 0              │                │              │
│     │   }                   │                │                │              │
│     │                       │                │                │              │
│     │── POST /app/sign ─────────────────────→│                │              │
│     │── POST /app/sign ──────────────────────────────────────→│              │
│     │                       │                │                │              │
│     │       ┌───────────────┤  Each operator computes:       │              │
│     │       │ Operator side │                │                │              │
│     │       │               │  1. Load active key share x_i  │              │
│     │       │               │  2. Q = HashToG1(appID)        │              │
│     │       │               │  3. σ_i = Q ^ x_i    (G1 pt)  │              │
│     │       │               │  4. Return σ_i + operatorAddr  │              │
│     │       └───────────────┤                │                │              │
│     │                       │                │                │              │
│     │◄── { operator_address: "0xA..",        │                │              │
│     │      partial_signature: σ_1 } ────────│                │              │
│     │◄── { ..., σ_2 } ──────────────────────│                │              │
│     │◄── { ..., σ_N } ───────────────────────────────────────│              │
│     │                                                                        │
│     │  Map each response:                                                    │
│     │    nodeID = AddressToNodeID(operatorAddress)                            │
│     │    partialSigs[nodeID] = σ_i                                           │
│     │                                                                        │
│     │  Stop once len(partialSigs) >= threshold                               │
│     │  (tolerates up to ⌊n/3⌋ operator failures)                            │
│     │                                                                        │
│     │  ┌─────────────────────────────────────────────────────────────────┐   │
│     │  │ STEP 2: Recover app private key (Lagrange interpolation)        │   │
│     │  └─────────────────────────────────────────────────────────────────┘   │
│     │                                                                        │
│     │  participants = sorted(partialSigs.keys())[:threshold]                 │
│     │                                                                        │
│     │  For each participant i in {id_1, id_2, ..., id_t}:                    │
│     │                                                                        │
│     │    λ_i = ∏ ( (0 - j) / (i - j) )   for all j ∈ participants, j ≠ i   │
│     │          ─────────────────────────                                     │
│     │          computed in Fr (finite field arithmetic)                       │
│     │                                                                        │
│     │  sk_app = Σ( λ_i · σ_i )  for i ∈ participants                        │
│     │                                                                        │
│     │  ┌────────────────────────────────────────────────────────────────┐    │
│     │  │  WHY THIS WORKS                                                │    │
│     │  │                                                                │    │
│     │  │  Each σ_i = [x_i] · Q_ID   where x_i is operator i's share   │    │
│     │  │                                                                │    │
│     │  │  Lagrange interpolation at x=0 recovers the master secret:    │    │
│     │  │    Σ(λ_i · x_i) = S   (the master secret, by definition)     │    │
│     │  │                                                                │    │
│     │  │  Therefore:                                                    │    │
│     │  │    sk_app = Σ(λ_i · [x_i]·Q_ID)                              │    │
│     │  │           = [Σ(λ_i · x_i)] · Q_ID                            │    │
│     │  │           = [S] · Q_ID                                        │    │
│     │  │           = the full app private key                          │    │
│     │  │                                                                │    │
│     │  │  The master secret S is NEVER reconstructed as a scalar —     │    │
│     │  │  it only appears embedded in the G1 point result.             │    │
│     │  └────────────────────────────────────────────────────────────────┘    │
│     │                                                                        │
│     │  ┌─────────────────────────────────────────────────────────────────┐   │
│     │  │ STEP 3: IBE Decrypt                                             │   │
│     │  └─────────────────────────────────────────────────────────────────┘   │
│     │                                                                        │
│     │  a) Parse ciphertext:                                                  │
│     │     - Verify magic "IBE" + version 0x01                                │
│     │     - Extract C1 (96 B), nonce (12 B), encryptedData (rest)            │
│     │                                                                        │
│     │  b) g_ID = e(sk_app, C1)              // pairing → GT element          │
│     │     ────────────────────────────────────────────────────               │
│     │     e([S]·Q_ID, [r]·G2) = e(Q_ID, G2)^(S·r)                          │
│     │                         = e(Q_ID, [S]·G2)^r                            │
│     │                         = e(Q_ID, masterPubKey)^r                      │
│     │     This matches the encryption g_ID exactly!                          │
│     │                                                                        │
│     │  c) symKey = HKDF-SHA256(g_ID, same salt/info as encryption)           │
│     │                                                                        │
│     │  d) AAD = appID ‖ 0x01 ‖ C1_bytes                                     │
│     │                                                                        │
│     │  e) plaintext = AES-GCM-Decrypt(symKey, nonce, encryptedData, AAD)     │
│     │                                                                        │
│     │  Output: plaintext → file or stdout                                    │
│     │                                                                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

### 5d. TEE Secret Delivery (Attestation-Verified)

For TEE applications, the `/secrets` endpoint replaces the manual encrypt/decrypt flow.
The TEE proves its identity via hardware attestation before receiving secrets.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│              TEE SECRETS FLOW — STEP-BY-STEP                                 │
│                                                                              │
│  TEE Instance                          KMS Operator                          │
│     │                                      │                                 │
│     │  ┌─────────────────────────────────────────────────────────────────┐   │
│     │  │ STEP 1: Prepare request with attestation                        │   │
│     │  └─────────────────────────────────────────────────────────────────┘   │
│     │                                      │                                 │
│     │  Generate ephemeral RSA key pair     │                                 │
│     │  (for encrypting the response)       │                                 │
│     │                                      │                                 │
│     │  Obtain attestation evidence:        │                                 │
│     │  ┌──────────────────────────────────────────────────────────────┐      │
│     │  │ Option A: GCP / Intel (production)                           │      │
│     │  │  - attestation_method: "gcp" or "intel"                      │      │
│     │  │  - attestation: JWT from Confidential Space / Trust Auth.    │      │
│     │  │  - Proves: TEE execution, image digest, platform identity    │      │
│     │  │                                                              │      │
│     │  │ Option B: ECDSA (development)                                │      │
│     │  │  - attestation_method: "ecdsa"                               │      │
│     │  │  - challenge: "<unix_timestamp>-<32_byte_nonce_hex>"         │      │
│     │  │  - attestation: sign(keccak256(appID‖"-"‖challenge‖"-"‖pk)) │      │
│     │  │  - public_key: ECDSA public key bytes                        │      │
│     │  │  - Proves: key ownership only (5 min time window)            │      │
│     │  └──────────────────────────────────────────────────────────────┘      │
│     │                                      │                                 │
│     │── POST /secrets ────────────────────→│                                 │
│     │   {                                  │                                 │
│     │     "app_id":             "my-app",  │                                 │
│     │     "attestation_method": "gcp",     │                                 │
│     │     "attestation":        <jwt>,     │                                 │
│     │     "rsa_pubkey_tmp":     <pem>,     │                                 │
│     │     "attest_time":        1702857600 │                                 │
│     │   }                                  │                                 │
│     │                                      │                                 │
│     │  ┌─────────────────────────────────────────────────────────────────┐   │
│     │  │ STEP 2: Operator verifies attestation                           │   │
│     │  └─────────────────────────────────────────────────────────────────┘   │
│     │                                      │                                 │
│     │                   ┌──────────────────┤                                 │
│     │                   │  1. Verify attestation signature                    │
│     │                   │     (JWT via JWK set for GCP/Intel,                │
│     │                   │      or ECDSA sig verify + time check)             │
│     │                   │                                                    │
│     │                   │  2. Query blockchain for expected                   │
│     │                   │     image digest for this appID                     │
│     │                   │                                                    │
│     │                   │  3. Compare attestation RTMR0 value                │
│     │                   │     against keccak256(imageDigest)                  │
│     │                   │                                                    │
│     │                   │  4. Validate platform certificates                 │
│     │                   │                                                    │
│     │                   │  ANY CHECK FAILS → 401 Unauthorized                │
│     │                   └──────────────────┤                                 │
│     │                                      │                                 │
│     │  ┌─────────────────────────────────────────────────────────────────┐   │
│     │  │ STEP 3: Operator generates partial signature + encrypts secrets │   │
│     │  └─────────────────────────────────────────────────────────────────┘   │
│     │                                      │                                 │
│     │                   ┌──────────────────┤                                 │
│     │                   │  1. Look up key version for attest_time            │
│     │                   │                                                    │
│     │                   │  2. Compute partial sig:                           │
│     │                   │     σ_i = HashToG1(appID) ^ share_i                │
│     │                   │                                                    │
│     │                   │  3. Encrypt partial sig with TEE's                 │
│     │                   │     ephemeral RSA public key                       │
│     │                   │                                                    │
│     │                   │  4. Encrypt env vars with AES                      │
│     │                   │     (developer-provided secrets                    │
│     │                   │      fetched from blockchain)                      │
│     │                   └──────────────────┤                                 │
│     │                                      │                                 │
│     │◄── {                                 │                                 │
│     │      "encrypted_env":         <aes>, │                                 │
│     │      "public_env":            <b64>, │                                 │
│     │      "encrypted_partial_sig": <rsa>  │                                 │
│     │    } ────────────────────────────────│                                 │
│     │                                      │                                 │
│     │  ┌─────────────────────────────────────────────────────────────────┐   │
│     │  │ STEP 4: TEE collects threshold responses & recovers secrets     │   │
│     │  └─────────────────────────────────────────────────────────────────┘   │
│     │                                                                        │
│     │  Repeat POST /secrets to ⌈2n/3⌉ operators (concurrent)                │
│     │                                                                        │
│     │  For each response:                                                    │
│     │    1. RSA-decrypt partial signature with ephemeral private key         │
│     │    2. Map operator address → nodeID                                    │
│     │    3. Collect into partialSigs map                                     │
│     │                                                                        │
│     │  Recover app private key via Lagrange interpolation:                   │
│     │    sk_app = Σ(λ_i · σ_i)  (same math as decrypt flow above)           │
│     │                                                                        │
│     │  Derive deterministic mnemonic:                                        │
│     │    mnemonic = DeriveKey(sk_app, appID)                                 │
│     │                                                                        │
│     │  AES-decrypt environment variables from encrypted_env                  │
│     │                                                                        │
│     │  Inject into container environment:                                    │
│     │    MNEMONIC="word1 word2 ... word12"                                   │
│     │    DB_PASSWORD="..." (from developer secrets)                          │
│     │    API_KEY="..." (from developer secrets)                              │
│     │                                                                        │
│     │  Start application container                                           │
│     │                                                                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

### 5e. Putting It Together — Encrypt/Decrypt Sequence

```
  Developer                kms-client CLI              KMS Operators (n=7, t=5)
     │                         │                              │
     │                         │                              │
     │  ENCRYPT                │                              │
     │  ════════               │                              │
     │                         │                              │
     │  $ kms-client encrypt   │                              │
     │    --app-id "prod-app"  │                              │
     │    --data "SECRET=abc"  │                              │
     │─────────────────────────→                              │
     │                         │                              │
     │                         │──── discover operators ─────→│ (blockchain query)
     │                         │◄─── 7 operators found ──────│
     │                         │                              │
     │                         │──── GET /pubkey (×7) ───────→│ (concurrent)
     │                         │◄─── 7 commitment sets ──────│
     │                         │                              │
     │                         │  mpk = Σ(C[i][0])            │
     │                         │  Q = HashToG1("prod-app")    │
     │                         │  r ← random                  │
     │                         │  C1 = r·G2                   │
     │                         │  g = e(Q, mpk)^r             │
     │                         │  key = HKDF(g)               │
     │                         │  ct = AES-GCM(key, data)     │
     │                         │                              │
     │  ◄── encrypted.hex ─────│                              │
     │                         │                              │
     │                         │                              │
     │  DECRYPT                │                              │
     │  ═══════                │                              │
     │                         │                              │
     │  $ kms-client decrypt   │                              │
     │    --app-id "prod-app"  │                              │
     │    --encrypted-data     │                              │
     │      encrypted.hex      │                              │
     │─────────────────────────→                              │
     │                         │                              │
     │                         │──── discover operators ─────→│
     │                         │◄─── 7 operators found ──────│
     │                         │     threshold = ⌈14/3⌉ = 5   │
     │                         │                              │
     │                         │──── POST /app/sign (×7) ────→│ (concurrent)
     │                         │                              │
     │                         │  Operator 1: σ₁ = Q^x₁  ────│
     │                         │  Operator 2: σ₂ = Q^x₂  ────│  5 respond
     │                         │  Operator 3: timeout     ────│  (sufficient)
     │                         │  Operator 4: σ₄ = Q^x₄  ────│
     │                         │  Operator 5: σ₅ = Q^x₅  ────│  2 fail
     │                         │  Operator 6: error       ────│  (tolerated)
     │                         │  Operator 7: σ₇ = Q^x₇  ────│
     │                         │                              │
     │                         │  Got 5 sigs >= threshold ✓   │
     │                         │                              │
     │                         │  Lagrange interpolation:      │
     │                         │   λ₁·σ₁ + λ₂·σ₂ + λ₄·σ₄     │
     │                         │   + λ₅·σ₅ + λ₇·σ₇            │
     │                         │   = [S]·Q = sk_app            │
     │                         │                              │
     │                         │  Parse ct → C1, nonce, enc   │
     │                         │  g = e(sk_app, C1)           │
     │                         │  key = HKDF(g)               │
     │                         │  data = AES-GCM-Dec(key,..)  │
     │                         │                              │
     │  ◄── "SECRET=abc" ──────│                              │
     │                         │                              │
```

---

## 6. Authenticated P2P Messaging

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                   AUTHENTICATED MESSAGE FLOW                                 │
│                                                                              │
│  Sender Operator                               Receiver Operator             │
│     │                                              │                         │
│     │  1. Construct payload:                       │                         │
│     │     { from, to, session, data }              │                         │
│     │                                              │                         │
│     │  2. Hash: h = keccak256(payload)             │                         │
│     │                                              │                         │
│     │  3. Sign: sig = BN254_sign(h, privkey)       │                         │
│     │                                              │                         │
│     │  4. Wrap: AuthenticatedMessage               │                         │
│     │     { payload, hash, signature }             │                         │
│     │                                              │                         │
│     │ ──── POST /dkg/share ───────────────────────→│                         │
│     │                                              │                         │
│     │                          5. Verify hash:     │                         │
│     │                             keccak256(payload)│                        │
│     │                             == hash ?         │                        │
│     │                                              │                         │
│     │                          6. Lookup sender    │                         │
│     │                             BN254 pubkey     │                         │
│     │                             from peering     │                         │
│     │                             data (blockchain)│                         │
│     │                                              │                         │
│     │                          7. Verify signature │                         │
│     │                             against pubkey   │                         │
│     │                                              │                         │
│     │                          8. Check session    │                         │
│     │                             timestamp matches│                         │
│     │                             current protocol │                         │
│     │                                              │                         │
│     │                          9. Process message  │                         │
│     │                                              │                         │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Fraud Detection & Slashing

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                     FRAUD DETECTION FLOW                                     │
│                                                                              │
│  Honest Operator         Malicious Operator      Slashing Contract           │
│     │                         │                       │                      │
│     │  Receives share from    │                       │                      │
│     │  malicious dealer       │                       │                      │
│     │◄────────────────────────│                       │                      │
│     │                         │                       │                      │
│     │  Verify: s·G2 ≟ Σ(C_k · nodeID^k)              │                      │
│     │  Result: MISMATCH — invalid share!              │                      │
│     │                         │                       │                      │
│     │  Construct fraud proof: │                       │                      │
│     │  - Dealer's signed commitments                  │                      │
│     │  - Invalid signed share                         │                      │
│     │  - Node ID for verification                     │                      │
│     │                         │                       │                      │
│     │  Submit fraud proof ────────────────────────────→│                      │
│     │                         │                       │                      │
│     │                         │      Verify on-chain: │                      │
│     │                         │      - Check sigs     │                      │
│     │                         │      - Re-compute     │                      │
│     │                         │        verification   │                      │
│     │                         │        equation       │                      │
│     │                         │      - Confirm        │                      │
│     │                         │        mismatch       │                      │
│     │                         │                       │                      │
│     │                         │      Slash via        │                      │
│     │                         │      EigenLayer       │                      │
│     │                         │      AllocationManager│                      │
│     │                         │                       │                      │
│     │                         │  ┌────────────────────┴──────────────┐       │
│     │                         │  │  Penalty Schedule                 │       │
│     │                         │  │  ─────────────────────────────    │       │
│     │                         │  │  Invalid Share:    0.1 ETH       │       │
│     │                         │  │  Equivocation:     1.0 ETH       │       │
│     │                         │  │  Commit Inconsist: 0.5 ETH       │       │
│     │                         │  │  Non-Participation: 0.05 ETH/miss│       │
│     │                         │  │  Ejection: after 3+ violations   │       │
│     │                         │  └───────────────────────────────────┘       │
│     │                         │                       │                      │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Complete System Lifecycle (Summary)

```
                    ┌─────────────────────────────────────┐
                    │     OPERATORS REGISTER ON-CHAIN     │
                    │  (stake ETH, register BN254 keys,   │
                    │   set socket addresses)              │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │         GENESIS DKG                  │
                    │  Operators collectively generate     │
                    │  master secret via threshold         │
                    │  secret sharing (Feldman-VSS)        │
                    │  No single operator knows            │
                    │  the master secret.                  │
                    └──────────────────┬──────────────────┘
                                       │
                           ┌───────────┴───────────┐
                           │                       │
                           ▼                       ▼
           ┌──────────────────────┐ ┌──────────────────────┐
           │   PERIODIC RESHARE   │ │  APPLICATION USAGE    │
           │   (every N blocks)   │ │                       │
           │                      │ │  Encrypt: IBE with    │
           │  - Rotate all shares │ │    master public key  │
           │  - Preserve master   │ │                       │
           │    secret S          │ │  Decrypt: Collect     │
           │  - Support operator  │ │    ⌈2n/3⌉ partial    │
           │    joins/leaves      │ │    sigs, Lagrange     │
           │  - Forward secrecy   │ │    interpolation      │
           │                      │ │                       │
           └──────────┬───────────┘ │  Secrets: TEE attests │
                      │             │    to KMS, receives    │
                      │             │    mnemonic + secrets  │
                      └──────┬──────┘                       │
                             │      └───────────────────────┘
                             │
                             ▼
           ┌──────────────────────────────────────────────┐
           │            FRAUD MONITORING                   │
           │                                               │
           │  Operators monitor peers for:                 │
           │  - Invalid shares                             │
           │  - Equivocation                               │
           │  - Commitment inconsistency                   │
           │  - Non-participation                          │
           │                                               │
           │  Violations → Fraud proof → On-chain slash    │
           └──────────────────────────────────────────────┘
```

---

## Security Guarantees at a Glance

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **No single point of failure** | Any ⌈2n/3⌉ operators can serve requests | Threshold secret sharing |
| **Byzantine fault tolerance** | Tolerates ⌊n/3⌋ malicious operators | ⌈2n/3⌉ threshold + verification |
| **Master secret never reconstructed** | Secret stays distributed across operators | Shamir secret sharing |
| **Forward secrecy** | Old shares useless after reshare | Periodic reshare with new polynomials |
| **Authenticated messaging** | All P2P messages signed with BN254 | Signature verification via blockchain keys |
| **Economic security** | Misbehavior is costly | On-chain fraud proofs + EigenLayer slashing |
| **Hardware isolation** | Keys inaccessible outside TEE | Intel TDX memory encryption |
| **Deterministic identity** | Same app → same wallet across deploys | HMAC(masterSecret, appID) |
| **Code integrity** | Only authorized images get keys | Attestation + blockchain image digest |
