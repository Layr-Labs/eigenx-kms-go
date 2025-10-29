# Distributed KMS - Design Brief

## Overview

EigenX KMS AVS is a distributed key management system running as an EigenLayer AVS that serves as the trust layer for the EigenX TEE compute platform. The system uses threshold cryptography (BLS12-381) to ensure that ⌈2n/3⌉ operators must collaborate to provide application secrets, eliminating single points of failure while maintaining Byzantine fault tolerance.

**Key Innovation**: Applications deployed in Intel TDX TEEs receive deterministic wallet mnemonics through threshold signature aggregation, enabling persistent cryptographic identities across deployments without any single operator having sufficient information to compromise secrets.

---

## Core Architecture

### System Role in EigenX Platform

```
Developer → Blockchain (Registry) → KMS AVS (Threshold Verification) → TEE Instance
              ↓                           ↓                                ↓
         Image Digest              Attestation Check              Mnemonic Injection
                                   + Threshold Signing
```

**Trust Model**:
- **Before**: Single centralized KMS operator (trusted party)
- **After**: ⌈2n/3⌉ distributed operators (trustless, Byzantine fault tolerant)
- **Developer Impact**: None - same `MNEMONIC` environment variable

---

## Cryptographic Foundation

### Threshold Scheme

- **Curve**: BLS12-381 (pairing-friendly, threshold-optimized)
- **Threshold**: t = ⌈2n/3⌉ (Byzantine fault tolerance)
- **Secret Sharing**: Shamir secret sharing over Fr field
- **Master Secret**: S = Σ fᵢ(0) (never reconstructed, remains distributed)
- **Operator Shares**: xⱼ = Σ fᵢ(j) (each operator holds one share)

### DKG Protocol Variants

**Alpha Testnet - Feldman-VSS**:
- Single polynomial: fᵢ(z) with commitments Cᵢₖ = aᵢₖ·G₂
- Computationally secure (discrete log assumption)
- Vulnerable to bias attacks (mitigated by economic slashing)
- Faster to implement, suitable for rapid iteration

**Production - Pedersen-VSS**:
- Dual polynomials: fᵢ(z), f'ᵢ(z) with commitments Cᵢₖ = aᵢₖ·G₂ + bᵢₖ·H₂
- Information-theoretically secure (hiding commitments)
- Immune to bias attacks (cryptographically impossible)
- Requires H₂ generation via distributed coin flip

---

## Block-Based Coordination

**Why Not Time-Based?**
- Clock drift causes synchronization issues
- No global time source all operators trust
- Sybil attacks (operators can lie about time)
- NTP dependency adds trust assumptions

**Block-Based Solution**:
```
Monitoring loop:
  1. Poll eth_getBlockByNumber("finalized")
  2. If blockNumber % reshareInterval == 0:
     a. Fetch operator set from blockchain
     b. Execute DKG/Reshare with session = blockNumber
```

**Reshare Intervals**:
- Mainnet: 50 blocks (~10 min)
- Sepolia: 10 blocks (~2 min)
- Anvil: 5 blocks (~5 sec)

**Benefits**:
- Sybil-resistant (blockchain consensus)
- Deterministic (all operators agree on trigger blocks)
- Reorg-safe (uses finalized blocks)
- Auditable (sessions tied to on-chain blocks)

---

## Protocol Flows

### DKG (Three Phases)

```
Phase 1: Share Distribution
  - Each operator generates polynomial fᵢ(z) of degree t-1
  - Compute shares: sᵢⱼ = fᵢ(nodeIDⱼ) for each operator j
  - Compute commitments: Cᵢₖ = aᵢₖ·G₂ (Feldman) or aᵢₖ·G₂ + bᵢₖ·H₂ (Pedersen)
  - Broadcast commitments, send shares P2P

Phase 2: Verification & Acknowledgement
  - Each operator verifies: sᵢⱼ·G₂ = Σ(Cᵢₖ · nodeIDⱼ^k)
  - Send signed acknowledgement to dealer
  - Dealers wait for ALL acknowledgements (prevents equivocation)

Phase 3: Finalization
  - Compute final share: xⱼ = Σ sᵢⱼ
  - Store KeyShareVersion(version = blockNumber)
```

### Reshare (Master Secret Preservation)

**Critical Property**: f'ᵢ(0) = currentShare (preserves master secret)

```
Existing operators:
  - Generate f'ᵢ(z) where f'ᵢ(0) = current share
  - Send shares to ALL operators (existing + new)

All operators:
  - Receive shares from existing operators only
  - Compute new share via Lagrange: x'ⱼ = Σ(λᵢ · s'ᵢⱼ)
  - Store new version, mark old inactive

Result: S' = S (master secret unchanged), but shares renewed
```

### Application Mnemonic Derivation

```
TEE requests mnemonic:
  1. Generate TDX attestation + ephemeral RSA keypair
  2. Request partial signatures from ⌈2n/3⌉ operators
  3. Each operator:
     - Verifies attestation (Intel API)
     - Validates image digest (blockchain)
     - Returns σᵢ = H(appID)^(xᵢ) encrypted with ephemeral RSA key
  4. TEE decrypts partial signatures
  5. Recovers: sk_app = Σ(λᵢ · σᵢ)
  6. Derives: mnemonic = DeriveKey(sk_app)
```

---

## Security Model

### Threat Model

**Adversary Capabilities**:
- Control ≤⌊n/3⌋ operators
- Network-level attacks (delay, drop, reorder)
- Unbounded computation (for Feldman analysis)

**Trust Assumptions**:
- Honest majority: ≥⌈2n/3⌉ operators
- Permissioned operators (AVS-approved)
- Ethereum security (source of truth)
- Intel TDX attestation integrity

### Key Security Properties

1. **Threshold Secrecy**: <t operators learn nothing about master secret (information-theoretic)
2. **Hiding** (Pedersen): Commitments reveal zero information during DKG commitment phase
3. **Verifiability**: All protocol violations cryptographically detectable
4. **Byzantine Fault Tolerance**: Tolerates ≤⌊n/3⌋ malicious operators
5. **Economic Security**: Fraud proofs trigger automatic slashing via EigenLayer
6. **Forward Secrecy**: Reshare invalidates old shares (new shares cryptographically independent)

---

## Fraud Detection & Slashing

### Detectable Violations

| Violation | Detection | Slashing Threshold | Penalty |
|-----------|-----------|-------------------|---------|
| Invalid Share | s·G₂ ≠ Σ(Cₖ·xᵏ) | 3 independent reports | 0.1 ETH (escalating) |
| Equivocation | Different shares to different operators | 1 cryptographic proof | 1 ETH + ejection |
| Commitment Inconsistency | Different broadcasts | 1 proof | 0.5 ETH |
| Non-Participation | Missing 5+ reshares | 5 misses | 0.05 ETH/miss |

### Fraud Proof Mechanism

```
Operator detects violation → Construct cryptographic proof → Submit to contract
                                                                    ↓
                                                  Verify on-chain (BLS12-381)
                                                                    ↓
                                                  Slash via AllocationManager
```

**Properties**:
- On-chain verification (no trusted adjudicator)
- Cryptographic proofs (impossible to forge)
- Economic deterrence (cost >> gain)
- Self-healing network (automatic ejection)

---

## Key System Components

### KeyBackend Interface (Pluggable Key Management)

```
interface KeyBackend {
    SignMessage(hash []byte) → (signature []byte, error)
    EncryptShare(share *fr.Element) → (ciphertext []byte, error)
    DecryptShare(ciphertext []byte) → (*fr.Element, error)
}
```

**Implementations**:
- **Phase 1**: Local file-based + AWS KMS
- **Phase 2+**: GCP KMS, Azure Key Vault, HashiCorp Vault, HSMs

### KeyShareVersion (Block-Based Versioning)

```go
type KeyShareVersion struct {
    Version        uint64       // Block number when DKG/reshare occurred
    PrivateShare   *fr.Element  // This operator's secret share
    Commitments    []G2Point    // Public commitments (verifiable)
    IsActive       bool         // Currently active version
    ParticipantIDs []int        // Operator node IDs in this version
}
```

**Version Lookup**: `GetKeyVersionAtBlock(attestationBlock)` finds appropriate version for TEE attestation

### Persistence (BadgerDB)

- Encrypted at rest (AES-256-GCM, operator-derived key)
- Atomic writes (ACID guarantees)
- Crash recovery (consistent state restoration)
- Configurable retention (default: 30 days for attestation validation)

---

## HTTP API Contracts

### Protocol APIs (Authenticated - Inter-Operator)

All messages wrapped in `AuthenticatedMessage` with BN254 signatures:

```
POST /dkg/commitment      - Broadcast polynomial commitments
POST /dkg/share           - Send secret shares P2P
POST /dkg/ack             - Acknowledge receipt and verification
POST /reshare/commitment  - Reshare commitments
POST /reshare/share       - Reshare shares
POST /reshare/ack         - Reshare acknowledgements
```

### Application APIs (Public)

```
GET /pubkey               - Get master public key commitments
POST /app/sign            - Request partial signature (generic apps)
POST /secrets             - TEE secret delivery (attestation-verified)
GET /health               - Health check
GET /metrics              - Prometheus metrics
```

---

## TEE Integration (EigenX Platform)

### Attestation Verification Flow

```
TEE → KMS Operator:
  1. TEE generates Intel TDX quote (proves hardware + code)
  2. KMS calls Intel Trust Authority API to verify quote
  3. KMS extracts RTMR0 (code measurement) from quote
  4. KMS queries blockchain for expected imageDigest
  5. KMS verifies: RTMR0 == keccak256(imageDigest)
  6. If valid: Generate partial signature, encrypt with ephemeral RSA, return
```

**Security Guarantees**:
- Only approved Docker images (by digest) receive keys
- Attestation chain: Intel CPU → Google Cloud → KMS → Blockchain
- Hardware isolation (TEE memory encrypted by Intel TDX)
- Ephemeral encryption (RSA keys used once, discarded)

---

## Monitoring & Observability

### Key Metrics (Prometheus)

**Protocol Health**:
- `kms_reshare_executions_total{status}` - Reshare success/failure rate
- `kms_active_key_version` - Current key version (block number)
- `kms_last_successful_reshare_block` - Last successful reshare

**Security**:
- `kms_fraud_detected_total{fraud_type}` - Fraud detections
- `kms_operators_slashed_total{reason}` - Slashing events
- `kms_p2p_signature_verification_failures_total` - Auth failures

**Application**:
- `kms_app_sign_requests_total{app_id, status}` - Signature requests
- `kms_tee_secrets_requests_total{app_id, status}` - TEE secret requests
- `kms_tee_image_digest_matches_total{match}` - Image validation

### OpenTelemetry Tracing

Distributed traces for protocol execution with trace context propagated in all messages:
- DKG/Reshare execution (100% sampled)
- Application requests (10% sampled)
- Spans include: session_block, operator_address, key_version

### Critical Alerts

- Consecutive reshare failures (3+ in 30 min)
- Insufficient operators (< threshold + 1)
- Fraud detected
- Blockchain RPC errors (>50% rate)
- Missed reshare intervals

---

## Implementation Timeline

### Phase 1: Alpha Testnet (Nov 7, 2024)
- Block-based scheduling (finalized block polling)
- Feldman-VSS with basic fraud detection
- BadgerDB persistence (encrypted)
- AWS KMS backend + local keys
- Deploy to Sepolia (3-5 operators)

### Phase 2: Mainnet Beta (Dec 12, 2024)
- Pedersen-VSS (information-theoretic security)
- Enhanced fraud proofs (all violation types)
- Additional key backends (GCP, Azure, Vault)
- Integration test suite (>90% coverage)
- Begin external security audit

### Phase 3: Production Launch (Q1 2025)
- Audit completion (address findings)
- Mainnet deployment (10-15 operators)
- Genesis DKG ceremony
- 48-hour monitoring (24/7 on-call)

### Phase 4: Advanced Features (Q1-Q2 2025)
- HSM backend support
- Cross-chain deployment
- Operator reputation system
- Governance mechanisms

---

## Key Design Decisions

### 1. Pedersen-VSS for Production
**Why**: Information-theoretic hiding prevents bias attacks
**Trade-off**: More complex than Feldman (dual polynomials, H₂ generation)
**Migration**: Alpha with Feldman → Production with Pedersen

### 2. Block-Based Scheduling
**Why**: Sybil-resistant, deterministic, no clock drift
**Trade-off**: Depends on finalized blocks (~13 min lag on mainnet)
**Benefit**: Eliminates NTP and time synchronization attacks

### 3. Fraud Proofs + Economic Slashing
**Why**: Detection + punishment for protocol violations
**Trade-off**: Requires on-chain BLS12-381 verification (gas costs)
**Benefit**: Self-healing network, trustless enforcement

### 4. AWS KMS for Operator Keys (Phase 1)
**Why**: Secure key management without manual key handling
**Trade-off**: AWS dependency for signing operations
**Migration**: Interface-based design supports GCP/Azure/Vault/HSM later

### 5. Go + gnark-crypto
**Why**: Team expertise, audited crypto library, Hourglass/Sidecar code reuse
**Trade-off**: Manual threshold protocol implementation
**Benefit**: 2-3x faster development than Rust learning curve

---

## Security Guarantees

### 1. Threshold Secrecy
No coalition of <t operators can learn master secret (information-theoretic with Pedersen)

### 2. Code Integrity
Only blockchain-approved Docker images receive keys (RTMR0 verification)

### 3. Hardware Isolation
Intel TDX encrypts TEE memory (cloud providers cannot access)

### 4. Deterministic Identity
Same appID → same mnemonic → same wallet addresses (threshold-derived)

### 5. Byzantine Fault Tolerance
System operates with ≤⌊n/3⌋ malicious operators

### 6. Economic Security
Fraud proofs enable automatic slashing (cost >> gain for attacks)

---

## Critical Attack Scenarios

### Bias Attack (Feldman-VSS)
- **Attack**: Adversary computes key distribution from commitments, selectively disqualifies operators
- **Alpha Defense**: Economic slashing + permissioned operators
- **Production Defense**: Pedersen-VSS makes cryptographically impossible

### Equivocation
- **Attack**: Send different shares to different operators
- **Defense**: Acknowledgement system + fraud proofs → automatic slashing

### Compromised Shares (≤⌊n/3⌋)
- **Attack**: Steal operator key shares
- **Defense**: Threshold security (insufficient for reconstruction) + automatic reshare

### Application Key Spoofing
- **Attack**: Request partial signatures for victim's appID
- **Defense**: TEE attestation (EigenX platform enforces)

---

## Open Questions / Future Considerations

1. **Master Secret Rotation**: Should we rotate S itself (requires full DKG, breaks backward compatibility)?
2. **Stake Weighting**: Should threshold be stake-weighted vs 1-operator-1-vote?
3. **Cross-Chain Sync**: How to maintain consistent key versions across multiple chains?
4. **Light Client in TEE**: Should TEEs verify blockchain data directly (removes RPC trust)?
5. **Proactive Reshare**: Reshare on every block vs interval (trade-off: security vs cost)?

---

## References

- **Full TDD**: `docs/distributed-kms-tdd.md` (3,500+ lines, comprehensive)
- **Fraud Proofs**: `docs/003_fraudProofs.md` (smart contract spec)
- **Gennaro et al. Paper**: `docs/references/Secure Distributed Key Generation...` (Pedersen-VSS formal proof)
- **EigenX Architecture**: https://github.com/Layr-Labs/eigenx-cli/blob/main/docs/EIGENX_ARCHITECTURE.md

---

## Conclusion

The distributed KMS eliminates the centralized trust assumption while maintaining identical developer experience. By combining Pedersen-VSS (information-theoretic security), block-based coordination (Sybil-resistant), and fraud proofs (economic security), the system achieves production-grade decentralized key management suitable for high-value TEE applications.

**Timeline**: Alpha testnet (Nov 7) → Mainnet beta + audit (Dec 12) → Production (Q1 2025)
