# TDD: Distributed KMS

## Summary

EigenX KMS AVS is a production-grade distributed key management system running as an EigenLayer Active Validated Service (AVS). It serves as the **trust layer** for the EigenX compute platform, which enables developers to deploy verifiable applications in Trusted Execution Environments (TEEs). The KMS provides threshold cryptography-based secret management, combining BLS12-381 threshold signatures with Identity-Based Encryption (IBE) to ensure secure, decentralized access to application secrets and deterministic wallet generation.

The system leverages EigenLayer's restaking infrastructure to create a Byzantine fault-tolerant network of operators who collectively manage cryptographic keys without any single point of failure. Through distributed key generation (DKG) and automatic key resharing, the system ensures that no individual operator ever possesses sufficient information to compromise application secrets, while maintaining ⌈2n/3⌉ availability for legitimate applications.

**EigenX Platform Context**: The KMS operates as the gatekeeper between trusted hardware (Intel TDX TEEs) and application deployment, verifying TEE attestations, validating Docker image digests against blockchain records, and providing deterministic keys to authenticated TEE instances. This enables applications running in hardware-isolated environments to receive cryptographic identities (wallet mnemonics) and secrets that persist across deployments while remaining inaccessible to host operating systems or cloud providers.

### Goals

**Primary Goals:**

1. **Distributed Key Management**: Provide a decentralized key management system where no single operator can compromise application secrets, requiring ⌈2n/3⌉ threshold collaboration for any cryptographic operation.

2. **Byzantine Fault Tolerance**: Maintain security and liveness guarantees even with up to ⌊n/3⌋ Byzantine (malicious or faulty) operators, ensuring system resilience against adversarial behavior.

3. **Cryptographically Secure DKG**: Implement Pedersen Verifiable Secret Sharing (VSS) for distributed key generation, providing information-theoretic hiding of secret shares during the commitment phase. This prevents adversarial bias attacks on key distribution that are possible with simpler schemes.
   - **Alpha Testnet**: Deploy with Feldman-VSS (computationally secure) for rapid iteration
   - **Production**: Upgrade to Pedersen-VSS (information-theoretically secure) before mainnet and security audits

4. **EigenLayer Integration**: Operate as a native EigenLayer AVS, leveraging restaked ETH security and operator infrastructure for economic alignment and slashing guarantees.

5. **TEE Compute Platform Support**: Serve as the trust layer for EigenX's TEE-based compute platform by:
   - Verifying Intel TDX attestations from TEE instances using Intel's attestation verification APIs
   - Validating Docker image digests against blockchain-stored configurations
   - Providing deterministic wallet mnemonics via threshold-based key derivation
   - Delivering application secrets to authenticated TEE instances
   - Ensuring cryptographic identity persistence across deployments

6. **Identity-Based Encryption**: Enable application developers to encrypt secrets using simple application identifiers (app IDs) without complex key management infrastructure.

7. **Automatic Key Rotation**: Implement periodic, transparent key resharing to enhance forward secrecy and mitigate long-term key exposure risks.

8. **Fraud Detection and Slashing**: Implement on-chain fraud proof system enabling operators to submit cryptographic evidence of protocol violations, triggering automatic slashing of malicious operators through EigenLayer's slashing mechanism.

9. **Authenticated Communication**: Ensure all inter-operator messages are cryptographically authenticated using BN254 signatures, preventing impersonation and message tampering.

10. **Developer-Friendly API**: Offer simple HTTP-based APIs and CLI tools for application integration, abstracting complex threshold cryptography from developers.

**Secondary Goals:**

- Support dynamic operator sets with join/leave capabilities
- Maintain historical key versions for time-based attestation validation
- Provide operational visibility through metrics and monitoring
- Enable cross-chain deployment (Ethereum mainnet, Sepolia testnet, local Anvil)

### Non-Goals

**Out of Scope:**

1. **General-Purpose HSM Replacement**: This system is designed specifically for application secret management in EigenLayer AVS contexts, not as a replacement for hardware security modules or general key management services.

2. **Non-EigenLayer Deployments**: The system is tightly coupled with EigenLayer's operator registry, restaking economics, and slashing mechanisms. Standalone deployment outside EigenLayer is not supported.

3. **Alternative Signature Schemes**: The system is optimized for BLS12-381 threshold signatures. Support for other schemes (RSA, ECDSA, EdDSA) is not planned.

4. **Consensus-Based Protocols**: The system uses interval-based scheduling and threshold cryptography rather than traditional consensus mechanisms (Raft, PBFT). Full Byzantine agreement protocols are not required.

5. **Direct Secret Storage**: The system manages cryptographic keys for encryption/decryption, not raw secret storage. Applications must handle their own encrypted data persistence.

6. **Key Recovery/Backup**: Individual key shares are not designed for recovery. If ⌈2n/3⌉ operators become permanently unavailable, key material cannot be recovered (by design for security).

7. **Real-Time Performance**: The system prioritizes security and correctness over ultra-low latency. Applications requiring sub-millisecond cryptographic operations should consider alternative architectures.

## EigenX Platform Architecture

Before diving into the KMS-specific architecture, it's important to understand how the KMS fits into the broader EigenX compute platform ecosystem.

### System Layers

EigenX is structured as a multi-layer platform where the KMS serves as the critical trust layer:

```
┌──────────────────────────────────────────────────────────────────┐
│                      Developer Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│  │ EigenX CLI   │  │ Docker Image │  │ App Config   │            │
│  │ (Build/Deploy│  │ Registry     │  │ (Secrets)    │            │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘            │ 
│         │                 │                  │                   │
└─────────┼─────────────────┼──────────────────┼───────────────────┘
          │                 │                  │
┌─────────▼─────────────────▼──────────────────▼────────────────────┐
│                       Trust Layer (Blockchain)                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  EigenX Smart Contracts (Ethereum)                         │  │
│  │  - App Registry: Stores authorized Docker image digests   │  │
│  │  - App Configuration: Stores encrypted secrets, state     │  │
│  │  - Access Control: Defines who can deploy/manage apps     │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  KMS AVS (This System)                                     │  │
│  │  - TEE Attestation Verification                            │  │
│  │  - Image Digest Validation (queries blockchain)           │  │
│  │  - Deterministic Mnemonic Generation: HMAC(master, appID) │  │
│  │  - Secret Delivery to Authenticated TEEs                  │  │
│  └────────────────────────────────────────────────────────────┘  │
└───────────────────────────┬───────────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────────┐
│                    Automation Layer                               │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │  EigenX Coordinator                                        │   │
│  │  - Watches blockchain for deployment events                │   │
│  │  - Provisions Google Cloud VMs with Intel TDX              │   │
│  │  - Manages application lifecycle (start/stop/upgrade)      │   │
│  │  - Monitors TEE instance health                            │   │
│  └────────────────────────────────────────────────────────────┘   │
└───────────────────────────┬───────────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────────┐
│                     Execution Layer                               │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  TEE Instance (Intel TDX on Google Cloud)                  │  │
│  │                                                             │  │
│  │  ┌────────────────────────────────────────────────────┐    │  │
│  │  │ Hardware-Isolated VM (Memory Encrypted)            │    │  │
│  │  │                                                     │    │  │
│  │  │  ┌───────────────────────────────────────────┐     │    │  │
│  │  │  │ Docker Container (Application Code)       │     │    │  │
│  │  │  │                                            │     │    │  │
│  │  │  │  Environment Variables:                    │     │    │  │
│  │  │  │  - MNEMONIC="word1 word2 ... word12"      │     │    │  │
│  │  │  │  - DB_PASSWORD="..." (from developer)     │     │    │  │
│  │  │  │  - API_KEY="..." (from developer)         │     │    │  │
│  │  │  │                                            │     │    │  │
│  │  │  │  Application derives wallets from mnemonic│     │    │  │
│  │  │  │  - Ethereum: m/44'/60'/0'/0/0             │     │    │  │
│  │  │  │  - Bitcoin: m/44'/0'/0'/0/0               │     │    │  │
│  │  │  │  - Signs transactions autonomously        │     │    │  │
│  │  │  └───────────────────────────────────────────┘     │    │  │
│  │  │                                                     │    │  │
│  │  │  Host OS CANNOT access memory (Intel TDX)          │    │  │
│  │  └────────────────────────────────────────────────────┘    │  │
│  └────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

### Application Deployment Flow

The complete flow from developer deployment to running TEE application:

```
Developer                Blockchain         Coordinator          KMS AVS           TEE Instance
    │                        │                  │                  │                    │
    │ 1. Build Docker image  │                  │                  │                    │
    ├───────────────────────→│                  │                  │                    │
    │                        │                  │                  │                    │
    │ 2. Deploy app          │                  │                  │                    │
    │    (image digest,      │                  │                  │                    │
    │     encrypted secrets) │                  │                  │                    │
    ├───────────────────────→│                  │                  │                    │
    │                        │                  │                  │                    │
    │                        │ 3. Event: AppDeployed               │                    │
    │                        ├─────────────────→│                  │                    │
    │                        │                  │                  │                    │
    │                        │                  │ 4. Provision VM  │                    │
    │                        │                  │    (Intel TDX)   │                    │
    │                        │                  ├─────────────────────────────────────→│
    │                        │                  │                  │                    │
    │                        │                  │                  │ 5. Generate        │
    │                        │                  │                  │    attestation JWT │
    │                        │                  │                  │    (proves config) │
    │                        │                  │                  │◄───────────────────│
    │                        │                  │                  │                    │
    │                        │                  │ 6. Request secrets with attestation   │
    │                        │                  │                  │◄───────────────────│
    │                        │                  │                  │                    │
    │                        │ 7. Query image digest for appID     │                    │
    │                        │◄─────────────────────────────────────│                    │
    │                        │                  │                  │                    │
    │                        │ 8. Return digest │                  │                    │
    │                        ├─────────────────────────────────────→│                    │
    │                        │                  │                  │                    │
    │                        │                  │ 9. Verify:       │                    │
    │                        │                  │    - Attestation │                    │
    │                        │                  │    - Image digest│                    │
    │                        │                  │    - RTMR values │                    │
    │                        │                  │                  │                    │
    │                        │                  │ 10. Generate deterministic mnemonic   │
    │                        │                  │     mnemonic = HMAC(master, appID)    │
    │                        │                  │                  │                    │
    │                        │                  │ 11. Decrypt developer secrets         │
    │                        │                  │     (from blockchain)                 │
    │                        │                  │                  │                    │
    │                        │                  │ 12. Return encrypted response         │
    │                        │                  │                  ├───────────────────→│
    │                        │                  │                  │                    │
    │                        │                  │                  │ 13. Decrypt,       │
    │                        │                  │                  │     inject env vars│
    │                        │                  │                  │                    │
    │                        │                  │                  │ 14. Start app      │
    │                        │                  │                  │     container      │
    │                        │                  │                  │                    │
    │                        │                  │                  │ 15. App accesses   │
    │                        │                  │                  │     MNEMONIC       │
    │                        │                  │                  │     env variable   │
    │                        │                  │                  │                    │
    │                        │                  │                  │ 16. Derive wallets │
    │                        │                  │                  │     Sign txs       │
```

### Key System Guarantees

**1. Code Integrity**

Only exact Docker images (by digest) stored on blockchain can receive cryptographic keys from the KMS.

**Enforcement Mechanism:**
- Application registry smart contract stores authorized `imageDigest` for each application
- KMS operators query blockchain to retrieve expected digest before key release
- TEE generates attestation quote containing RTMR0 (measurement of running code)
- KMS verifies `attestation.RTMR0 == keccak256(imageDigest)` before proceeding
- Verification failure results in key denial and alert

**Security Properties:**
- Prevents unauthorized code from obtaining application keys
- Creates immutable audit trail of approved code versions
- Enables rollback protection (old vulnerable versions can be revoked on-chain)

---

**2. Deterministic Identity**

Applications receive consistent cryptographic identities (wallet mnemonics) across all deployments, enabling persistent blockchain addresses and fund management.

**Mechanism:**
```
mnemonic = DeriveKey(masterSecret, appID)

Where:
  - masterSecret: Distributed among KMS operators via threshold DKG
  - appID: Unique identifier from application registry
  - DeriveKey: Threshold-based derivation requiring ⌈2n/3⌉ operators
```

**Security Properties:**
- Same appID → Same mnemonic → Same wallet addresses (deterministic)
- Different appIDs → Cryptographically independent mnemonics (isolated)
- No single operator can compute mnemonics (threshold-protected)
- Master secret never reconstructed in any location (remains distributed)

---

**3. Hardware Isolation**

Application keys and secrets remain isolated within Intel TDX trusted execution environments, inaccessible to cloud providers, host operating systems, or other tenants.

**Enforcement Mechanism:**
- Intel TDX encrypts TEE memory using hardware-based encryption keys
- Memory encryption keys derived from CPU hardware secrets
- DMA protection prevents direct memory access from peripherals
- Attestation proves code runs within hardware-protected enclave

**Security Properties:**
- Cloud provider administrators cannot access TEE memory (hardware-enforced)
- Host OS cannot read or modify TEE state (architectural isolation)
- Keys never persisted to disk in plaintext (ephemeral or encrypted)
- Side-channel protections via Intel TDX microarchitecture

---

**4. Attestation Chain of Trust**

End-to-end cryptographic verification chain from hardware to blockchain ensures only authentic, authorized code receives keys.

**Trust Chain:**
```
Intel CPU → TEE Instance → KMS Operators → Blockchain Registry → Application
   ↓            ↓              ↓              ↓                      ↓
 HW Root    Attestation   Threshold       Authority           Key Delivery
  of Trust    Quote      Verification    Verification
```

**Verification Steps:**
1. **Hardware Authenticity**: TEE attestation signed by Intel CPU using hardware-fused keys
2. **Platform Identity**: Google Cloud platform certificate validates infrastructure
3. **Code Measurement**: RTMR0 contains hash of loaded application code
4. **Configuration State**: RTMR1 contains runtime configuration measurements
5. **Blockchain Authority**: Smart contract confirms application deployment authorization
6. **Freshness**: Attestation timestamp prevents replay attacks

**Security Properties:**
- Cryptographic proof chain from silicon to software
- No trusted intermediaries (hardware + blockchain as roots of trust)
- Tamper-evident (any modification breaks attestation signature)
- Replay-resistant (nonces and timestamps in attestation quotes)

---

**5. Threshold Security**

Master secret distributed among KMS operators such that no coalition of ≤⌊n/3⌋ operators can compromise system security.

**Mechanism:**
- DKG protocol generates master secret as `S = Σ f_i(0)` where each operator contributes random `f_i(0)`
- Each operator holds share `x_j = Σ f_i(j)` enabling threshold reconstruction
- Threshold t = ⌈2n/3⌉ operators required for any cryptographic operation
- Pedersen-VSS ensures information-theoretic hiding during commitment phase

**Security Properties:**
- No single point of failure (any ⌈2n/3⌉ operators can continue operations)
- Byzantine fault tolerance (up to ⌊n/3⌋ malicious operators tolerated)
- Information-theoretic secrecy (shares reveal zero information about master secret)
- Forward secrecy via periodic resharing (old shares become useless)

---

**6. Fraud Detection and Economic Security**

On-chain fraud proof system enables cryptographic detection of protocol violations, triggering automatic slashing of malicious operators.

**Enforcement Mechanism:**
- Operators monitor protocol execution for violations (invalid shares, equivocation)
- Violations proven via cryptographic fraud proofs submitted to slashing contract
- Smart contract verifies proof on-chain (e.g., share verification equation)
- Verified fraud triggers automatic slashing via EigenLayer AllocationManager
- Repeated violations result in operator ejection from AVS

**Detectable Violations:**
- Invalid shares (don't verify against commitments)
- Equivocation (different shares to different operators)
- Commitment inconsistency (different broadcasts to different receivers)
- Protocol deviation (failing to follow DKG/reshare specifications)

**Security Properties:**
- Economic deterrence (fraud costs exceed potential gains)
- Self-healing network (malicious operators automatically removed)
- Transparent accountability (fraud proofs publicly verifiable)
- No trusted adjudicator (smart contract verifies cryptographic proofs)

### Current Architecture vs. Distributed KMS

**Current (Centralized KMS)**:
- Single KMS operator controls all key release decisions
- Single point of failure and trust
- Operator can withhold keys or provide keys to wrong parties
- No Byzantine fault tolerance

**This Design (Distributed KMS AVS)**:
- ⌈2n/3⌉ operators required for key operations
- Byzantine fault tolerant (up to ⌊n/3⌋ malicious operators)
- Economic security via EigenLayer restaking
- Automatic key rotation via resharing
- No single operator can compromise applications

**Migration Path**: This distributed KMS design replaces the centralized KMS while maintaining the same external API, enabling seamless transition for existing EigenX applications.

### Application Developer Perspective

**Important**: The transition from centralized to distributed KMS is **completely transparent** to application developers. The developer experience remains identical to the current status quo.

From an application developer's perspective using EigenX:

```go
// Inside TEE container (developers write this code)
// This code works identically with centralized or distributed KMS
package main

import (
    "os"
    "github.com/tyler-smith/go-bip39"
    "github.com/tyler-smith/go-bip32"
)

func main() {
    // KMS injects this via environment variable
    // (Same interface whether centralized or distributed KMS)
    mnemonic := os.Getenv("MNEMONIC")

    // Generate wallet seed from mnemonic
    seed := bip39.NewSeed(mnemonic, "")

    // Derive Ethereum wallet (BIP-44: m/44'/60'/0'/0/0)
    masterKey, _ := bip32.NewMasterKey(seed)
    ethPurpose, _ := masterKey.NewChildKey(44 + bip32.FirstHardenedChild)
    ethCoinType, _ := ethPurpose.NewChildKey(60 + bip32.FirstHardenedChild)
    ethAccount, _ := ethCoinType.NewChildKey(0 + bip32.FirstHardenedChild)
    ethChange, _ := ethAccount.NewChildKey(0)
    ethAddress, _ := ethChange.NewChildKey(0)

    // Use private key to sign transactions
    privateKey := ethAddress.Key

    // Application has deterministic identity across deployments
    // Same mnemonic → Same addresses → Can receive funds persistently
}
```

**Developer Benefits**:
1. **No code changes required** (migration is transparent)
2. No key management code required
3. Deterministic identity (can publish addresses, receive funds)
4. Hardware isolation (keys never leave TEE)
5. Automatic secret injection (database passwords, API keys)
6. Multi-chain support (derive keys for any BIP-44 chain)

**What Changes Under the Hood**:
- **Before**: Single KMS operator provides mnemonic (trusted party)
- **After**: ⌈2n/3⌉ operators collectively generate mnemonic (trustless)
- **Developer Impact**: None - same `MNEMONIC` environment variable, same deterministic value

## Architecture Overview

### System Components

The EigenX KMS AVS is built on a modular architecture with clear separation of concerns:

```
┌──────────────────────────────────────────────────────────────────┐
│                        Application Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │ KMS Client   │  │ TEE Runtime  │  │ Web3 App     │           │
│  │ CLI Tool     │  │ (TDX/SGX)    │  │ Integration  │           │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
│         │                 │                  │                    │
│         └─────────────────┴──────────────────┘                    │
│                           │                                       │
│                  HTTP API (Public Endpoints)                      │
└───────────────────────────┼───────────────────────────────────────┘
                            │
┌───────────────────────────┼───────────────────────────────────────┐
│                    KMS Node (Operator)                            │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                  HTTP Server (pkg/node)                    │  │
│  │  ┌──────────────────┐  ┌──────────────────────────────┐   │  │
│  │  │ Protocol APIs    │  │ Application APIs             │   │  │
│  │  │ /dkg/*           │  │ /pubkey, /app/sign, /secrets │   │  │
│  │  └──────────────────┘  └──────────────────────────────┘   │  │
│  └───────────┬──────────────────────────┬─────────────────────┘  │
│              │                          │                         │
│  ┌───────────▼───────────┐  ┌──────────▼──────────────┐          │
│  │ Protocol Engines      │  │ Application Handler     │          │
│  │ - DKG (pkg/dkg)       │  │ - Pubkey aggregation    │          │
│  │ - Reshare             │  │ - Partial signing       │          │
│  │   (pkg/reshare)       │  │ - TEE verification      │          │
│  └───────────┬───────────┘  └─────────────────────────┘          │
│              │                                                     │
│  ┌───────────▼─────────────────────────────────────┐             │
│  │         Transport Layer (pkg/transport)         │             │
│  │  - Message signing/verification (BN254)         │             │
│  │  - Authenticated message wrapping               │             │
│  │  - HTTP client with retry logic                 │             │
│  └───────────┬─────────────────────────────────────┘             │
│              │                                                     │
│  ┌───────────▼─────────────────────────────────────┐             │
│  │    Cryptographic Operations (pkg/crypto)        │             │
│  │  - BLS12-381: threshold sigs, DKG (pkg/bls)     │             │
│  │  - BN254: message authentication                │             │
│  │  - IBE: encryption/decryption                   │             │
│  │  - Share verification & Lagrange interpolation  │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                    │
│  ┌─────────────────────────────────────────────────┐             │
│  │      Key Management (pkg/keystore)              │             │
│  │  - Versioned key share storage                  │             │
│  │  - Active/historical version tracking           │             │
│  │  - Time-based key lookup                        │             │
│  └─────────────────────────────────────────────────┘             │
│                                                                    │
│  ┌─────────────────────────────────────────────────┐             │
│  │    Peering System (pkg/peering)                 │             │
│  │  - Operator discovery from blockchain           │             │
│  │  - Socket address resolution                    │             │
│  │  - BN254 public key retrieval                   │             │
│  └───────────┬─────────────────────────────────────┘             │
│              │                                                     │
└──────────────┼─────────────────────────────────────────────────────┘
               │
┌──────────────▼─────────────────────────────────────────────────────┐
│                    EigenLayer Protocol                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│  │ AVSDirectory │  │ Operator Set │  │ Key Registrar│            │
│  │              │  │ Registrar    │  │ (BN254)      │            │
│  └──────────────┘  └──────────────┘  └──────────────┘            │
└────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities and API Contracts

#### KMS Node Server

**Responsibility**: Manages protocol lifecycle and exposes HTTP APIs for inter-operator communication and application requests.

**Public API Contract**:
- Protocol endpoints (authenticated): `/dkg/*`, `/reshare/*`
- Application endpoints (public): `/pubkey`, `/app/sign`, `/secrets`
- Health monitoring: `/health`, `/metrics`

**Key Behaviors**:
- Automatic protocol scheduling at interval boundaries (configurable per chain)
- Session management for concurrent DKG/reshare runs (isolated by timestamp)
- Request authentication via BN254 signature verification against peering data
- Graceful degradation when subset of operators unavailable

**Security Boundaries**:
- All inter-operator messages must carry valid BN254 signatures
- Application endpoints rate-limited to prevent DoS
- TEE attestation verification required for `/secrets` endpoint

---

#### Protocol Engines (DKG/Reshare)

**Responsibility**: Execute distributed cryptographic protocols for key generation and rotation.

**Interface Contract**:
```
GenerateShares() → (shares, commitments, error)
VerifyShare(dealerNodeID, share, commitments) → bool
FinalizeKeyShare(receivedShares, allCommitments, participants) → KeyShareVersion
```

**Key Behaviors**:
- **Alpha**: Feldman-VSS with single polynomial (fast iteration)
- **Production**: Pedersen-VSS with dual polynomials (information-theoretic hiding)
- Three-phase execution: commitment, verification, finalization
- Acknowledgement system prevents dealer equivocation
- Automatic fraud detection and reporting

**Security Properties**:
- Share verification ensures polynomial consistency
- Threshold t = ⌈2n/3⌉ for Byzantine fault tolerance
- No single operator learns master secret
- Forward secrecy via periodic resharing

---

#### Authenticated Transport Layer

**Responsibility**: Provides authenticated, reliable message delivery between operators with cryptographic proof of sender identity.

**Message Contract**:
```
AuthenticatedMessage {
    payload: []byte           // Serialized protocol message
    hash: [32]byte           // keccak256(payload)
    signature: []byte        // BN254_sign(hash, operatorPrivateKey)
}

Payload contains:
    fromOperatorAddress: Ethereum address
    toOperatorAddress: Ethereum address (0x0 for broadcast)
    sessionTimestamp: int64
    messageData: protocol-specific content
```

**Key Behaviors**:
- Automatic message signing on send
- Signature verification on receive using peering system
- Retry with exponential backoff (max 3 attempts)
- Broadcast support via zero-address routing
- Message routing to correct session by timestamp

**Security Properties**:
- Prevents impersonation (signature verification)
- Prevents replay attacks (session timestamp binding)
- Detects tampering (hash verification)
- Ensures message authenticity (BN254 cryptographic proofs)

---

#### Cryptographic Operations

**Responsibility**: Provides primitive cryptographic operations for threshold protocols, ensuring correct implementation of BLS12-381 and BN254 operations.

**Operation Contract**:
```
BLS12-381 Operations:
- EvaluatePolynomial(poly, x) → share
- ComputeCommitments(poly) → []G2Point
- VerifyShare(share, nodeID, commitments) → bool
- ComputeLagrangeCoefficient(nodeID, participants) → coefficient
- RecoverSecret(shares, participants) → secret

BN254 Operations:
- SignMessage(payload, privateKey) → signature
- VerifySignature(payload, signature, publicKey) → bool

IBE Operations:
- HashToG1(appID) → G1Point
- GeneratePartialSignature(appID, keyShare) → G1Point
- RecoverAppPrivateKey(partialSigs, participants) → G1Point
```

**Key Behaviors**:
- Constant-time operations where cryptographically relevant
- Comprehensive input validation
- Deterministic outputs for reproducibility
- Error propagation with context

**Security Properties**:
- Implementation follows gnark-crypto (audited library)
- Scalar operations in correct field (Fr for BLS12-381)
- Point validation on deserialization
- No timing side-channels in critical paths

---

#### Key Store

**Responsibility**: Manages versioned key share storage with time-based lookups, supporting historical key versions for attestation validation.

**Storage Interface**:
```
StoreKeyShareVersion(version KeyShareVersion) → error
GetActiveKeyShare() → KeyShareVersion
GetKeyVersionAtTime(timestamp int64) → KeyShareVersion
ListVersions() → []int64
```

**Data Model**:
```
KeyShareVersion {
    version: int64              // Session timestamp (epoch)
    privateShare: *fr.Element   // Threshold share
    commitments: []G2Point      // Public commitments
    isActive: bool              // Current version flag
    participantIDs: []int       // Operator node IDs
}
```

**Key Behaviors**:
- Epoch-based versioning using session timestamps
- Automatic activation of new versions (marks previous inactive)
- Historical lookups for TEE attestation time validation
- Thread-safe concurrent access

**Security Properties**:
- Shares encrypted at rest (production requirement)
- Version immutability (once stored, never modified)
- Atomic updates (no partial state visible)
- Configurable retention period

---

#### Peering System

**Responsibility**: Discovers and validates operator set membership, providing BN254 public keys for message authentication.

**Interface Contract**:
```
GetOperators() → []OperatorSetPeer

OperatorSetPeer {
    operatorAddress: Ethereum address
    socketAddress: HTTP endpoint URL
    wrappedPublicKey: BN254 public key
    curveType: "BN254"
}
```

**Key Behaviors**:
- Queries blockchain for current operator set at each interval
- Caches operator data with TTL (avoid excessive RPC calls)
- Validates operator registrations via smart contract state
- Detects operator churn (joins/leaves)

**Security Properties**:
- Public keys fetched from trusted source (blockchain)
- Operator set immutable within session (timestamp-locked)
- Address-to-nodeID derivation deterministic and collision-resistant

### Identity Model

The system uses an **address-based identity model** where:

1. **Operator Identity**: Each operator is identified by their Ethereum address (not sequential IDs)
2. **Node ID Derivation**: `nodeID = addressToNodeID(keccak256(address))`
   - Provides deterministic, unique node IDs for cryptographic protocols
   - Ensures consistent identity across all protocol runs
3. **Key Pairs**:
   - **BN254 Private Key**: Used for P2P message authentication
   - **BN254 Public Key**: Registered on-chain via EigenLayer KeyRegistrar
   - **BLS12-381 Shares**: Generated during DKG, used for threshold signatures

This model ensures that operator identity is:
- Ethereum-native and on-chain queryable
- Compatible with EigenLayer's operator registry
- Consistent across protocol executions
- Verifiable by all participants

### Data Flow

**DKG/Reshare Protocol Flow:**
```
Block Monitor
    │
    ├─→ Poll for latest finalized block
    │
    ├─→ Check if blockNumber % reshareInterval == 0
    │
    ├─→ If trigger block: Fetch operators from blockchain
    │
    ├─→ Determine protocol: DKG vs Reshare
    │
    └─→ Execute protocol (goroutine, session = blockNumber)
           │
           ├─→ Phase 1: Share distribution
           │   └─→ POST /dkg/share, /dkg/commitment
           │       (messages include SessionBlock field)
           │
           ├─→ Phase 2: Verification & acknowledgement
           │   └─→ POST /dkg/ack
           │
           └─→ Phase 3: Finalization
               └─→ Store KeyShareVersion(version = blockNumber)
```

**Application Encrypt/Decrypt Flow:**
```
Application
    │
    ├─→ Get master public key
    │   └─→ GET /pubkey from each operator
    │       └─→ Aggregate commitments
    │
    ├─→ Encrypt with IBE
    │   └─→ ciphertext = IBE.Encrypt(appID, mpk, plaintext)
    │
    └─→ Decrypt with threshold signatures
        │
        ├─→ Collect partial signatures
        │   └─→ POST /app/sign to each operator
        │       └─→ σ_i = H_1(appID)^(x_i)
        │
        ├─→ Recover app private key
        │   └─→ sk_app = Σ(λ_i * σ_i)  [Lagrange]
        │
        └─→ Decrypt ciphertext
            └─→ plaintext = IBE.Decrypt(sk_app, ciphertext)
```

### Block-Based Protocol Coordination

The system uses **block-based scheduling** to coordinate protocol execution without requiring consensus or trusted time sources. Operators monitor finalized blockchain blocks and trigger DKG/Reshare protocols at deterministic block intervals.

#### Scheduling Mechanism

```
Block monitoring loop:
  1. Poll for latest finalized block from Ethereum RPC
  2. Check if blockNumber % reshareInterval == 0
  3. Skip if already processed this block number
  4. Fetch current operator set from blockchain
  5. Determine protocol type:
     - No local shares + no cluster keys → Genesis DKG
     - No local shares + cluster has keys → Join via Reshare
     - Has local shares → Routine Reshare
  6. Execute protocol in background with session = blockNumber
  7. Mark block number as processed
```

**Reshare Intervals by Chain**:

| Chain          | Chain ID | Reshare Interval | Block Time | Real Time |
|----------------|----------|------------------|------------|-----------|
| Ethereum Mainnet | 1      | 50 blocks        | ~12s       | ~10 min   |
| Sepolia Testnet  | 11155111 | 10 blocks      | ~12s       | ~2 min    |
| Anvil Devnet     | 31337  | 5 blocks         | ~1s        | ~5 sec    |

#### Why Block-Based vs Time-Based Scheduling

**Time-Based Approach (Rejected)**:
```
Problem: Using cron jobs or interval tickers (e.g., every 10 minutes)

Issues:
  1. Clock Drift: Operator clocks drift independently over time
     → Different operators trigger at slightly different times
     → Protocol messages arrive out of sync

  2. No Global Truth: No authoritative time source all operators trust
     → Operators might disagree on "current time"
     → Leads to session confusion and failed protocols

  3. Sybil Attacks: Malicious operator can lie about time
     → Can claim "it's time to reshare" when it's not
     → Other operators cannot verify the claim
```

**Block-Based Approach (Implemented)**:
```
Solution: Use blockchain block numbers as coordination source

Benefits:
  1. Blockchain Consensus: All operators see same block numbers
     → Ethereum consensus guarantees global agreement
     → No clock synchronization required

  2. Authoritative Source: Blockchain is single source of truth
     → Operators query same canonical chain state
     → No ambiguity about "current block"

  3. Sybil-Resistant: Block numbers cannot be forged
     → Operators cannot lie about trigger conditions
     → Cryptographically verifiable via block headers

  4. Reorg-Safe: Use finalized blocks (not head)
     → Finality ensures block numbers never change
     → Prevents protocol confusion during chain reorgs

  5. Auditable: Sessions tied to on-chain block numbers
     → Anyone can verify when reshare should have occurred
     → Transparent accountability for protocol execution

  6. No External Dependencies: Only requires Ethereum RPC
     → No NTP, no external time services
     → Reduced attack surface
```

**Finality Considerations**:

| Chain          | Finality Mechanism | Finality Time |
|----------------|-------------------|---------------|
| Ethereum Mainnet | 2 epoch confirmation | ~13 minutes |
| Sepolia Testnet  | 2 epoch confirmation | ~13 minutes |
| Anvil Devnet     | Immediate (single node) | < 1 second |

**Implementation**: Operators query `eth_getBlockByNumber("finalized")` to get latest finalized block, ensuring reshare triggers are reorg-proof.

**Key Properties**:
- **Deterministic**: All operators trigger at same block number (blockchain consensus)
- **Sybil-Resistant**: Block numbers cannot be manipulated by operators
- **Decentralized**: No coordinator or master node required
- **Reorg-Safe**: Uses finalized blocks to prevent reorganization issues
- **Globally Consistent**: All operators see identical block numbers
- **Trustless**: No reliance on external time sources or synchronization protocols
- **Churn-tolerant**: Operator set queried fresh each interval (handles joins/leaves)

### DKG Process

The Distributed Key Generation (DKG) protocol enables operators to collectively generate a shared master secret without any single operator ever knowing the complete secret. The system targets **Pedersen Verifiable Secret Sharing (VSS)** for production deployment, providing information-theoretic security against bias attacks. Alpha testnet uses **Feldman-VSS** for rapid iteration.

#### Feldman-VSS vs Pedersen-VSS

**Alpha Testnet Implementation (Feldman-VSS)**:

**Commitment Scheme**: Single polynomial with public commitments
```
Each operator i generates: fᵢ(z) = aᵢ₀ + aᵢ₁·z + ... + aᵢ₍ₜ₋₁₎·z^(t-1)
Commitments: Cᵢₖ = aᵢₖ · G₂  (only uses G₂ generator)
```

**Security**: Computationally secure (discrete log assumption)

**Vulnerability**: Commitments reveal information about polynomial to computationally unbounded adversary. Timing attacks possible where adversary:
1. Sees all commitments after Phase 1
2. Computes aggregate key distribution
3. Decides which corrupted operators to disqualify
4. Biases final key distribution

**Mitigation**: Economic security via fraud proofs and slashing (see Fraud Detection section)

---

**Production Target (Pedersen-VSS)**:

**Commitment Scheme**: Dual polynomials with hiding commitments
```
Each operator i generates TWO polynomials:
  fᵢ(z) = aᵢ₀ + aᵢ₁·z + ... + aᵢ₍ₜ₋₁₎·z^(t-1)  (secret polynomial)
  f'ᵢ(z) = bᵢ₀ + bᵢ₁·z + ... + bᵢ₍ₜ₋₁₎·z^(t-1)  (blinding polynomial)

Commitments: Cᵢₖ = aᵢₖ·G₂ + bᵢₖ·H₂  (uses two generators G₂ and H₂)

Where H₂ generated via distributed coin flip such that dlog(H₂) is unknown
```

**Security**: Information-theoretically hiding (commitments reveal zero information about polynomial)

**Protection**: Bias attacks cryptographically impossible - adversary cannot determine key distribution from commitments regardless of computational power

**Requirement**: Must generate H₂ via distributed protocol before first DKG (one-time setup)

---

#### Protocol Flow (Pedersen-VSS - Production Target)

```
Operator 1          Operator 2          Operator 3          ...  Operator n
    │                   │                   │                       │
    │◄──────────────────┴───────────────────┴───────────────────────┘
    │  Phase 1a: Commitment (Information-Theoretically Hiding)
    │
    ├─→ Generate TWO random polynomials: fᵢ(z), f'ᵢ(z)
    │   Both degree t-1 with independent random coefficients
    │
    ├─→ Compute Pedersen commitments:
    │   Cᵢₖ = aᵢₖ·G₂ + bᵢₖ·H₂  (hides aᵢₖ via bᵢₖ)
    │   Broadcast to all operators
    │
    ├─→ Evaluate and send shares:
    │   sᵢⱼ = fᵢ(nodeID_j), s'ᵢⱼ = f'ᵢ(nodeID_j)
    │   Send (sᵢⱼ, s'ᵢⱼ) to operator j
    │
    │◄──────────────────────────────────────────────────────────────┐
    │  Receive commitments and share pairs from all operators        │
    │  Adversary sees C commitments but CANNOT compute yᵢ = g^(zᵢ)  │
    │                                                                 │
    │◄──────────────────┬───────────────────┬────────────────────────┘
    │  Phase 1b: Verification
    │
    ├─→ Verify each received share pair:
    │   sᵢⱼ·G₂ + s'ᵢⱼ·H₂ ?= Σ(Cᵢₖ · nodeID_j^k) for k=0 to t-1
    │
    ├─→ Send acknowledgement if valid
    │   (Same acknowledgement system as Feldman)
    │
    │◄──────────────────────────────────────────────────────────────┐
    │  Wait for ALL acknowledgements (100% required)                 │
    │  Determine QUAL = set of operators who received all acks       │
    │                                                                 │
    │◄──────────────────┬───────────────────┬────────────────────────┘
    │  Phase 2: Extraction (Reveal Public Values)
    │
    ├─→ Broadcast extraction commitments:
    │   Aᵢₖ = aᵢₖ·G₂  (reveals actual polynomial, no blinding)
    │
    ├─→ Verify consistency with Phase 1:
    │   Check Aᵢₖ·G₂ + (derived_bᵢₖ)·H₂ = Cᵢₖ
    │
    ├─→ Verify shares against extracted commitments:
    │   sᵢⱼ·G₂ ?= Σ(Aᵢₖ · nodeID_j^k)
    │
    │◄──────────────────┬───────────────────┬────────────────────────┘
    │  Phase 3: Finalization
    │
    ├─→ Compute final share: xⱼ = Σ(sᵢⱼ) for all i ∈ QUAL
    │   Master secret: S = Σ(aᵢ₀) for all i ∈ QUAL
    │
    ├─→ Store KeyShareVersion with extracted commitments
    │
    └─→ DKG complete
```

**Critical Security Property**: By the time adversary sees `Aᵢₖ` values in Phase 2 (which reveal `yᵢ = g^(zᵢ)`), QUAL is already determined in Phase 1. Adversary cannot retroactively change participation to bias key distribution.

---

#### Current Implementation (Feldman-VSS for Alpha)

The alpha testnet implementation uses simplified Feldman-VSS for rapid development:

```
Phase 1: Commitment and Share Distribution
  - Generate single polynomial fᵢ(z)
  - Commitments: Cᵢₖ = aᵢₖ·G₂ (Feldman-style, not hiding)
  - Broadcast commitments to all operators
  - Send shares sᵢⱼ = fᵢ(nodeID_j) to each operator

Phase 2: Verification and Acknowledgement
  - Verify: sᵢⱼ·G₂ = Σ(Cᵢₖ · nodeID_j^k)
  - Send signed acknowledgement to dealer
  - Dealer waits for ALL acknowledgements (100% required)

Phase 3: Finalization
  - Compute final share: xⱼ = Σ(sᵢⱼ)
  - Store KeyShareVersion
```

**Acknowledgement System**: Prevents dealer equivocation by requiring proof that all operators received and verified shares before finalization.

#### Mathematical Foundation

**Polynomial Secret Sharing**:

Each operator i contributes secret `zᵢ` via polynomial:
```
fᵢ(z) = aᵢ₀ + aᵢ₁·z + ... + aᵢ₍ₜ₋₁₎·z^(t-1)

Where:
- t = ⌈2n/3⌉ (threshold for Byzantine fault tolerance)
- aᵢₖ ∈ Fr (BLS12-381 scalar field), chosen uniformly at random
- aᵢ₀ = fᵢ(0) = zᵢ (operator i's secret contribution)
```

**Share Generation**: Each operator j receives `sᵢⱼ = fᵢ(nodeID_j)` from operator i

**Final Share Computation**: `xⱼ = Σ sᵢⱼ` for all i

**Master Secret**: `S = Σ zᵢ = Σ fᵢ(0)` (never computed by any party, remains distributed)

**Threshold Reconstruction**: Any t operators can recover S via Lagrange interpolation:
```
S = Σ(λⱼ · xⱼ) for j ∈ T where |T| ≥ t
λⱼ = Π((0 - i)/(j - i)) for all i ∈ T, i ≠ j
```

---

#### Share Verification

**Feldman-VSS Verification** (Alpha):
```
Verify: sᵢⱼ·G₂ = Σ(Cᵢₖ · nodeID_j^k) for k=0 to t-1

Where: Cᵢₖ = aᵢₖ·G₂ (public commitments)
```

**Pedersen-VSS Verification** (Production):
```
Phase 1 Verify: sᵢⱼ·G₂ + s'ᵢⱼ·H₂ = Σ(Cᵢₖ · nodeID_j^k)
  Where: Cᵢₖ = aᵢₖ·G₂ + bᵢₖ·H₂ (hiding commitments)

Phase 2 Verify: sᵢⱼ·G₂ = Σ(Aᵢₖ · nodeID_j^k)
  Where: Aᵢₖ = aᵢₖ·G₂ (extracted commitments)
```

**Properties**:
- Cryptographic proof of share correctness
- Prevents dealer from sending invalid shares
- Detectable violations enable fraud proofs

#### Threshold Calculation

**Formula**: `t = ⌈2n/3⌉`

**Examples**:
- n=3 operators → t=2 threshold (can tolerate 1 failure)
- n=4 operators → t=3 threshold (can tolerate 1 failure)
- n=7 operators → t=5 threshold (can tolerate 2 failures)
- n=10 operators → t=7 threshold (can tolerate 3 failures)

**Byzantine Fault Tolerance**:
- **Safety**: Up to ⌊n/3⌋ operators can be malicious without compromising security
- **Liveness**: Any ⌈2n/3⌉ honest operators can complete operations
- **Standard BFT**: Matches typical Byzantine agreement requirements

#### State Machine

```
DKG Session State Machine:

    [INIT] ──────────────────────────────────────┐
       │                                          │
       │ Start DKG (at interval boundary)         │
       ▼                                          │
    [SHARE_DISTRIBUTION]                          │
       │                                          │
       │ Generate polynomial                      │
       │ Compute commitments                      │
       │ Send shares to all operators             │
       │ Receive shares from all operators        │ Timeout or
       ▼                                          │ Error
    [VERIFICATION]                                │
       │                                          │
       │ Verify all received shares               │
       │ Create acknowledgements                  │
       │ Send acks to all dealers                 │
       │ Receive acks from all operators          │
       ▼                                          │
    [ACKNOWLEDGEMENT_WAIT]                        │
       │                                          │
       │ Wait for 100% acknowledgement            │
       │ Timeout if any operator missing          │
       ▼                                          │
    [FINALIZATION] ──────────────────────────────┘
       │
       │ Compute final share: xⱼ = Σ(sᵢⱼ)
       │ Store KeyShareVersion
       ▼
    [COMPLETE]
```

#### Security Properties

1. **Secrecy (Information-Theoretic)**: No coalition of fewer than t = ⌈2n/3⌉ operators can learn the master secret, even with unbounded computation (Pedersen-VSS) or under discrete log assumption (Feldman-VSS)

2. **Correctness**: Any t or more operators can reconstruct the master secret via Lagrange interpolation with probability 1

3. **Verifiability**: All shares cryptographically verifiable against public commitments, enabling fraud detection

4. **Hiding (Pedersen only)**: Commitments reveal zero information about secret contributions during commitment phase, preventing bias attacks

5. **Non-repudiation**: Acknowledgement system with BN254 signatures prevents dealer equivocation and creates audit trail

6. **Fairness**: All operators contribute equally to master secret (uniform random polynomial coefficients)

7. **Abort Security**: Protocol aborts safely if any operator misbehaves, preventing partial key leakage

### Reshare Process

The reshare protocol enables periodic key rotation and dynamic operator set changes without requiring applications to update their encryption keys or re-encrypt data. The system preserves the master secret across resharing while generating new key shares for all operators, supporting both key rotation (same operator set) and operator churn (operators joining/leaving).

#### Protocol Overview

The reshare protocol differs from DKG in one critical aspect: existing operators use their **current shares** as the constant term of their reshare polynomials, rather than random values. This preserves the master secret across resharing.

```
Existing Operator 1   Existing Operator 2   New Operator 3
 (has share x₁)        (has share x₂)        (no share)
       │                     │                     │
       │◄────────────────────┴─────────────────────┘
       │  Phase 1: Reshare Distribution
       │
       ├─→ Create polynomial f'₁(z) where f'₁(0) = x₁  ← CRITICAL
       │   Higher degree terms random: a₁, a₂, ..., aₜ₋₁
       │
       ├─→ Compute new commitments: C'₁ = [f'₁(0)·G₂, ..., f'₁(t-1)·G₂]
       │   Broadcast to ALL operators (including new)
       │
       ├─→ Evaluate new shares: s'₁ⱼ = f'₁(nodeID_j) for ALL operators
       │   Send to existing AND new operators
       │
       │◄──────────────────────────────────────────────────────────────┐
       │  Receive commitments and shares from all EXISTING operators    │
       │  (New operators only receive, do not generate)                 │
       │                                                                 │
       │◄──────────────────┬────────────────────────────────────────────┘
       │  Phase 2: Lagrange Interpolation
       │
       ├─→ Compute Lagrange coefficients for existing operators:
       │   λᵢ = Π((0 - j)/(i - j)) for all j ∈ existing, j ≠ i
       │
       ├─→ Compute new share using interpolation:
       │   x'ⱼ = Σ(λᵢ · s'ᵢⱼ) for all i ∈ existing operators
       │
       ├─→ Verification:
       │   Check x'ⱼ·G₂ against aggregated commitments
       │
       ├─→ Store new KeyShareVersion:
       │   - Version: sessionTimestamp (new epoch)
       │   - PrivateShare: x'ⱼ (new share, preserves master secret)
       │   - Commitments: all received commitments
       │   - IsActive: true (activate immediately)
       │   - Old version marked inactive
       │
       └─→ Reshare complete, continue operations with new shares
```

#### Master Secret Preservation

The critical property of reshare is that the master secret remains unchanged:

**Original DKG:**
```
Master secret S = Σ(fᵢ(0)) for all i ∈ [1, n]
Operator j's share: xⱼ = Σ(fᵢ(j))
```

**After Reshare:**
```
Existing operator i creates f'ᵢ(z) where:
  f'ᵢ(0) = xᵢ  ← Current share becomes constant term

Master secret preservation:
  S' = Σ(f'ᵢ(0)) = Σ(xᵢ) = S  ← Same master secret!

New share computation (Lagrange interpolation):
  x'ⱼ = Σ(λᵢ · s'ᵢⱼ) for i ∈ existing operators
      = Σ(λᵢ · f'ᵢ(j))

At x=0 (master secret):
  S' = Σ(λᵢ · f'ᵢ(0)) = Σ(λᵢ · xᵢ) = S
```

#### Lagrange Interpolation

Lagrange interpolation is the mathematical technique that allows computing new shares while preserving the master secret:

```
Given: Existing operators with shares {xᵢ} and node IDs {i}
Goal: Compute new share x'ⱼ at node ID j

Lagrange basis polynomial:
  Lᵢ(x) = Π((x - k)/(i - k)) for all k ∈ existing, k ≠ i

Lagrange coefficient at x=0:
  λᵢ = Lᵢ(0) = Π((0 - k)/(i - k)) = Π(-k/(i - k))

New share:
  x'ⱼ = Σ(λᵢ · s'ᵢⱼ) where s'ᵢⱼ = f'ᵢ(j)
```

**Implementation** (`pkg/reshare/lagrange.go`):

```go
func ComputeLagrangeCoefficients(
    existingNodeIDs []int,
    x *big.Int,  // Usually 0 for master secret
) ([]*fr.Element, error) {
    n := len(existingNodeIDs)
    coefficients := make([]*fr.Element, n)

    for i := 0; i < n; i++ {
        numerator := fr.NewElement().SetOne()
        denominator := fr.NewElement().SetOne()

        for j := 0; j < n; j++ {
            if i == j {
                continue
            }

            // numerator *= (x - nodeID_j)
            term := fr.NewElement().SetInt64(int64(existingNodeIDs[j]))
            term.Sub(x, term)
            numerator.Mul(numerator, term)

            // denominator *= (nodeID_i - nodeID_j)
            diff := big.NewInt(int64(existingNodeIDs[i] - existingNodeIDs[j]))
            term.SetBigInt(diff)
            denominator.Mul(denominator, term)
        }

        // coefficient = numerator / denominator (field division)
        coefficients[i] = fr.NewElement()
        coefficients[i].Div(numerator, denominator)
    }

    return coefficients, nil
}

func ComputeNewShare(
    receivedShares []*fr.Element,
    lagrangeCoefficients []*fr.Element,
) (*fr.Element, error) {
    if len(receivedShares) != len(lagrangeCoefficients) {
        return nil, errors.New("mismatched lengths")
    }

    newShare := fr.NewElement().SetZero()
    for i := range receivedShares {
        term := fr.NewElement()
        term.Mul(lagrangeCoefficients[i], receivedShares[i])
        newShare.Add(newShare, term)
    }

    return newShare, nil
}
```

#### Operator Scenarios

**Scenario 1: Existing Operator (Routine Key Rotation)**

An operator that participated in the previous DKG or reshare executes periodic key rotation at the next interval boundary.

**Process**:
1. **Retrieve Current Share**: Operator loads its active key share from local keystore
2. **Generate Reshare Polynomial**: Creates new polynomial where the constant term equals the current share
   - **Critical**: `f'(0) = currentShare` preserves the master secret across resharing
   - Higher-degree terms (a₁, a₂, ..., aₜ₋₁) chosen randomly
3. **Distribute New Shares**: Evaluates polynomial at all current operator node IDs
   - Sends shares to both existing operators and any newly joined operators
   - Broadcasts commitments to all participants for verification
4. **Receive and Verify**: Collects shares from all other existing operators
   - Verifies each share against dealer's broadcast commitments
   - Reports fraud if verification fails
5. **Compute Updated Share**: Uses Lagrange interpolation to compute new share
   - Lagrange coefficients computed for existing operator set
   - New share = Σ(λᵢ × received_share_i) for all existing operators i
6. **Activate New Version**: Stores new key share with incremented version timestamp
   - Marks previous version as inactive
   - Immediately usable for application signing requests

**Properties**:
- Master secret S remains unchanged: S' = S
- Old shares become cryptographically independent from new shares (forward secrecy)
- New threshold may differ if operator set size changed (t' = ⌈2n'/3⌉)
- Applications unaffected (master public key unchanged)

---

**Scenario 2: New Operator (Joining Existing Cluster)**

An operator joining an existing KMS cluster for the first time participates passively in reshare to obtain its initial key share.

**Process**:
1. **Passive Participation**: Operator does NOT generate or distribute shares
   - Only existing operators (those with current shares) act as dealers
   - New operator is purely a receiver in this reshare round
2. **Receive Shares**: Waits for shares from all existing operators
   - Each existing operator sends one share (their polynomial evaluated at new operator's node ID)
3. **Verify Shares**: Validates each received share against dealer's commitments
   - Uses same verification equation as existing operators
   - Reports fraud for invalid shares
4. **Compute Initial Share**: Uses Lagrange interpolation with existing operators' node IDs
   - Same mathematical process as existing operators
   - Results in valid share of the unchanged master secret
5. **Store and Activate**: Saves first key share version, becomes full participant
   - Immediately eligible for application signing requests
   - Will act as dealer in next reshare round

**Properties**:
- New operator cannot influence master secret (passive receiver only)
- Master secret S unchanged despite operator set expansion
- New operator immediately capable of threshold operations (becomes full peer)
- Operator count increase causes threshold recalculation

---

**Scenario 3: Operator Leaves**

An operator removed from the operator set (by AVS governance or slashing) stops participating in protocols.

**Process**:
1. **Detection**: At interval boundary, operator discovers it's no longer in current operator set
2. **Cessation**: Operator stops participating in DKG/Reshare protocols
3. **Redistribution**: Remaining operators execute reshare without departed operator
   - Shares redistributed among remaining n' operators
   - Threshold recalculated: t' = ⌈2n'/3⌉
4. **Key Invalidation**: Departed operator's share becomes useless
   - Cannot participate in threshold reconstruction (not in current set)
   - Master secret S unchanged, but access requires current operator participation

**Properties**:
- Graceful operator removal without master secret change
- Departed operator's share provides no information (information-theoretic secrecy)
- System continues operating with remaining operators (if ≥ t)

---

#### Security Properties

1. **Master Secret Preservation**: The master secret S remains unchanged across all reshares
2. **Forward Secrecy**: Old shares cannot decrypt data encrypted after reshare
3. **Share Independence**: New shares are computationally independent from old shares
4. **Threshold Consistency**: t = ⌈2n/3⌉ maintained for new operator set
5. **No Trusted Dealer**: Reshare is distributed; no central party needed
6. **Operator Churn Support**: Handles joins/leaves without full DKG

### EigenLayer Protocol Integration

EigenX KMS operates as a native EigenLayer AVS, leveraging EigenLayer's restaking infrastructure for operator management, economic security, and cryptographic key registration. The integration spans multiple EigenLayer contracts and protocols.

#### Contract Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    EigenLayer Core Contracts                     │
│                                                                   │
│  ┌────────────────────┐  ┌──────────────────────────────────┐   │
│  │ DelegationManager  │  │   AllocationManager              │   │
│  │ - Operator reg     │  │   - Stake allocation tracking    │   │
│  │ - Delegations      │  │   - Slashing conditions          │   │
│  └────────────────────┘  └──────────────────────────────────┘   │
│                                                                   │
│  ┌────────────────────┐  ┌──────────────────────────────────┐   │
│  │ AVSDirectory       │  │   OperatorSetRegistrar           │   │
│  │ - AVS registry     │  │   - Operator set management      │   │
│  │ - Operator→AVS     │  │   - Join/leave operations        │   │
│  └────────────────────┘  └──────────────────────────────────┘   │
│                                                                   │
└───────────────────────────┬───────────────────────────────────────┘
                            │
                            │
┌───────────────────────────▼───────────────────────────────────────┐
│                    KMS AVS Contracts                              │
│                                                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ KeyRegistrar                                               │  │
│  │ - BN254 public key registration                            │  │
│  │ - Key history tracking                                     │  │
│  │ - Operator key queries                                     │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ KMS Release Manager (Future)                               │  │
│  │ - Configuration management                                 │  │
│  │ - Interval updates                                         │  │
│  │ - Feature flags                                            │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

#### Operator Discovery via Peering

```
┌─────────────┐
│  KMS Node   │
└──────┬──────┘
       │
       │ GetOperators()
       ▼
┌──────────────────────────┐
│ OperatorSetRegistrar     │  (EigenLayer Contract)
│ getOperatorSet(setId)    │
└──────┬───────────────────┘
       │ Returns: [operatorAddress₁, operatorAddress₂, ...]
       │
       │ For each operator:
       ▼
┌──────────────────────────┐
│  KeyRegistrar Contract   │
│  getOperatorKey(address) │
└──────┬───────────────────┘
       │ Returns: BN254 Public Key (G1 point)
       │
       ▼
┌──────────────────────────┐
│  Socket Registry         │
│  getSocket(address)      │
└──────┬───────────────────┘
       │ Returns: "http://host:port"
       │
       ▼
┌──────────────────────────┐
│  OperatorSetPeer[]       │
│  {                       │
│    operatorAddress,      │
│    bn254PublicKey,       │
│    socketAddress         │
│  }                       │
└──────────────────────────┘
```

**Peering Interface**:
```
GetOperators() → []OperatorSetPeer
```

**Returned Data**:
- `operatorAddress`: Ethereum address (operator identity)
- `bn254PublicKey`: Public key for message verification
- `socketAddress`: HTTP endpoint for P2P communication

**Implementations**:
- **Production**: Queries blockchain via EigenLayer contracts
- **Testing**: Local mock using ChainConfig test data

**Security**: Public keys and socket addresses are fetched from trusted blockchain state, preventing MITM attacks during peer discovery

### HTTP API Interface

The KMS node exposes two categories of HTTP endpoints: **Protocol APIs** for inter-operator communication (authenticated with BN254 signatures) and **Application APIs** for client interactions.

#### Protocol APIs (Authenticated)

All protocol messages wrapped in `AuthenticatedMessage` structure with BN254 signatures for authentication.

**Message Envelope**:
```
AuthenticatedMessage {
    payload: []byte       // Serialized protocol message
    hash: [32]byte       // keccak256(payload)
    signature: []byte    // BN254_sign(hash, operatorPrivateKey)
}
```

**DKG Endpoints:**

```
POST /dkg/commitment
  Request: AuthenticatedMessage<CommitmentMessage>
    FromOperatorAddress: dealer address
    ToOperatorAddress: 0x0 (broadcast)
    SessionTimestamp: interval boundary time
    Commitments: []G2Point
  Response: 200 OK | 400 Bad Request

POST /dkg/share
  Request: AuthenticatedMessage<ShareMessage>
    FromOperatorAddress: dealer address
    ToOperatorAddress: specific receiver address
    SessionTimestamp: interval boundary time
    Share: Fr element (encrypted)
  Response: 200 OK | 400 Bad Request | 401 Unauthorized

POST /dkg/ack
  Request: AuthenticatedMessage<AcknowledgementMessage>
    FromOperatorAddress: receiver address
    ToOperatorAddress: dealer address
    SessionTimestamp: interval boundary time
    ShareHash: keccak256(share)
  Response: 200 OK | 400 Bad Request
```

**Reshare Endpoints:**

```
POST /reshare/commitment
POST /reshare/share
POST /reshare/ack
POST /reshare/complete

(Same message structure as DKG endpoints)
```

**Authentication Flow**:
1. Parse `AuthenticatedMessage` from request body
2. Verify payload hash matches `keccak256(payload)`
3. Extract sender address from deserialized payload
4. Lookup sender's BN254 public key from peering data
5. Verify signature: `ecrecover(hash, signature) == senderAddress`
6. Verify recipient matches (if not broadcast message)
7. Forward to protocol handler if all checks pass

#### Application APIs (Public)

These endpoints are accessible to applications and clients without authentication:

**Master Public Key Query:**

```
GET /pubkey

Response: 200 OK
{
    "operatorAddress": "0x1234...",
    "commitments": [
        {
            "x": "0x...",  // G2 point X coordinate
            "y": "0x..."   // G2 point Y coordinate
        },
        // ... more commitment points
    ],
    "version": 1640995200,  // Session timestamp
    "isActive": true
}
```

**Application Partial Signature (Direct):**

```
POST /app/sign

Request:
{
    "appID": "my-application",
    "attestationTime": 1640995200  // Optional: historical key lookup
}

Response: 200 OK
{
    "operatorAddress": "0x1234...",
    "partialSignature": {
        "x": "0x...",  // G1 point X coordinate
        "y": "0x..."   // G1 point Y coordinate
    },
    "version": 1640995200
}
```

**TEE Secrets Delivery** (attestation-verified):

```
POST /secrets

Request:
{
    "app_id": "my-application",
    "attestation": "base64_encoded_tdx_quote",  // Intel TDX attestation
    "rsa_pubkey_tmp": "-----BEGIN PUBLIC KEY-----...",  // Ephemeral RSA key
    "attest_time": 1640995200
}

Response: 200 OK
{
    "encrypted_env": "base64_aes_encrypted_environment_variables",
    "public_env": "base64_plain_environment_variables",
    "encrypted_partial_sig": "base64_rsa_encrypted_partial_signature"
}

Error Response: 400/401
{
    "error": "attestation_verification_failed",
    "details": "Invalid TDX quote signature"
}
```

**Health Check:**

```
GET /health

Response: 200 OK
{
    "status": "healthy",
    "version": "v0.1.0",
    "hasActiveKey": true,
    "lastReshare": 1640995200,
    "operatorAddress": "0x1234..."
}
```

#### Client Request Flow

See the **Encryption Workflow** and **Decryption Workflow** sections in the "Application Integration" chapter for detailed diagrams of client request flows.

## Cryptographic Components

### BLS12-381 Threshold Signatures

**Curve Properties:**
- **Pairing-friendly** elliptic curve supporting efficient threshold cryptography
- **Security level**: ~128-bit (comparable to AES-128)
- **Field**: Prime field Fr with large prime order
- **Groups**:
  - **G1**: Used for signatures and application private keys
  - **G2**: Used for public keys and polynomial commitments
  - **GT**: Target group for pairings (verification)

**Key Operations:**

1. **Polynomial Generation**: Creates a random polynomial of degree t-1 where coefficients are sampled from the field Fr
2. **Polynomial Evaluation**: Computes f(x) = Σ(aₖ·xᵏ) for generating secret shares at each operator's node ID
3. **Commitment Generation**: Creates public commitments Cₖ = aₖ·G₂ for each polynomial coefficient for verifiable secret sharing

**Share Verification:**

Operators verify received shares using the polynomial commitments by checking the equation:
```
s·G₂ = Σ(Cₖ·xᵏ) for k=0 to t-1
```
where s is the share, x is the nodeID, and Cₖ are the commitments. This ensures the dealer correctly distributed shares from the same polynomial.

**Partial Signature Generation:**

Each operator generates a partial signature for an application using their private share:
```
σᵢ = H₁(appID)^(xᵢ)
```
where H₁ hashes the app ID to a G1 point and xᵢ is the operator's private share.

**Signature Recovery:**

The full application private key is recovered from threshold partial signatures using Lagrange interpolation:
```
sk_app = Σ(λᵢ·σᵢ) for i ∈ [1, t]
```
where λᵢ are Lagrange coefficients computed at x=0 for the participating operators' node IDs.

### BN254 Message Authentication

**Purpose**: Authenticate all inter-operator P2P messages

**Key Properties:**
- EigenLayer standard curve for operator keys
- Solidity-compatible (ecrecover-style verification on-chain)
- Efficient signature generation and verification

**Message Authentication Process:**

1. **Message Signing**: Compute keccak256 hash of the payload, then sign with BN254 private key. Returns an AuthenticatedMessage containing the payload, hash, and signature.

2. **Message Verification**:
   - Verify the payload hash matches the included hash
   - Recover the signer's public key from the signature
   - Compare recovered public key with expected operator's public key
   - All steps must succeed for message to be authenticated

**Security Properties:**
- Prevents message tampering (hash verification)
- Authenticates sender identity (signature verification)
- Non-repudiable (cryptographic signature binding)

### Identity-Based Encryption (IBE)

**Concept**: Encrypt data using simple identifiers (app IDs) without pre-shared keys

**Encryption Process:**

1. **Hash to G1**: Hash the app ID to a G1 point using SHA-256 and the standard hash-to-curve algorithm
2. **Derive Encryption Key**: Compute a pairing between the hashed app ID and the master public key (constant term of commitments) to derive a symmetric encryption key in GT
3. **Symmetric Encryption**: Use AES-GCM with the derived key to encrypt the plaintext data

**Decryption Process:**

1. **Collect Partial Signatures**: Application requests threshold partial signatures from operators
2. **Recover App Private Key**: Use Lagrange interpolation to aggregate partial signatures into the full application private key (a G1 point)
3. **Derive Decryption Key**: Convert the app private key to bytes for use as symmetric key
4. **Symmetric Decryption**: Use AES-GCM to decrypt the ciphertext

**Application Private Key Recovery:**

```
Given:
  - appID = "my-application"
  - t partial signatures: {σ₁, σ₂, ..., σₜ} from operators
  - Operator node IDs: {id₁, id₂, ..., idₜ}

Step 1: Compute Lagrange coefficients
  λᵢ = Π((0 - j)/(i - j)) for all j ≠ i

Step 2: Aggregate partial signatures
  sk_app = Σ(λᵢ · σᵢ) for i ∈ [1, t]

Step 3: Use sk_app to decrypt ciphertext
  plaintext = IBE.Decrypt(sk_app, ciphertext)
```

**Security Properties:**
1. **Identity-based**: No key exchange required
2. **Threshold decryption**: Requires t operators to decrypt
3. **Forward secrecy**: Reshare invalidates old app keys
4. **Selective disclosure**: Different apps have different keys

### Key Serialization

**BLS12-381 Serialization Formats:**

All cryptographic elements use compressed point encoding for efficient storage and transmission:

- **G1 Points**: 48 bytes compressed (used for signatures and application private keys)
- **G2 Points**: 96 bytes compressed (used for public keys and polynomial commitments)
- **Fr Elements**: 32 bytes big-endian (used for secret shares and scalars)

**Operations:**
- Serialization converts curve points to compressed byte representations
- Deserialization reconstructs curve points from compressed formats
- Compression reduces bandwidth and storage requirements while maintaining security

## Security Model

### Threat Model

**Adversary Capabilities:**
- Control up to ⌊n/3⌋ operators through compromise or collusion
- Network-level adversary (delay, reorder, drop, or inject messages)
- Passive observation of all network traffic and blockchain state
- Access to historical key shares from compromised operators
- Unbounded computational power (for analyzing Feldman-VSS commitments in alpha)
- Real-time decision making during protocol execution (for bias attacks)

**Trust Assumptions:**
- **Honest Majority**: At least ⌈2n/3⌉ operators follow protocol correctly and are not colluding
- **Cryptographic Hardness**:
  - Discrete log problem in BLS12-381 (128-bit security)
  - Elliptic curve discrete log in BN254 (EigenLayer standard)
- **Economic Rationality**: Operators act rationally under slashing incentives
- **Permissioned Operation**: Operators vetted and approved by AVS governance before admission
- **Blockchain Security**: Ethereum provides tamper-proof source of truth for operator sets
- **Hardware Trust**: Intel TDX provides authentic attestation of TEE execution

**Out of Scope Threats:**
- Quantum adversaries (post-quantum cryptography not implemented)
- Side-channel attacks on operator hardware (assumed secure operational environment)
- Social engineering of operator key material (operators responsible for key security)
- Supply chain attacks on operator infrastructure (operators responsible for secure deployment)

### Security Properties

**1. Threshold Secrecy (Information-Theoretic)**

**Property**: No coalition of fewer than t = ⌈2n/3⌉ operators can learn the master secret or any application private key, regardless of computational resources.

**Mechanism**: Shamir secret sharing over BLS12-381 scalar field
- Master secret `S = Σ fᵢ(0)` distributed across operators
- Each operator holds share `xⱼ = Σ fᵢ(j)`
- Any t shares can reconstruct S via Lagrange interpolation
- Fewer than t shares reveal zero information (information-theoretic guarantee)

**Security Level**:
- **Alpha (Feldman-VSS)**: Computational security under discrete log assumption
- **Production (Pedersen-VSS)**: Information-theoretic hiding during commitment phase

**Attack Resistance**:
- ⌊n/3⌋ compromised operators cannot recover master secret
- Reshare invalidates compromised shares (forward secrecy)
- Applications receive independent private keys (IBE isolation)

---

**2. Hiding (Pedersen-VSS Production Target)**

**Property**: During DKG commitment phase, polynomial commitments reveal zero information about operator secret contributions, preventing bias attacks.

**Feldman-VSS Limitation (Alpha)**:
```
Commitments: Cᵢₖ = aᵢₖ·G₂
Problem: Adversary can compute yᵢ = g^(zᵢ) from commitments
Result: Timing-based bias attacks theoretically possible
```

**Pedersen-VSS Solution (Production)**:
```
Commitments: Cᵢₖ = aᵢₖ·G₂ + bᵢₖ·H₂
Property: Information-theoretically hiding (no information about aᵢₖ)
Result: Bias attacks cryptographically impossible
```

**Bias Attack Prevention**:
- **Feldman**: Relies on economic security (slashing) and limited attack window
- **Pedersen**: Cryptographically prevents bias attacks (hiding commitments)

---

**3. Verifiability and Fraud Detection**

**Property**: All protocol violations are cryptographically detectable and provable on-chain.

**Mechanisms**:
- Share verification equation: `sᵢⱼ·G₂ = Σ(Cᵢₖ · nodeID_j^k)`
- BN254 signatures on all inter-operator messages
- Acknowledgement system with cryptographic proofs
- On-chain fraud proof verification in smart contracts

**Detectable Violations**:
- Invalid shares (don't verify against commitments)
- Equivocation (different shares to different operators with same commitments)
- Commitment inconsistency (different commitments broadcast to different receivers)
- Missing acknowledgements (protocol non-participation)

**Enforcement**: Verified fraud proofs trigger automatic slashing via EigenLayer

---

**4. Byzantine Fault Tolerance**

**Property**: System maintains safety and liveness with up to ⌊n/3⌋ Byzantine (malicious or faulty) operators.

**Mechanisms**:
- Threshold t = ⌈2n/3⌉ ensures any honest majority can operate
- Share verification prevents invalid contribution acceptance
- Acknowledgements prevent partial participation attacks
- Reshare handles operator recovery and churn

**Guarantees**:
- **Safety**: Adversary with ≤⌊n/3⌋ operators cannot compromise master secret
- **Liveness**: Any ⌈2n/3⌉ operators can complete DKG/Reshare and serve applications
- **Self-Healing**: Malicious operators detected and removed via slashing

---

**5. Economic Security via Slashing**

**Property**: Protocol violations are economically irrational due to slashing penalties exceeding potential gains.

**Mechanism**: Operators submit fraud proofs to slashing contract
- Smart contract verifies proofs cryptographically on-chain
- Verified fraud triggers automatic slashing via EigenLayer AllocationManager
- Repeated violations result in operator ejection from AVS

**Economic Deterrence**:
- **Invalid Share**: 0.1 ETH slash per fraud (threshold: 3 reports)
- **Equivocation**: 1 ETH slash (threshold: 1 proof)
- **Repeated Violations**: Escalating penalties + ejection

**Game Theory**: Cost of attack (stake slashed) >> Gain from attack (biased key distribution provides no financial benefit)

---

**6. Non-Repudiation and Accountability**

**Property**: All operator actions cryptographically attributable with non-repudiable signatures.

**Mechanisms**:
- BN254 signatures on all protocol messages (commitment, share, acknowledgement)
- Signatures include sender address, recipient address, session timestamp
- On-chain BN254 public key registration provides signature verification anchor
- Acknowledgements create audit trail of protocol participation

**Accountability**:
- Operators cannot deny sending invalid shares (signature proof)
- Operators cannot claim they didn't receive shares (acknowledgement absence is observable)
- All protocol violations have cryptographic evidence trail

---

**7. Forward Secrecy**

**Property**: Compromise of current key shares does not compromise previously encrypted application data.

**Mechanism**: Periodic resharing with cryptographically independent share generation
- Reshare creates new shares from existing shares via Lagrange interpolation
- New shares computationally independent from old shares
- Old shares become useless for decryption after reshare

**Limitation**: Master secret S remains constant (only shares rotate)
- Data encrypted with master public key before reshare can still be decrypted after reshare
- Applications should periodically re-encrypt with updated master public key (after full DKG)

**Future Enhancement**: Master secret rotation via periodic full DKG (backward compatibility break)

### Attack Scenarios and Defenses

**Scenario 1: Key Distribution Bias Attack (Feldman-VSS Vulnerability)**

**Attack**: Adversary controlling multiple operators attempts to bias the final master key distribution.

**Attack Steps** (Feldman-VSS only):
1. All operators broadcast commitments Cᵢₖ = aᵢₖ·G₂
2. Adversary sees commitments, computes aggregate `y = Π yᵢ where yᵢ = g^(zᵢ)`
3. Adversary analyzes last bit of y
4. If unfavorable, adversary forces one corrupted operator to be disqualified
5. Final key changes to `y' = y / yₐ` where yₐ is disqualified operator's contribution
6. Adversary gains ~1 bit of bias per execution

**Defense (Alpha Testnet - Feldman-VSS)**:
- **Economic Deterrence**: Slashing makes attack costly (lose stake for minimal bias)
- **Permissioned Operators**: Pre-vetted operators reduce anonymous adversaries
- **Statistical Monitoring**: Repeated bias attempts detectable across multiple DKGs
- **Limited Gain**: ~1 bit bias provides no practical attack advantage

**Defense (Production - Pedersen-VSS)**:
- **Cryptographic Prevention**: Information-theoretic hiding makes bias attack impossible
- Commitments `Cᵢₖ = aᵢₖ·G₂ + bᵢₖ·H₂` reveal zero information about yᵢ
- By the time yᵢ values revealed (Phase 2), QUAL already determined
- Adversary cannot retroactively change participation decisions

**Verdict**:
- **Alpha**: Low risk (economic disincentive + limited gain)
- **Production**: No risk (cryptographically prevented)

---

**Scenario 2: Equivocation (Malicious Dealer)**

**Attack**: Operator i sends different shares to different operators while broadcasting same commitments.

**Attack Example**:
- Dealer broadcasts commitments C
- Sends share s₁ to operator 1 where s₁ verifies against C
- Sends share s₂ to operator 2 where s₂ verifies against C
- But s₁ and s₂ lie on different polynomials (inconsistent)

**Defense**:
1. All operators receive identical commitments (broadcast channel)
2. Each operator verifies received share against commitments
3. Both shares may verify individually but define different polynomials
4. Operators exchange acknowledgements, detect inconsistency
5. Operators can collab to generate equivocation fraud proof
6. Submit proof to slashing contract for verification

**Result**: Equivocation cryptographically proven, dealer slashed and ejected

---

**Scenario 3: Compromised Operator Shares**

**Attack**: Adversary compromises ⌊n/3⌋ operators and steals their private key shares.

**Impact Analysis** (n=10 example):
- Operators compromised: 3
- Threshold required: ⌈20/3⌉ = 7
- Adversary has: 3 shares (insufficient for reconstruction)

**Defense**:
- **Threshold Security**: 3 < 7, mathematically impossible to recover master secret
- **Information-Theoretic**: 3 shares reveal zero information about S
- **Automatic Recovery**: Next reshare (10 min intervals) generates new shares
- **Compromised shares become useless after reshare**

**Result**: No secret leakage, automatic mitigation within 10 minutes

---

**Scenario 4: Message Replay Attack**

**Attack**: Adversary captures valid DKG share message, attempts replay in future protocol run.

**Defense**:
- `SessionTimestamp` in message binds it to specific DKG run
- Nodes maintain set of processed session timestamps
- Messages with non-current SessionTimestamp rejected
- BN254 signature prevents message modification

**Result**: Replay detected and rejected (stale session timestamp)

---

**Scenario 5: Application Key Request Spoofing**

**Attack**: Malicious client requests partial signatures for victim application's appID.

**Impact**: Without application-layer authentication, attacker could decrypt victim's data.

**Defense** (Application Responsibility):
- **TEE Attestation**: Intel TDX quote proving authorized code (EigenX platform)
- **Access Control**: OAuth/JWT tokens, API keys, IP allowlisting
- **Rate Limiting**: Prevent brute-force appID enumeration
- **Monitoring**: Alert on suspicious partial signature request patterns

**Protocol Position**: KMS provides cryptographic primitives; applications must implement access control appropriate to their threat model.

---

**Scenario 6: Network Partition During Reshare**

**Attack**: Network partition splits operator set during reshare protocol execution.

**Impact**:
- Minority partition (< ⌈2n/3⌉): Cannot complete reshare (insufficient operators)
- Majority partition (≥ ⌈2n/3⌉): Reshare succeeds with available operators

**Defense**:
- **Graceful Degradation**: Majority continues operations
- **Automatic Retry**: Minority operators retry at next interval boundary (10 min)
- **Historical Keys**: Old key versions remain valid for historical attestation times
- **No Data Loss**: Applications can still decrypt with previous key version

**Result**: Majority completes reshare, minority rejoins at next opportunity

### Cryptographic Assumptions

1. **Discrete Logarithm Problem (BLS12-381)**: Computing private share from public commitment is intractable
2. **Elliptic Curve Discrete Log (BN254)**: Recovering private key from public key is intractable
3. **Collision Resistance (Keccak256)**: Finding hash collisions is computationally infeasible
4. **Bilinear Pairing Security**: No efficient algorithm breaks pairing-based cryptography

### Operational Security

**Key Management:**
- Operator BN254 private keys should be stored in HSMs or secure enclaves
- Key shares should be encrypted at rest (future: integration with vault backends)
- Regular key rotation via reshare

**Network Security:**
- TLS recommended for HTTP endpoints (terminate at reverse proxy)
- IP allowlisting for protocol endpoints
- DDoS protection via rate limiting

**Monitoring:**
- Track DKG/reshare success rates
- Alert on missing acknowledgements
- Monitor operator availability

**Incident Response:**
- Operator key compromise: Immediately deregister from operator set
- Suspected equivocation: Investigate acknowledgement logs
- Protocol failure: Automatic retry at next interval

## Fraud Detection and Slashing

### Overview

The KMS implements an on-chain fraud proof system enabling cryptographic detection and economic punishment of protocol violations. Operators monitor peer behavior and submit verifiable proofs of misbehavior to the slashing smart contract, which triggers automatic penalties via EigenLayer's AllocationManager.

### Fraud Detection Mechanism

**Detection Flow**:
```
Operator detects violation → Construct fraud proof → Submit to contract
                                                              ↓
                                            Verify proof cryptographically
                                                              ↓
                                            Slash via AllocationManager
                                                              ↓
                                            Eject if threshold exceeded
```

**Fraud Proof Components**:
1. **Cryptographic Evidence**: Signatures proving dealer's actions
2. **Violation Proof**: Mathematical proof of protocol deviation
3. **Context**: Session timestamp, operator addresses, commitments
4. **Verification**: On-chain cryptographic verification (no trusted party)

### Slashable Violations

**1. Invalid Share**

**Violation**: Dealer sends share that doesn't verify against broadcast commitments.

**Detection**: Receiver computes `sᵢⱼ·G₂` and `Σ(Cᵢₖ · nodeID_j^k)`, finds inequality.

**Fraud Proof Contains**:
- Dealer's broadcast commitments (with signature)
- Invalid share sent to receiver (with signature)
- Receiver's node ID for verification

**On-Chain Verification**:
```
Contract computes:
  leftSide = g^share
  rightSide = Σ(commitments[k] · nodeID^k)

If leftSide ≠ rightSide:
  Fraud proven → Increment dealer's fraud counter
```

**Slashing Threshold**: 3 independent reports from different receivers
**Penalty**: 0.1 ETH per fraud, escalating with repeat violations

---

**2. Equivocation**

**Violation**: Dealer sends different shares to different operators (both verify individually, but inconsistent).

**Detection**: Two receivers compare notes, find they received different shares for same polynomial.

**Fraud Proof Contains**:
- Dealer's broadcast commitments (signed)
- Share 1 sent to receiver 1 (signed) + receiver 1's node ID
- Share 2 sent to receiver 2 (signed) + receiver 2's node ID
- Both shares verify individually but define different polynomials

**On-Chain Verification**:
```
Verify both shares valid individually:
  s₁·G₂ = Σ(C_k · nodeID₁^k) ✓
  s₂·G₂ = Σ(C_k · nodeID₂^k) ✓

But shares are inconsistent (different polynomials):
  Lagrange interpolation shows polynomial mismatch
```

**Slashing Threshold**: 1 cryptographic proof (more severe)
**Penalty**: 1 ETH immediate slash + ejection consideration

---

**3. Commitment Inconsistency**

**Violation**: Dealer broadcasts different commitments to different operators.

**Detection**: Operators compare received commitments, find inconsistency.

**Fraud Proof Contains**:
- Commitment set 1 sent to receiver 1 (signed, includes receiver address)
- Commitment set 2 sent to receiver 2 (signed, includes receiver address)
- Both signed by same dealer but different content

**On-Chain Verification**:
```
Verify dealer signed both commitment sets
Verify commitments are different (array inequality)
Fraud proven if both signatures valid and commitments differ
```

**Slashing Threshold**: 1 proof
**Penalty**: 0.5 ETH + monitoring for repeated violations

---

**4. Protocol Non-Participation**

**Violation**: Operator fails to send shares/acknowledgements, causing protocol abortion.

**Detection**: Operators track which peers responded, identify non-responsive operators.

**Enforcement**: Off-chain monitoring with on-chain checkpoints
- Missing multiple consecutive reshares triggers availability violation
- Accumulated violations lead to ejection

**Slashing Threshold**: Missing 5 consecutive reshares
**Penalty**: 0.05 ETH per missed reshare + ejection after 10 misses

### Slashing Configuration

**Penalty Structure**:

| Violation Type | First Offense | Threshold | Escalation |
|---------------|---------------|-----------|------------|
| Invalid Share | Warning | 3 reports | 0.1 ETH → 0.2 ETH → 0.4 ETH |
| Equivocation | 1 ETH | 1 proof | Immediate ejection consideration |
| Commitment Inconsistency | 0.5 ETH | 1 proof | Monitor for pattern |
| Non-Participation | 0.05 ETH/miss | 5 misses | Ejection after 10 |

**Escalation Policy**:
- First fraud in session: Base penalty
- Second fraud in session: 2× penalty
- Fraud in 3+ sessions: Automatic ejection from operator set

**Ejection Triggers**:
- Equivocation (single proof)
- 3+ different fraud types across sessions
- Total penalties > 5 ETH
- Non-participation for 10 consecutive intervals

### Economic Game Theory

**Attack Cost-Benefit Analysis** (for bias attack):

**Costs**:
- Minimum 2 operators required (2× stake at risk)
- Slashing if fraud detected: 0.1-1 ETH per operator
- Ejection permanently loses future rewards
- Reputation damage (publicly visible fraud proofs)

**Benefits**:
- ~1 bit of bias in key distribution
- No direct financial gain (keys still secure)
- Applications unaffected (keys functionally random)

**Conclusion**: Economically irrational (cost >> benefit)

### Fraud Proof Submission Process

**Operator Side**:
1. Detect violation during protocol execution
2. Collect cryptographic evidence (signatures, commitments, shares)
3. Construct fraud proof struct with all evidence
4. Submit transaction to `EigenKMSSlashing` contract
5. Monitor for slashing event confirmation

**Contract Side**:
1. Receive fraud proof via transaction
2. Verify reporter is in operator set (authorized)
3. Verify all signatures (commitment sig, share sig)
4. Execute verification equation on-chain (BLS12-381 operations)
5. If verified, increment fraud counter for dealer
6. Trigger slashing if threshold reached
7. Emit events for monitoring and transparency

**Security Considerations**:
- **False Accusations**: Cryptographic verification prevents false positives
- **Collusion**: Multiple independent reporters required for threshold
- **Griefing**: False accusers can be counter-slashed
- **Frontrunning**: Fraud proofs processed in submission order

See `docs/003_fraudProofs.md` for detailed implementation specification.

## Key Management

### KeyShareVersion Structure

```go
type KeyShareVersion struct {
    Version        uint64          // Block number when DKG/reshare occurred
    PrivateShare   *fr.Element     // This operator's secret share
    Commitments    []G2Point       // Polynomial commitments (public)
    IsActive       bool            // Currently used for signing
    ParticipantIDs []int           // Operator node IDs in this version
    CreatedAt      time.Time       // Local creation timestamp
}
```

**Version Semantics:**
- `Version`: Block number when DKG/reshare was triggered
- Serves as epoch identifier for block-based key lookups
- Globally consistent across all operators (blockchain consensus)

**Storage Interface**:

```go
type KeyStore struct {
    mu            sync.RWMutex
    keyVersions   map[uint64]*KeyShareVersion  // blockNumber → KeyShareVersion
    activeVersion uint64                        // Currently active block version
}

// Core operations
StoreKeyShareVersion(version *KeyShareVersion) → error
GetActiveKeyShare() → *KeyShareVersion
GetKeyVersionAtBlock(blockNumber uint64) → *KeyShareVersion
ListVersions() → []uint64
```

**Key Operations**:
- `StoreKeyShareVersion`: Stores new version, marks previous as inactive
- `GetActiveKeyShare`: Returns currently active key share
- `GetKeyVersionAtBlock`: Finds appropriate version for attestation block number

### Version Lifecycle

```
Lifecycle (Mainnet Example):

Genesis (block 18,000,000):
  │
  ├─→ DKG execution
  │   Version: 18000000 (trigger block number)
  │   IsActive: true
  │
Interval 1 (block 18,000,050):
  │
  ├─→ Reshare execution
  │   Version: 18000050
  │   IsActive: true
  │   Previous version (18000000) marked IsActive: false
  │
Interval 2 (block 18,000,100):
  │
  ├─→ Reshare execution
  │   Version: 18000100
  │   IsActive: true
  │   Previous version (18000050) marked IsActive: false
  │
Historical Lookups:
  │
  ├─→ App requests signature with attestationBlock = 18000025
  │   GetKeyVersionAtBlock(18000025) → version 18000000
  │
  └─→ App requests signature with attestationBlock = 18000075
      GetKeyVersionAtBlock(18000075) → version 18000050
```

### Block-Based Key Lookup

**Use Case**: TEE applications with attestation block numbers

**Lookup Algorithm**:

```
GetKeyVersionAtBlock(attestationBlock uint64) → KeyShareVersion:
  1. Compute version block: versionBlock = (attestationBlock / interval) × interval
  2. Lookup keyVersions[versionBlock]
  3. If not found, find latest version where version ≤ attestationBlock
  4. Return version or nil if none exists
```

**Attestation Block Semantics:**

```
Example (Mainnet, 50-block intervals):
  - DKG at block 18,000,000, active until block 18,000,050
  - Reshare at block 18,000,050, new keys active
  - TEE application started at block 18,000,025, generates attestation

Application request:
  {
    "appID": "my-app",
    "attestationBlock": 18000025  // Block when TEE started
  }

Operator lookup:
  - Computes: versionBlock = (18000025 / 50) × 50 = 18000000
  - Looks up key version at block 18000000
  - Generates partial signature with that version's share
  - Returns signature with version=18000000

Client aggregation:
  - Collects partial signatures from threshold operators
  - All should have version=18000000 for attestationBlock=18000025
  - Aggregates to recover app private key from v18000000 master key
  - Decrypts secrets with that key
```

### Master Public Key Computation

The master public key is derived from the constant term of all commitments:

```go
// Compute master public key from commitments
func ComputeMasterPublicKey(
    commitmentSets [][]G2Point,  // From all operators
) (*G2Point, error) {
    // All operators should have same constant term (master public key)
    masterPubKey := new(bls12381.G2Affine).SetInfinity()

    // Sum all constant terms (commitment[0] from each operator)
    for _, commitments := range commitmentSets {
        if len(commitments) == 0 {
            continue
        }
        masterPubKey.Add(masterPubKey, &commitments[0])
    }

    return masterPubKey, nil
}
```

**Property**: Constant term Σ(C₀ᵢ) = Σ(f_i(0)·G₂) = S·G₂ where S is master secret

### Key Share Persistence

**Current State**: In-memory storage (ephemeral, lost on node restart)
**Production Requirement**: Durable persistence with encryption at rest

#### Persistence Interface

The system defines a pluggable persistence interface supporting multiple storage backends:

```
KeySharePersistence interface:
  Store(version KeyShareVersion) → error
  LoadActive() → (KeyShareVersion, error)
  LoadAtTime(timestamp int64) → (KeyShareVersion, error)
  ListVersions() → ([]int64, error)
  Prune(retentionPeriod time.Duration) → error
```

#### Design Requirements

1. **Encryption at Rest**: All key shares encrypted using operator-derived encryption key
   - Key derivation: `HKDF-SHA256(operatorBN254PrivateKey, "kms-keyshare-encryption")`
   - Encryption: AES-256-GCM (authenticated encryption)
   - Key rotation: Supported via re-encryption with new derived key

2. **Atomic Operations**: Prevent partial state corruption during failures
   - Transactional writes required (all-or-nothing semantics)
   - Crash recovery to consistent state
   - No torn writes visible to readers

3. **Version History**: Configurable retention period for historical key lookups
   - Default retention: 30 days (TEE attestation time validation)
   - Configurable per deployment needs
   - Automatic pruning of expired versions

4. **Performance**: Fast lookups by version timestamp
   - O(log n) or O(1) lookup by version
   - Index on `isActive` for active version queries
   - Index on `createdAt` for time-based queries

5. **Backup and Recovery**: Support for encrypted backups
   - Export encrypted key versions
   - Import on operator migration
   - Verify integrity post-import

#### Candidate Storage Backends

**BadgerDB** (Embedded LSM Key-Value Store):
- **Pros**: Pure Go, ACID transactions, fast lookups, built-in encryption
- **Cons**: Single-writer limitation, periodic compaction needed
- **Use Case**: Default recommendation for most deployments
- **Performance**: Microsecond latencies, handles high throughput

**SQLite** (Embedded Relational Database):
- **Pros**: SQL queries, widely understood, excellent tooling, ACID guarantees
- **Cons**: Write performance lower than BadgerDB for high-throughput workloads
- **Use Case**: Operators preferring SQL for operational queries/debugging
- **Performance**: Millisecond latencies, sufficient for KMS use case

**PostgreSQL/MySQL** (External RDBMS):
- **Pros**: Enterprise features, replication, point-in-time recovery
- **Cons**: External dependency, network latency, operational complexity
- **Use Case**: Enterprise deployments with existing database infrastructure
- **Performance**: Network RTT dependent

**External KMS** (Vault, AWS KMS, GCP KMS):
- **Pros**: Centralized key management, audit logging, compliance features
- **Cons**: External dependency, higher latency, cost per operation
- **Use Case**: Regulated industries requiring HSM-backed key storage
- **Performance**: 10-100ms per operation (API calls)

## Application Integration (Encrypt/Decrypt Flow)

### Encryption Workflow

Applications encrypt secrets using the master public key derived from operator commitments:

```
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: Discover Operators                                      │
│                                                                  │
│ Client queries blockchain or uses hardcoded list:               │
│   operators = GetOperatorSetMembers(avsAddress, operatorSetID)  │
│   endpoints = [op.SocketAddress for op in operators]            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: Collect Public Key Commitments                          │
│                                                                  │
│ for endpoint in endpoints:                                       │
│     response = GET endpoint/pubkey                               │
│     commitments.append(response.commitments)                     │
│                                                                  │
│ Aggregate constant terms:                                        │
│   masterPubKey = Σ(commitments[i][0]) for all i                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: Identity-Based Encryption                               │
│                                                                  │
│ Q = HashToG1(appID)  // Hash app ID to G1 point                 │
│                                                                  │
│ Derive encryption key:                                           │
│   e_key = Pairing(Q, masterPubKey)  // Pairing to GT            │
│                                                                  │
│ Encrypt plaintext:                                               │
│   ciphertext = AES_GCM_Encrypt(e_key, plaintext)                 │
│                                                                  │
│ Store ciphertext (database, file, etc.)                          │
└─────────────────────────────────────────────────────────────────┘
```

**CLI Example:**

```bash
# Encrypt application secrets
./bin/kms-client \
  --avs-address "0xAVS..." \
  --operator-set-id 0 \
  --rpc-url "https://sepolia.infura.io/v3/..." \
  encrypt \
    --app-id "my-app-production" \
    --data "DATABASE_PASSWORD=secret123;API_KEY=key456" \
    --output encrypted_secrets.bin

# Output:
# Master public key retrieved from 7 operators
# Encrypted 45 bytes → 128 bytes (with nonce/tag)
# Saved to encrypted_secrets.bin
```

### Decryption Workflow

Applications decrypt secrets by collecting threshold partial signatures to recover the app private key:

```
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: Collect Partial Signatures                              │
│                                                                  │
│ partialSigs = []                                                 │
│ threshold = ⌈2n/3⌉                                               │
│                                                                  │
│ for endpoint in endpoints:                                       │
│     response = POST endpoint/app/sign                            │
│                  Body: {"appID": "my-app",                       │
│                         "attestationTime": 1640995200}           │
│     partialSigs.append(response.partialSignature)                │
│     if len(partialSigs) >= threshold:                            │
│         break  // Have enough signatures                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: Recover Application Private Key (Lagrange)              │
│                                                                  │
│ Compute Lagrange coefficients:                                   │
│   λᵢ = Π((0 - j)/(i - j)) for all j ∈ signers, j ≠ i            │
│                                                                  │
│ Aggregate partial signatures:                                    │
│   sk_app = Σ(λᵢ · partialSig_i) for all i                       │
│                                                                  │
│ This is the application private key: H₁(appID)^S                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: Decrypt Ciphertext                                       │
│                                                                  │
│ Derive decryption key:                                           │
│   d_key = sk_app  // Application private key                     │
│                                                                  │
│ Decrypt:                                                          │
│   plaintext = AES_GCM_Decrypt(d_key, ciphertext)                 │
│                                                                  │
│ Use plaintext (environment variables, config, etc.)              │
└─────────────────────────────────────────────────────────────────┘
```

**CLI Example:**

```bash
# Decrypt application secrets
./bin/kms-client \
  --avs-address "0xAVS..." \
  --operator-set-id 0 \
  --rpc-url "https://sepolia.infura.io/v3/..." \
  decrypt \
    --app-id "my-app-production" \
    --encrypted-data encrypted_secrets.bin

# Output:
# Collected 7 partial signatures (threshold: 5)
# Recovered application private key
# Decrypted 128 bytes → 45 bytes
# Plaintext:
# DATABASE_PASSWORD=secret123
# API_KEY=key456
```

### TEE Integration (Intel TDX) - EigenX Platform

For EigenX TEE-based applications, the system provides deterministic wallet generation and attestation-verified secret delivery. This is the **primary use case** for the distributed KMS.

#### Deterministic Mnemonic Generation

The KMS generates wallet mnemonics deterministically using HMAC-based key derivation:

```go
// Generate deterministic mnemonic for an application
func GenerateDeterministicMnemonic(
    masterSecret *fr.Element,  // From threshold DKG
    appID string,              // Application identifier from blockchain
) (string, error) {
    // Derive deterministic seed using HMAC
    h := hmac.New(sha256.New, masterSecret.Bytes())
    h.Write([]byte(appID))
    seed := h.Sum(nil)

    // Generate BIP-39 mnemonic from seed
    entropy := seed[:16]  // 128 bits → 12 words
    mnemonic, err := bip39.NewMnemonic(entropy)
    if err != nil {
        return "", err
    }

    return mnemonic, nil
}
```

**Properties:**
1. **Deterministic**: Same appID always produces same mnemonic
2. **Unpredictable**: Without master secret, cannot predict mnemonics
3. **Threshold Protected**: Requires ⌈2n/3⌉ operators to generate
4. **Isolated**: Each app gets unique mnemonic even with identical code

**Threshold Generation Flow:**

Since mnemonic generation requires the master secret (which no single operator has), the system uses threshold techniques:

```
Option 1: Partial HMAC (Current Design)
  Each operator i computes: hmac_i = HMAC(share_i, appID)
  Aggregate using Lagrange: mnemonic = Σ(λ_i · hmac_i)

Option 2: Threshold Signature (Alternative)
  Use partial signatures on appID as in IBE decrypt flow
  Convert recovered signature to mnemonic seed

Current implementation uses Option 2 (reuses IBE infrastructure)
```

---

#### Intel TDX Attestation Verification

**Attestation Service**: Intel Trust Authority (cloud-based) or Intel DCAP libraries (self-hosted verification)

**Verification API Integration**:

KMS operators use **Intel Trust Authority API** for production attestation verification:

```
Attestation Request Flow:
  1. TEE generates TDX quote via tdx-attest library
  2. KMS receives quote in /secrets request
  3. KMS calls Intel Trust Authority API:

     POST https://api.trustauthority.intel.com/appraisal/v2/attest
     Headers:
       Authorization: Bearer <intel-api-key>
       Content-Type: application/json
     Body:
       {
         "quote": "<base64-encoded-tdx-quote>",
         "runtime_data": "<nonce-or-ephemeral-key-hash>",
         "policy_ids": ["<app-specific-policy-id>"]
       }

     Response:
       {
         "token": "<jwt-attestation-token>",
         "verification_result": "SUCCESS",
         "tcb_status": "UpToDate",
         "tdx_module_identity": {...},
         "measurements": {
           "rtmr0": "<hash-of-code>",
           "rtmr1": "<hash-of-config>",
           "rtmr2": "<reserved>",
           "rtmr3": "<reserved>"
         }
       }

  4. KMS verifies JWT signature (Intel signing key)
  5. KMS validates TCB status is "UpToDate"
  6. KMS checks RTMR0 against expected image digest from blockchain
  7. If all checks pass, generate and return partial signature
```

**Alternative (Self-Hosted)**: Intel DCAP libraries
- Requires local provisioning of Intel attestation certificates
- Lower latency (no external API call)
- Higher operational complexity (certificate management)
- Suitable for airgapped or high-security deployments

**Security Properties**:
- **Hardware Root of Trust**: Attestation signed by Intel CPU hardware keys
- **Freshness**: Nonce in quote prevents replay attacks
- **Code Binding**: RTMR0 cryptographically ties quote to running code
- **TCB Validation**: Ensures firmware/microcode up-to-date and unrevoked

---

#### Complete TEE Integration Flow

```
TEE Application (Intel TDX)          KMS Operators (≥ ⌈2n/3⌉)          Blockchain
        │                                      │                           │
        │ 1. Generate attestation              │                           │
        │    - TDX quote (proves hardware)     │                           │
        │    - Ephemeral RSA key pair          │                           │
        │                                      │                           │
        │ 2. Request secrets                   │                           │
        ├─────────POST /secrets────────────────→│                           │
        │    {appID, attestation, rsaPubKey}   │                           │
        │                                      │                           │
        │                                      │ 3. Query image digest     │
        │                                      ├──────────────────────────→│
        │                                      │←──────imageDigest─────────│
        │                                      │                           │
        │                                      │ 4. Verify attestation:    │
        │                                      │    - Call Intel API       │
        │                                      │    - Check TCB status     │
        │                                      │    - Validate RTMR0       │
        │                                      │    - Match image digest   │
        │                                      │                           │
        │                                      │ 5. Generate partial sig   │
        │                                      │    σᵢ = H(appID)^(xᵢ)     │
        │                                      │                           │
        │                                      │ 6. Encrypt with RSA       │
        │                                      │    enc = RSA(σᵢ, pubKey)  │
        │                                      │                           │
        │←────encrypted partial sig────────────│                           │
        │                                      │                           │
        │ 7. Collect threshold sigs            │                           │
        │    (repeat for ⌈2n/3⌉ operators)     │                           │
        │                                      │                           │
        │ 8. Decrypt with ephemeral RSA        │                           │
        │    σᵢ = RSA_decrypt(enc)             │                           │
        │                                      │                           │
        │ 9. Recover mnemonic                  │                           │
        │    sk = Σ(λᵢ · σᵢ) [Lagrange]       │                           │
        │    mnemonic = derive(sk)             │                           │
        │                                      │                           │
        │ 10. Inject MNEMONIC env var          │                           │
        │     Start application container      │                           │
```

**Operator Verification Steps**:
1. Parse TDX attestation quote from request
2. Call Intel Trust Authority API to verify quote signature and freshness
3. Extract RTMR measurements from verified quote
4. Query blockchain for expected image digest (by appID)
5. Verify `RTMR0 == keccak256(expectedImageDigest)`
6. Verify TCB status is "UpToDate" (no revoked firmware)
7. If all checks pass, generate partial signature for mnemonic derivation
8. Encrypt partial signature with TEE's ephemeral RSA public key
9. Return encrypted response to TEE

**Security Properties**:
- **Attestation Verification**: Only authentic Intel TDX hardware instances receive secrets
- **Code Binding**: RTMR0 measurement ensures only authorized code executes
- **Image Authorization**: Blockchain check ensures only approved Docker images run
- **Ephemeral Encryption**: RSA key used once, discarded after mnemonic recovery
- **Threshold Security**: No single operator can generate mnemonic alone

## Monitoring and Observability

### Overview

The KMS implements comprehensive monitoring using Prometheus metrics and OpenTelemetry distributed tracing to provide operational visibility into protocol health, performance, and security events.

### Prometheus Metrics

**Protocol Health Metrics**:

```
# DKG Protocol
kms_dkg_executions_total{status="success|failure|timeout"}
  - Counter: Total DKG executions by outcome
  - Labels: status, trigger_block

kms_dkg_duration_seconds{phase="share_distribution|verification|finalization"}
  - Histogram: Duration of each DKG phase
  - Buckets: [0.1, 0.5, 1, 5, 10, 30, 60, 120]

kms_dkg_shares_received_total{dealer_address}
  - Counter: Total shares received per dealer
  - Labels: dealer_address, session_block

kms_dkg_shares_verified_total{dealer_address, valid="true|false"}
  - Counter: Share verification outcomes
  - Labels: dealer_address, valid, session_block

kms_dkg_acknowledgements_sent_total{dealer_address}
  - Counter: Acknowledgements sent to dealers
  - Labels: dealer_address, session_block

# Reshare Protocol
kms_reshare_executions_total{status="success|failure|timeout"}
  - Counter: Total reshare executions by outcome
  - Labels: status, trigger_block, operator_set_change="true|false"

kms_reshare_duration_seconds{phase}
  - Histogram: Duration of each reshare phase
  - Buckets: [0.1, 0.5, 1, 5, 10, 30, 60, 120]

kms_reshare_operator_count
  - Gauge: Number of operators in current reshare
  - Labels: session_block

kms_reshare_threshold
  - Gauge: Current threshold (⌈2n/3⌉)
  - Labels: session_block

# Key Management
kms_active_key_version
  - Gauge: Current active key version (block number)

kms_key_versions_total
  - Gauge: Total key versions stored

kms_last_successful_reshare_block
  - Gauge: Block number of last successful reshare
```

**Application Request Metrics**:

```
# Application Signing
kms_app_sign_requests_total{app_id, status="success|failure"}
  - Counter: Application signature requests
  - Labels: app_id, status

kms_app_sign_duration_seconds
  - Histogram: Latency to serve signature requests
  - Buckets: [0.01, 0.05, 0.1, 0.5, 1, 5]

kms_app_sign_key_version{app_id}
  - Gauge: Key version used for app signature
  - Labels: app_id

# TEE Secret Delivery
kms_tee_secrets_requests_total{app_id, status="success|attestation_failed|image_mismatch"}
  - Counter: TEE secret requests by outcome
  - Labels: app_id, status

kms_tee_attestation_verification_duration_seconds
  - Histogram: Intel Trust Authority API call latency
  - Buckets: [0.1, 0.5, 1, 2, 5, 10]

kms_tee_image_digest_matches_total{app_id, match="true|false"}
  - Counter: Image digest validation outcomes
  - Labels: app_id, match
```

**Fraud Detection Metrics**:

```
# Fraud Proofs
kms_fraud_detected_total{fraud_type, dealer_address}
  - Counter: Fraud detections by type
  - Labels: fraud_type=["invalid_share", "equivocation", "commitment_inconsistency"]
  - Labels: dealer_address, session_block

kms_fraud_proofs_submitted_total{fraud_type, status="success|failure"}
  - Counter: Fraud proof submissions to slashing contract
  - Labels: fraud_type, status

kms_operators_slashed_total{reason}
  - Counter: Operators slashed
  - Labels: reason, slashed_address

# P2P Communication
kms_p2p_messages_sent_total{message_type, recipient_address}
  - Counter: P2P messages sent
  - Labels: message_type=["share", "commitment", "ack"], recipient_address

kms_p2p_messages_received_total{message_type, sender_address, auth_valid="true|false"}
  - Counter: P2P messages received
  - Labels: message_type, sender_address, auth_valid

kms_p2p_signature_verification_failures_total{sender_address}
  - Counter: BN254 signature verification failures
  - Labels: sender_address
```

**System Health Metrics**:

```
kms_operator_active{operator_address}
  - Gauge: 1 if operator in current set, 0 otherwise
  - Labels: operator_address

kms_blockchain_latest_finalized_block
  - Gauge: Latest finalized block number seen

kms_blockchain_rpc_errors_total{rpc_url, method}
  - Counter: Blockchain RPC errors
  - Labels: rpc_url, method=["eth_getBlockByNumber", "eth_call"]

kms_uptime_seconds
  - Counter: Node uptime in seconds
```

---

### OpenTelemetry Distributed Tracing

**Trace Context Propagation**:

All protocol messages include OpenTelemetry trace context for end-to-end visibility:

```
AuthenticatedMessage {
    payload: []byte
    hash: [32]byte
    signature: []byte
    traceContext: {          // OpenTelemetry context
        traceID: string
        spanID: string
        traceFlags: byte
    }
}
```

**Traced Operations**:

1. **DKG Execution Trace**:
```
Span: dkg.execution (root)
  ├─ Span: dkg.generate_shares
  ├─ Span: dkg.broadcast_commitments
  ├─ Span: dkg.send_shares (parallel spans, one per recipient)
  ├─ Span: dkg.wait_for_shares
  ├─ Span: dkg.verify_shares (parallel spans, one per dealer)
  ├─ Span: dkg.send_acknowledgements (parallel spans)
  ├─ Span: dkg.wait_for_acknowledgements
  └─ Span: dkg.finalize

Attributes:
  - session_block: uint64
  - operator_count: int
  - threshold: int
  - operator_address: string
```

2. **Reshare Execution Trace**:
```
Span: reshare.execution (root)
  ├─ Span: reshare.load_current_share
  ├─ Span: reshare.generate_reshare_polynomial
  ├─ Span: reshare.broadcast_commitments
  ├─ Span: reshare.send_shares
  ├─ Span: reshare.wait_for_shares
  ├─ Span: reshare.verify_shares
  ├─ Span: reshare.compute_lagrange_coefficients
  ├─ Span: reshare.compute_new_share
  └─ Span: reshare.store_key_version

Attributes:
  - session_block: uint64
  - operator_role: "existing|new"
  - previous_version: uint64
  - new_version: uint64
```

3. **Application Sign Request Trace**:
```
Span: app.sign_request (root)
  ├─ Span: app.parse_request
  ├─ Span: app.lookup_key_version
  │   └─ Attribute: attestation_block, resolved_version
  ├─ Span: app.generate_partial_signature
  └─ Span: app.encode_response

Attributes:
  - app_id: string
  - attestation_block: uint64
  - key_version: uint64
  - operator_address: string
```

4. **TEE Secret Delivery Trace**:
```
Span: tee.secrets_delivery (root)
  ├─ Span: tee.parse_attestation
  ├─ Span: tee.verify_intel_quote
  │   └─ Span: intel_api.verify_quote (external call)
  ├─ Span: tee.query_image_digest (blockchain call)
  ├─ Span: tee.validate_rtmr
  ├─ Span: tee.lookup_key_version
  ├─ Span: tee.generate_partial_signature
  ├─ Span: tee.encrypt_with_ephemeral_rsa
  └─ Span: tee.encode_response

Attributes:
  - app_id: string
  - attestation_block: uint64
  - rtmr0: string (hex)
  - expected_image_digest: string
  - image_match: bool
```

**Trace Sampling**:
- **Protocol Traces**: 100% (always trace DKG/Reshare for debugging)
- **Application Requests**: 10% (sample to reduce overhead)
- **Health Checks**: 0% (no tracing for health endpoint)

**Trace Export**:
- Export to OpenTelemetry Collector
- Backends: Jaeger, Zipkin, or cloud providers (Honeycomb, Datadog, New Relic)
- Retention: 30 days for protocol traces, 7 days for app request traces

---

### Alerting Rules

**Critical Alerts** (PagerDuty, immediate response):

```yaml
# Protocol Failures
- alert: ConsecutiveReshareFailures
  expr: increase(kms_reshare_executions_total{status="failure"}[30m]) >= 3
  severity: critical
  description: "3+ reshare failures in 30 minutes"

- alert: InsufficientOperators
  expr: kms_operator_active < kms_threshold + 1
  severity: critical
  description: "Operator count below threshold+1 (no fault tolerance)"

- alert: FraudDetected
  expr: increase(kms_fraud_detected_total[5m]) > 0
  severity: critical
  description: "Protocol fraud detected and reported"

- alert: BlockchainRPCDown
  expr: rate(kms_blockchain_rpc_errors_total[5m]) > 0.5
  severity: critical
  description: "Blockchain RPC error rate > 50%"
```

**Warning Alerts** (Slack, investigate within hours):

```yaml
# Performance Degradation
- alert: HighDKGLatency
  expr: histogram_quantile(0.95, kms_dkg_duration_seconds) > 120
  severity: warning
  description: "DKG p95 latency > 2 minutes"

- alert: HighAppSignLatency
  expr: histogram_quantile(0.99, kms_app_sign_duration_seconds) > 5
  severity: warning
  description: "App signature p99 latency > 5 seconds"

# Security Events
- alert: SignatureVerificationFailures
  expr: increase(kms_p2p_signature_verification_failures_total[10m]) > 10
  severity: warning
  description: "Multiple signature verification failures (potential attack)"

- alert: ImageDigestMismatches
  expr: increase(kms_tee_image_digest_matches_total{match="false"}[10m]) > 5
  severity: warning
  description: "Multiple image digest mismatches (unauthorized code attempts)"

# Operational
- alert: MissedReshareInterval
  expr: (kms_blockchain_latest_finalized_block - kms_last_successful_reshare_block)
        > 2 * on(chain_id) reshare_interval
  severity: warning
  description: "Missed reshare interval (should trigger every 50 blocks)"
```

---

### Monitoring Dashboards

**Operator Dashboard** (Grafana):

1. **Protocol Health Panel**:
   - DKG/Reshare success rate (last 24h)
   - Current operator count vs threshold
   - Time since last successful reshare
   - Active key version (block number)

2. **Performance Panel**:
   - DKG/Reshare latency (p50, p95, p99)
   - App signature latency histogram
   - TEE attestation verification latency
   - Message throughput (messages/sec)

3. **Security Panel**:
   - Fraud detections (count by type)
   - Signature verification failure rate
   - Image digest mismatch rate
   - Slashing events timeline

4. **Blockchain Panel**:
   - Latest finalized block
   - Blocks until next reshare trigger
   - RPC error rate by endpoint
   - Operator set size over time

**Application Integration Dashboard**:

1. **App Request Panel**:
   - Requests by app_id (top 10)
   - Success rate per app
   - Latency distribution
   - Key version usage distribution

2. **TEE Attestation Panel**:
   - Attestation verification success rate
   - RTMR validation failures by app
   - Image digest match rate
   - Intel API latency

---

### Log Aggregation

**Structured Logging Format** (JSON):

```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "level": "info",
  "component": "dkg",
  "event": "share_verified",
  "session_block": 18000050,
  "dealer_address": "0x1234...",
  "operator_address": "0x5678...",
  "trace_id": "abc123...",
  "span_id": "def456..."
}
```

**Key Events to Log**:

- **Protocol Events**: DKG/Reshare start, phase transitions, completion
- **Security Events**: Fraud detection, signature failures, slashing submissions
- **Application Events**: Signature requests, attestation verifications, key deliveries
- **System Events**: Operator set changes, block triggers, RPC errors

**Log Aggregation**:
- Export to: Loki, Elasticsearch, or cloud providers (CloudWatch, Stackdriver)
- Retention: 90 days for security events, 30 days for operational logs
- Correlation: Use trace_id to link logs across operators

---

### Operational Runbooks

**Runbook 1: Reshare Failure**

**Symptoms**: `kms_reshare_executions_total{status="failure"}` incrementing

**Investigation**:
1. Check operator logs for errors during reshare
2. Verify all operators in current set are reachable
3. Check blockchain RPC connectivity
4. Review trace for failed reshare session
5. Validate operator set matches on-chain state

**Resolution**:
- If < t operators responsive: Scale up operators or wait for recovery
- If operator set mismatch: Restart operators to refresh peering data
- If network partition: Wait for next interval (automatic retry)

---

**Runbook 2: Fraud Detected**

**Symptoms**: `kms_fraud_detected_total` increments

**Investigation**:
1. Identify fraud type and dealer address from metrics
2. Review logs for fraud detection event details
3. Check if fraud proof submitted successfully
4. Verify slashing contract state (fraud counter incremented)
5. Investigate dealer's recent protocol participation

**Resolution**:
- Monitor for threshold fraud count (automatic slashing)
- If repeated violations: Coordinate operator ejection via governance
- Document incident for post-mortem analysis

---

**Runbook 3: High Application Signature Latency**

**Symptoms**: `kms_app_sign_duration_seconds` p99 > 5 seconds

**Investigation**:
1. Check operator CPU/memory utilization
2. Review keystore lookup performance
3. Check for disk I/O bottlenecks (if persistence enabled)
4. Analyze concurrent request patterns
5. Review traces for slow spans

**Resolution**:
- Scale operator resources (CPU, memory)
- Optimize keystore implementation (caching)
- Add rate limiting if request volume excessive
- Investigate slow cryptographic operations

## Implementation Timeline

### Phase 1: Alpha Testnet with Feldman-VSS

**Milestone**: Alpha testnet ready with Feldman-VSS, basic fraud detection, and persistence

**Target Date**: November 7, 2024

**Duration**: ~2 weeks (from current state)

**Objectives**:
- [ ] Migrate from time-based to block-based scheduling
- [ ] Implement block monitoring with finalized block polling
- [ ] Update session identification and key versioning to use block numbers
- [ ] Basic BadgerDB persistence with encrypted key shares at rest
- [ ] Crash recovery support
- [ ] Define KeyBackend interface for pluggable key management
- [ ] Implement AWS KMS backend for operator key signing
- [ ] Support both local keys (file-based) and AWS KMS keys
- [ ] Configuration system for backend selection
- [ ] Deploy contracts to Sepolia testnet
- [ ] Basic fraud detection (invalid share detection)
- [ ] Deploy EigenKMSSlashing contract (basic version)
- [ ] Onboard 3-5 test operators (mix of local and AWS KMS keys)
- [ ] Execute genesis DKG on Sepolia
- [ ] Run continuous reshare cycles (10 blocks = ~2 min)
- [ ] Basic monitoring (Prometheus metrics)

**Deliverable**: Public alpha testnet on Sepolia with block-based coordination, persistence, and AWS KMS support

---

### Phase 2: Mainnet Beta with Pedersen-VSS

**Milestone**: Mainnet beta ready with Pedersen-VSS and audit completion

**Target Date**: December 12, 2024

**Duration**: ~5 weeks (November 7 - December 12)

**Pedersen-VSS Core Implementation**:
- [ ] Implement dual-polynomial VSS (f_i, f'_i)
- [ ] Distributed coin flip protocol for H₂ generation
- [ ] Two-phase DKG protocol (commit phase, extract phase)
- [ ] Phase 1 verification: `s·G₂ + s'·H₂ = Σ(C_k · j^k)`
- [ ] Phase 2 verification: `s·G₂ = Σ(A_k · j^k)`
- [ ] Comprehensive unit tests for Pedersen primitives
- **Deliverable**: Pedersen-VSS implementation complete

**Enhanced Fraud Proofs & Additional Key Backends**:
- [ ] Complete fraud proof system (all violation types)
- [ ] Equivocation detection and proof construction
- [ ] Commitment inconsistency detection
- [ ] On-chain verification gas optimization
- [ ] Slashing threshold configuration
- [ ] Implement GCP KMS backend
- [ ] Implement Azure Key Vault backend
- [ ] Implement HashiCorp Vault backend
- [ ] Backend integration tests (all providers)
- **Deliverable**: Production-ready fraud detection + multi-cloud key management

**Hardening and Testing**:
- [ ] Persistence testing and optimization
- [ ] Integration test suite (>90% coverage)
- [ ] Performance benchmarking (all key backends)
- [ ] Load testing with sustained reshare cycles
- [ ] Security hardening review
- **Deliverable**: Production-grade reliability

**Audit Preparation and Deployment**:
- [ ] Code freeze for audit scope
- [ ] Security-focused code review
- [ ] Threat model documentation finalization
- [ ] Deploy to mainnet beta environment
- [ ] Onboard mainnet beta operators (5-7)
- [ ] Begin external security audit
- **Deliverable**: Mainnet beta live, audit in progress (December 12)

---

### Phase 3: Mainnet Production Launch

**Milestone**: Audit complete, mainnet production ready

**Target Date**: Q1 2025 (post-audit)

**Duration**: Dependent on audit findings

**Audit Completion**:
- [ ] Address all audit findings (critical, high, medium)
- [ ] Re-audit if significant changes required
- [ ] Final security review and sign-off
- **Deliverable**: Clean audit report

**Production Launch**:
- [ ] Mainnet contract deployment (production)
- [ ] Onboard production operator set (10-15 operators)
- [ ] Execute mainnet genesis DKG
- [ ] 48-hour monitoring period (24/7 on-call)
- [ ] Public announcement and documentation
- **Deliverable**: Production KMS AVS on Ethereum mainnet

---

### Phase 4: Post-Launch and Advanced Features

**Milestone**: Stable production operation with enhanced features

**Timeline**: Q1-Q2 2025 (ongoing)

**Post-Launch Stabilization**:
- [ ] Monitor protocol health (DKG/reshare success rates)
- [ ] Track fraud proof submissions (expect zero)
- [ ] Optimize performance based on production data
- [ ] Operator feedback incorporation
- [ ] Bug fixes and minor improvements
- **Deliverable**: Stable production operation

**Advanced Features**:
- [ ] Hardware Security Module (HSM) backend support (PKCS#11)
- [ ] Cross-chain deployment (Arbitrum, Optimism, Base)
- [ ] Advanced monitoring and analytics dashboards
- [ ] Operator reputation system
- [ ] Governance mechanisms (parameter voting)
- [ ] Master secret rotation (periodic full DKG)
- **Deliverable**: Enhanced production features and multi-chain support

---

### Critical Path

```
Block-Based Scheduling (Sprint 1)
    ↓
Alpha Testnet (November 7)
    ↓
Pedersen-VSS Implementation (Weeks 1-2)
    ↓
Fraud Proofs + Persistence (Weeks 3-4)
    ↓
Mainnet Beta + Audit Start (December 12)
    ↓
Audit Completion (Q1 2025)
    ↓
Mainnet Production (Q1 2025)
```

### Resource Requirements

**Development Team**:
- 1 Lead Engineer (Sean - full time)
- 1 Smart Contract Engineer (Phase 1-2, audit period)
- 1 Security Engineer (Phase 2-3, ongoing)

**External Services**:
- Security audit firm: ~$50-80k
- Intel Trust Authority API keys (production)
- Ethereum testnet ETH (Sepolia faucet)
- Infrastructure: ~$500/month testnet, ~$2k/month mainnet (10-15 operators)

### Risk Mitigation

**High-Risk Items**:
1. **Aggressive Timeline** (November 7 - 2 weeks)
   - Mitigation: Focus on core functionality, defer non-critical features
   - Fallback: Delay alpha by 1 week if block-based migration takes longer
2. **Pedersen-VSS Implementation** (5 weeks for mainnet beta)
   - Mitigation: Parallel Feldman testnet continues during Pedersen development
   - Fallback: Launch mainnet beta with Feldman if Pedersen delayed
3. **Audit Findings** (Unknown timeline impact)
   - Mitigation: Pre-audit security review, conservative code practices
   - Contingency: Budget 2-4 weeks for addressing findings

**Contingency Plans**:
- If November 7 deadline at risk: Deploy alpha with time-based scheduling, migrate to blocks in Phase 2
- If Pedersen complexity high: Maintain Feldman with enhanced fraud proofs for mainnet beta
- If audit finds critical issues: Delay production launch, prioritize fixes, re-audit as needed

## Conclusion

The EigenX KMS AVS provides a production-grade distributed key management system built on threshold cryptography, EigenLayer's restaking infrastructure, and rigorous security principles. The system achieves Byzantine fault tolerance, automatic key rotation, and identity-based encryption while maintaining strong security guarantees and operational simplicity for application developers.

# Appendix

## Commonware vs. Go Libraries: Implementation Decision

During the initial design phase of EigenX KMS, a key decision was made to implement the system in **Go using native cryptographic libraries** rather than **Rust with Commonware**. This appendix documents the reasoning behind this architectural choice.

### Technology Options

**Option 1: Rust + Commonware**
- **Commonware**: A Rust-based framework for building distributed applications with native support for consensus, networking, and cryptographic protocols
- **Benefits**: Purpose-built for distributed systems, strong memory safety guarantees, growing ecosystem
- **Challenges**: Requires Rust expertise, less mature tooling for threshold cryptography

**Option 2: Go + Native Libraries**
- **gnark-crypto**: Production-grade elliptic curve cryptography library by Consensys
- **Hourglass/Sidecar Code Reuse**: Leverage audited code from EigenLayer's Hourglass framework and Sidecar
- **Benefits**: Excellent library support, team expertise, mature ecosystem, proven patterns
- **Challenges**: Manual threshold cryptography protocol implementation required

### Decision: Go + Native Libraries

**Primary Factors:**

1. **Team Expertise and Development Velocity**
   - **Sean (Lead Developer)**: Expert-level Go experience, limited Rust experience
   - **Development Velocity**: Immediate productivity vs. learning curve
   - **Debugging Efficiency**: Familiar tooling and debugging workflows
   - **Code Review**: Easier review process with team's Go background

   **Impact**: Estimated 3-4x faster development time with Go vs. learning Rust + Commonware

2. **Go's Design for This Use Case**
   - **Network/Async Heavy**: Go designed for concurrent network services (goroutines, channels)
   - **Service APIs**: Standard library excels at HTTP servers and REST APIs
   - **Container Deployment**: Optimized for Linux runtime environments
   - **"Batteries Included"**: Standard library handles most backend service needs without external dependencies
   - **Build Philosophy**: Go encourages building directly rather than composing complex library stacks

   **Perfect Fit**: KMS is exactly the type of distributed network service Go was designed for

3. **Cryptographic Library Maturity: gnark-crypto**
   - **Battle-Tested**: Used in production by major projects (Polygon zkEVM, Scroll, Linea)
   - **Audit Status**: Extensively audited by Trail of Bits, Consensys Diligence, and others
   - **BLS12-381 Support**: Complete implementation with pairing operations
   - **BN254 Support**: Native EigenLayer-compatible curve
   - **Performance**: Highly optimized assembly implementations for critical operations
   - **Documentation**: Comprehensive docs and examples

   **Commonware Status** (at decision time):
   - Emerging library with less battle-testing
   - **No security audits** (major concern for cryptographic systems)
   - Growing but less comprehensive documentation

4. **Proven EigenLayer Patterns via Code Reuse**
   - **Hourglass Framework**: Reuse audited code for protocol integration, operator peering, KeyRegistrar interaction
   - **Sidecar**: Battle-tested block indexing logic for monitoring blockchain state
   - **Both Audited**: Security-reviewed code provides solid foundation
   - **Established Patterns**: Proven approaches for AVS development

   **Benefit**: Building on audited, production-tested code rather than starting from scratch

5. **Development Ecosystem**
   - **Go Benefits**:
     - Mature testing frameworks (testify, mock, integration test patterns)
     - Rich HTTP ecosystem (net/http standard library)
     - Excellent profiling and debugging tools (pprof, delve)
     - Fast compilation times (sub-second rebuilds)
     - Simple dependency management (go modules)
     - Garbage collection appropriate for service workloads

   - **Rust Tradeoffs**:
     - Longer compilation times (impacts iteration speed)
     - More complex dependency resolution
     - Steeper learning curve for contributors

### Implementation Requirements (Language-Agnostic)

Regardless of language choice, the following would need to be implemented:

**Threshold Cryptography Protocols**:
- Pedersen/Feldman VSS implementation
- Share verification logic
- Lagrange interpolation for recovery
- Polynomial commitment schemes

**Note**: Limited prior art exists for production threshold cryptography in either Go or Rust. However, Go has more reference implementations in adjacent domains (distributed systems, cryptographic services).

---

### Technical Trade-offs

**By choosing Go:**

**Accepted Limitations**:
- Manual threshold protocol implementation (no existing framework)
- However: Same requirement for Rust/Commonware (no threshold crypto support)

**Benefits Gained**:

1. **Faster Time-to-Market**: 1-3 month timeline vs. estimated 3-5 months with Rust learning curve
2. **Code Confidence**: Deep understanding of Go idioms and pitfalls
3. **Library Confidence**: gnark-crypto's extensive audit trail and production usage
4. **Audited Code Reuse**: Hourglass (protocol integration) and Sidecar (block indexing) already security-reviewed
5. **Team Scalability**: Easier to onboard future Go developers than Rust experts
6. **Debugging Efficiency**: Familiar tools significantly reduce bug investigation time
7. **No Audit Debt**: Commonware lacks security audits (critical gap for crypto systems)

### Architectural Validation

**Indicators this was the right choice:**

1. **Rapid Prototyping**: Proof-of-concept completed in 2-3 days
2. **Integration Success**: EigenLayer integration leveraged existing Hourglass/Sidecar patterns
3. **Testing Coverage**: Comprehensive integration tests with testutil patterns
4. **Performance**: Threshold cryptography operations complete in acceptable timeframes:
   - DKG (7 operators): ~2-3 seconds
   - Reshare (7 operators): ~1-2 seconds
   - App signature collection: ~500-800ms

5. **Code Quality**: Maintainable, tested, reviewable codebase with clear separation of concerns

### Conclusion

The decision to use **Go with gnark-crypto and Hourglass/Sidecar patterns** was driven by:
- Team expertise and development velocity
- Production-ready, audited cryptographic libraries (gnark-crypto)
- Reusable audited code from Hourglass and Sidecar
- Go's design alignment with network service workloads
- "Batteries included" standard library reducing external dependencies
- Appropriate performance characteristics for the use case

While **Commonware/Rust offers compelling benefits** for consensus-heavy systems, the EigenX KMS architecture (block-based coordination + threshold cryptography) is well-served by Go's mature ecosystem, proven patterns, and the team's existing expertise. The lack of security audits for Commonware made it unsuitable for a cryptographic system requiring high assurance.
