# Distributed KMS Technical Design Document

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
┌─────────────────────────────────────────────────────────────────┐
│                      Developer Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ EigenX CLI   │  │ Docker Image │  │ App Config   │          │
│  │ (Build/Deploy│  │ Registry     │  │ (Secrets)    │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                  │                   │
└─────────┼─────────────────┼──────────────────┼───────────────────┘
          │                 │                  │
┌─────────▼─────────────────▼──────────────────▼───────────────────┐
│                       Trust Layer (Blockchain)                    │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │  EigenX Smart Contracts (Ethereum)                           ││
│  │  - App Registry: Stores authorized Docker image digests     ││
│  │  - App Configuration: Stores encrypted secrets, state       ││
│  │  - Access Control: Defines who can deploy/manage apps       ││
│  └──────────────────────────────────────────────────────────────┘│
│                                                                   │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │  KMS AVS (This System)                                       ││
│  │  - TEE Attestation Verification                              ││
│  │  - Image Digest Validation (queries blockchain)             ││
│  │  - Deterministic Mnemonic Generation: HMAC(master, appID)   ││
│  │  - Secret Delivery to Authenticated TEEs                    ││
│  └──────────────────────────────────────────────────────────────┘│
└───────────────────────────┬───────────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────────┐
│                    Automation Layer                               │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │  EigenX Coordinator                                          ││
│  │  - Watches blockchain for deployment events                  ││
│  │  - Provisions Google Cloud VMs with Intel TDX               ││
│  │  - Manages application lifecycle (start/stop/upgrade)        ││
│  │  - Monitors TEE instance health                              ││
│  └──────────────────────────────────────────────────────────────┘│
└───────────────────────────┬───────────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────────┐
│                     Execution Layer                               │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │  TEE Instance (Intel TDX on Google Cloud)                    ││
│  │                                                               ││
│  │  ┌──────────────────────────────────────────────────────┐   ││
│  │  │ Hardware-Isolated VM (Memory Encrypted)              │   ││
│  │  │                                                       │   ││
│  │  │  ┌─────────────────────────────────────────────┐    │   ││
│  │  │  │ Docker Container (Application Code)         │    │   ││
│  │  │  │                                              │    │   ││
│  │  │  │  Environment Variables:                      │    │   ││
│  │  │  │  - MNEMONIC="word1 word2 ... word12"        │    │   ││
│  │  │  │  - DB_PASSWORD="..." (from developer)       │    │   ││
│  │  │  │  - API_KEY="..." (from developer)           │    │   ││
│  │  │  │                                              │    │   ││
│  │  │  │  Application derives wallets from mnemonic: │    │   ││
│  │  │  │  - Ethereum: m/44'/60'/0'/0/0               │    │   ││
│  │  │  │  - Bitcoin: m/44'/0'/0'/0/0                 │    │   ││
│  │  │  │  - Signs transactions autonomously          │    │   ││
│  │  │  └─────────────────────────────────────────────┘    │   ││
│  │  │                                                       │   ││
│  │  │  Host OS CANNOT access memory (Intel TDX)            │   ││
│  │  └──────────────────────────────────────────────────────┘   ││
│  └──────────────────────────────────────────────────────────────┘│
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

From an application developer's perspective using EigenX:

```go
// Inside TEE container (developers write this code)
package main

import (
    "os"
    "github.com/tyler-smith/go-bip39"
    "github.com/tyler-smith/go-bip32"
)

func main() {
    // KMS injects this via environment variable
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
1. No key management code required
2. Deterministic identity (can publish addresses, receive funds)
3. Hardware isolation (keys never leave TEE)
4. Automatic secret injection (database passwords, API keys)
5. Multi-chain support (derive keys for any BIP-44 chain)

## Architecture Overview

### System Components

The EigenX KMS AVS is built on a modular architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Application Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ KMS Client   │  │ TEE Runtime  │  │ Web3 App     │          │
│  │ CLI Tool     │  │ (TDX/SGX)    │  │ Integration  │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                  │                   │
│         └─────────────────┴──────────────────┘                   │
│                           │                                      │
│                  HTTP API (Public Endpoints)                     │
└───────────────────────────┼──────────────────────────────────────┘
                            │
┌───────────────────────────┼──────────────────────────────────────┐
│                    KMS Node (Operator)                           │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                  HTTP Server (pkg/node)                     │ │
│  │  ┌──────────────────┐  ┌─────────────────────────────────┐ │ │
│  │  │ Protocol APIs    │  │ Application APIs                │ │ │
│  │  │ /dkg/*           │  │ /pubkey, /app/sign, /secrets    │ │ │
│  │  └──────────────────┘  └─────────────────────────────────┘ │ │
│  └───────────┬──────────────────────────┬──────────────────────┘ │
│              │                          │                        │
│  ┌───────────▼───────────┐  ┌──────────▼─────────────┐          │
│  │ Protocol Engines      │  │ Application Handler    │          │
│  │ - DKG (pkg/dkg)       │  │ - Pubkey aggregation   │          │
│  │ - Reshare             │  │ - Partial signing      │          │
│  │   (pkg/reshare)       │  │ - TEE verification     │          │
│  └───────────┬───────────┘  └────────────────────────┘          │
│              │                                                    │
│  ┌───────────▼──────────────────────────────────────┐           │
│  │         Transport Layer (pkg/transport)          │           │
│  │  - Message signing/verification (BN254)          │           │
│  │  - Authenticated message wrapping                │           │
│  │  - HTTP client with retry logic                  │           │
│  └───────────┬──────────────────────────────────────┘           │
│              │                                                    │
│  ┌───────────▼──────────────────────────────────────┐           │
│  │    Cryptographic Operations (pkg/crypto)         │           │
│  │  - BLS12-381: threshold sigs, DKG (pkg/bls)      │           │
│  │  - BN254: message authentication                 │           │
│  │  - IBE: encryption/decryption                    │           │
│  │  - Share verification & Lagrange interpolation   │           │
│  └──────────────────────────────────────────────────┘           │
│                                                                   │
│  ┌──────────────────────────────────────────────────┐           │
│  │      Key Management (pkg/keystore)               │           │
│  │  - Versioned key share storage                   │           │
│  │  - Active/historical version tracking            │           │
│  │  - Time-based key lookup                         │           │
│  └──────────────────────────────────────────────────┘           │
│                                                                   │
│  ┌──────────────────────────────────────────────────┐           │
│  │    Peering System (pkg/peering)                  │           │
│  │  - Operator discovery from blockchain            │           │
│  │  - Socket address resolution                     │           │
│  │  - BN254 public key retrieval                    │           │
│  └───────────┬──────────────────────────────────────┘           │
│              │                                                    │
└──────────────┼────────────────────────────────────────────────────┘
               │
┌──────────────▼────────────────────────────────────────────────────┐
│                    EigenLayer Protocol                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │ AVSDirectory │  │ Operator Set │  │ Key Registrar│           │
│  │              │  │ Registrar    │  │ (BN254)      │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
└───────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

**KMS Node (`pkg/node/`)**
- Main server process managing protocol execution and application requests
- Automatic scheduler for DKG/reshare protocol execution at interval boundaries
- HTTP server exposing protocol and application endpoints
- Operator identity via Ethereum address and BN254 private key
- Session management for concurrent protocol runs

**Protocol Engines**
- **DKG (`pkg/dkg/`)**: Complete distributed key generation with authenticated acknowledgements
- **Reshare (`pkg/reshare/`)**: Key rotation protocol supporting existing and new operators
- **Session State**: Per-protocol state machines with phase tracking

**Transport Layer (`pkg/transport/`)**
- Wraps all messages in `AuthenticatedMessage` structure
- Automatic signing with BN254 private key
- Verification using sender's public key from peering data
- Retry logic with exponential backoff for network resilience
- Broadcast support (zero-address recipient)

**Cryptographic Operations (`pkg/crypto/`, `pkg/bls/`)**
- **BLS12-381 Operations**:
  - Polynomial evaluation and commitment generation
  - Share verification against commitments
  - Lagrange interpolation for share recovery
  - Threshold signature aggregation
- **BN254 Operations**: Message signing and verification
- **IBE Operations**: Identity-based encryption and decryption

**Key Management (`pkg/keystore/`)**
- Versioned storage of key shares (currently in-memory)
- Active version tracking for current operations
- Historical version retention for time-based attestation
- Epoch-based versioning using session timestamps

**Peering System (`pkg/peering/`)**
- `IPeeringDataFetcher` interface for operator discovery
- Production: blockchain queries via `ContractCaller`
- Testing: local `ChainConfig` with authentic test data
- Returns `OperatorSetPeer` with address, socket, and BN254 public key

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
Scheduler (500ms loop)
    │
    ├─→ Detect interval boundary
    │
    ├─→ Fetch operators from peering system
    │
    ├─→ Determine protocol: DKG vs Reshare
    │
    └─→ Execute protocol (goroutine)
           │
           ├─→ Phase 1: Share distribution
           │   └─→ POST /dkg/share, /dkg/commitment
           │
           ├─→ Phase 2: Verification & acknowledgement
           │   └─→ POST /dkg/ack
           │
           └─→ Phase 3: Finalization
               └─→ Store KeyShareVersion
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

### Automatic Scheduling

The system uses **interval-based scheduling** to coordinate protocol execution without requiring consensus:

```go
// Scheduler loop (pkg/node/node.go)
ticker := time.NewTicker(500 * time.Millisecond)
for range ticker.C {
    now := time.Now()
    interval := getChainInterval(chainID)  // 10min, 2min, or 30sec

    // Round to interval boundary
    roundedTime := (now.Unix() / interval) * interval

    // Skip if already processed
    if processedIntervals[roundedTime] {
        continue
    }

    // Fetch current operators
    operators := peeringFetcher.GetOperators()

    // Determine protocol type
    if !hasExistingShares() {
        if clusterHasKeys() {
            runReshareAsNewOperator(roundedTime, operators)
        } else {
            runDKG(roundedTime, operators)
        }
    } else {
        runReshareAsExistingOperator(roundedTime, operators)
    }

    processedIntervals[roundedTime] = true
}
```

**Key Properties:**
- Deterministic timing eliminates need for leader election
- All operators execute simultaneously at interval boundaries
- Session timestamp (`roundedTime`) coordinates message routing
- Supports operator churn (joins/leaves detected at each interval)

### DKG Process

The Distributed Key Generation (DKG) protocol enables operators to collectively generate a shared master secret without any single operator ever knowing the complete secret. The system implements a three-phase protocol based on Pedersen's verifiable secret sharing with authenticated acknowledgements to prevent dealer equivocation.

#### Protocol Overview

```
Operator 1          Operator 2          Operator 3          ...  Operator n
    │                   │                   │                       │
    │◄──────────────────┴───────────────────┴───────────────────────┘
    │  Phase 1: Share Distribution (Broadcast + P2P)
    │
    ├─→ Generate polynomial f₁(z) with random coefficients
    │   Constant term f₁(0) is operator 1's secret contribution
    │
    ├─→ Compute commitments: C₁ = [f₁(0)·G₂, f₁(1)·G₂, ..., f₁(t-1)·G₂]
    │   Broadcast commitments to all operators
    │
    ├─→ Evaluate shares: s₁ⱼ = f₁(nodeID_j) for each operator j
    │   Send encrypted share to each operator via P2P
    │
    │◄──────────────────────────────────────────────────────────────┐
    │  Receive commitments and shares from all other operators       │
    │                                                                 │
    │◄──────────────────┬───────────────────┬────────────────────────┘
    │  Phase 2: Verification & Acknowledgement
    │
    ├─→ Verify each received share against commitments:
    │   sᵢⱼ·G₂ ?= Σ(Cᵢ[k] · nodeID_j^k) for k=0 to t-1
    │
    ├─→ Sign acknowledgement for each valid share
    │   ack_msg = {from: j, to: i, sessionTimestamp, shareHash}
    │   sig = Sign_BN254(keccak256(ack_msg))
    │
    ├─→ Send acknowledgement to dealer
    │   POST /dkg/ack with authenticated message
    │
    │◄──────────────────────────────────────────────────────────────┐
    │  Wait for ALL operators to send acknowledgements (100%)        │
    │  CRITICAL: Any missing ack aborts protocol                     │
    │                                                                 │
    │◄──────────────────┬───────────────────┬────────────────────────┘
    │  Phase 3: Finalization
    │
    ├─→ Compute final share: xⱼ = Σ(all valid shares received)
    │   Master secret: S = Σ(fᵢ(0)) (never computed by any party)
    │
    ├─→ Store KeyShareVersion:
    │   - Version: sessionTimestamp
    │   - PrivateShare: xⱼ
    │   - Commitments: all received commitments
    │   - IsActive: true
    │   - ParticipantIDs: [all operator node IDs]
    │
    └─→ DKG complete, ready for application signing requests
```

#### Phase Details

**Phase 1: Share Distribution**

Each operator i independently generates a random polynomial:

```
fᵢ(z) = aᵢ₀ + aᵢ₁·z + aᵢ₂·z² + ... + aᵢ₍ₜ₋₁₎·z^(t-1)

Where:
- t = ⌈2n/3⌉ (threshold)
- aᵢₖ ∈ Fr (BLS12-381 scalar field) chosen uniformly at random
- aᵢ₀ = fᵢ(0) is operator i's secret contribution to master secret
```

Operator i computes:
1. **Commitments** (polynomial coefficients in G2):
   ```
   Cᵢ = [Cᵢ₀, Cᵢ₁, ..., Cᵢ₍ₜ₋₁₎]
   Where Cᵢₖ = aᵢₖ · G₂
   ```

2. **Shares** (polynomial evaluations at each operator's node ID):
   ```
   sᵢⱼ = fᵢ(nodeIDⱼ) for each operator j
   ```

3. **Message Distribution**:
   - Broadcast commitments via `POST /dkg/commitment` (ToOperatorAddress = 0x0)
   - Send individual shares via `POST /dkg/share` (P2P, ToOperatorAddress = specific operator)

**Phase 2: Verification & Acknowledgement**

Each operator j verifies received shares using the commitment scheme:

```
Verification equation:
sᵢⱼ · G₂ = Σ(Cᵢₖ · nodeIDⱼ^k) for k=0 to t-1

Left side:  Share scaled by G₂ generator
Right side: Sum of commitment terms scaled by powers of receiver's node ID

Implementation (pkg/crypto/bls/verification.go):
```go
func VerifyShare(share *fr.Element, nodeID int, commitments []G2Point) bool {
    // Left side: share · G₂
    leftSide := new(bls12381.G2Affine).ScalarMultiplication(
        bls12381.G2Generator,
        share.BigInt(),
    )

    // Right side: Σ(Cₖ · nodeID^k)
    rightSide := new(bls12381.G2Affine).Set(&bls12381.G2Affine{})
    nodeIDPower := big.NewInt(1)
    nodeIDBig := big.NewInt(int64(nodeID))

    for k, commitment := range commitments {
        term := new(bls12381.G2Affine).ScalarMultiplication(
            &commitment,
            nodeIDPower,
        )
        rightSide.Add(rightSide, term)
        nodeIDPower.Mul(nodeIDPower, nodeIDBig)
    }

    return leftSide.Equal(rightSide)
}
```

**Acknowledgement System** (prevents equivocation):

After verification, operator j creates a non-repudiable acknowledgement:

```go
type DKGAcknowledgement struct {
    FromOperatorAddress common.Address  // Receiver (j)
    ToOperatorAddress   common.Address  // Dealer (i)
    SessionTimestamp    int64
    ShareHash           [32]byte         // keccak256(share)
}

// Wrapped in AuthenticatedMessage with BN254 signature
ack := AuthenticatedMessage{
    Payload:   serialize(ackMsg),
    Hash:      keccak256(payload),
    Signature: Sign_BN254(hash, privateKey_j),
}
```

**Critical Requirement**: Dealer i MUST receive acknowledgements from **ALL** operators before proceeding to finalization. This prevents:
- Dealer equivocation (sending different shares to different operators)
- Partial participation attacks
- Inconsistent state across operators

**Phase 3: Finalization**

Once all operators have sent acknowledgements, each operator j computes their final share:

```
xⱼ = Σ(sᵢⱼ) for all i ∈ [1, n]

Where:
- xⱼ is operator j's private share
- sᵢⱼ is the share received from dealer i
```

The **master secret** (never computed by any party):
```
S = Σ(fᵢ(0)) for all i ∈ [1, n]
```

Due to polynomial properties:
```
Any subset T of t operators can recover the master secret using Lagrange interpolation:

S = Σ(λⱼ · xⱼ) for j ∈ T

Where λⱼ are Lagrange coefficients:
λⱼ = Π((0 - i)/(j - i)) for all i ∈ T, i ≠ j
```

#### Threshold Calculation

```go
// pkg/dkg/dkg.go
func CalculateThreshold(n int) int {
    return int(math.Ceil(float64(2*n) / 3.0))
}

Examples:
- n=3:  t=2  (⌈6/3⌉ = 2)
- n=4:  t=3  (⌈8/3⌉ = 3)
- n=7:  t=5  (⌈14/3⌉ = 5)
- n=10: t=7  (⌈20/3⌉ = 7)
```

This threshold provides Byzantine fault tolerance:
- Up to ⌊n/3⌋ operators can be malicious or offline
- Any ⌈2n/3⌉ honest operators can complete operations
- Standard BFT requirement for safety + liveness

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

1. **Secrecy**: No coalition of fewer than t operators can learn the master secret
2. **Correctness**: Any t or more operators can reconstruct the master secret
3. **Verifiability**: All shares can be verified against public commitments
4. **Non-repudiation**: Acknowledgements prevent dealer equivocation
5. **Fairness**: All operators contribute equally to master secret
6. **Abort Security**: If any operator misbehaves, protocol aborts safely

#### Implementation Locations

- **Protocol Logic**: `pkg/dkg/dkg.go`
- **Share Generation**: `pkg/crypto/bls/polynomial.go`
- **Share Verification**: `pkg/crypto/bls/verification.go`
- **HTTP Handlers**: `pkg/node/dkg_handlers.go`
- **Transport**: `pkg/transport/client.go`
- **Tests**: `internal/tests/integration/dkg_integration_test.go`

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

**Scenario 1: Existing Operator (Key Rotation)**

An operator with existing shares participates in scheduled reshare:

```go
// pkg/reshare/reshare.go
func (r *ReshareManager) RunReshareAsExistingOperator(
    sessionTimestamp int64,
    operators []peering.OperatorSetPeer,
) error {
    // 1. Get current active share
    currentShare := r.keystore.GetActiveKeyShare()

    // 2. Create reshare polynomial with share as constant term
    polynomial := crypto.GenerateResharePolynomial(
        currentShare.PrivateShare,  // f'(0) = current share
        threshold,
    )

    // 3. Generate commitments
    commitments := crypto.ComputeCommitments(polynomial)

    // 4. Broadcast commitments to ALL operators
    r.broadcastCommitments(commitments, sessionTimestamp)

    // 5. Generate and send shares to ALL operators (existing + new)
    for _, op := range operators {
        nodeID := addressToNodeID(op.OperatorAddress)
        share := crypto.EvaluatePolynomial(polynomial, nodeID)
        r.sendShare(op, share, sessionTimestamp)
    }

    // 6. Receive shares from all existing operators
    receivedShares := r.waitForShares(existingOperators)

    // 7. Compute Lagrange coefficients
    existingNodeIDs := extractNodeIDs(existingOperators)
    coefficients := ComputeLagrangeCoefficients(existingNodeIDs, big.NewInt(0))

    // 8. Compute new share
    newShare := ComputeNewShare(receivedShares, coefficients)

    // 9. Store new version, mark old as inactive
    r.keystore.StoreKeyShareVersion(&KeyShareVersion{
        Version:        sessionTimestamp,
        PrivateShare:   newShare,
        Commitments:    allCommitments,
        IsActive:       true,
        ParticipantIDs: allNodeIDs,
    })

    return nil
}
```

**Scenario 2: New Operator (Joining Cluster)**

A new operator without existing shares joins during reshare:

```go
func (r *ReshareManager) RunReshareAsNewOperator(
    sessionTimestamp int64,
    operators []peering.OperatorSetPeer,
) error {
    // 1. No existing share - only RECEIVE from existing operators
    // Do NOT generate or send own shares

    // 2. Wait for commitments from existing operators
    commitments := r.waitForCommitments(existingOperators)

    // 3. Wait for shares from existing operators
    receivedShares := r.waitForShares(existingOperators)

    // 4. Verify shares against commitments
    for i, share := range receivedShares {
        valid := crypto.VerifyShare(share, myNodeID, commitments[i])
        if !valid {
            return errors.New("share verification failed")
        }
    }

    // 5. Compute Lagrange coefficients (same as existing)
    existingNodeIDs := extractNodeIDs(existingOperators)
    coefficients := ComputeLagrangeCoefficients(existingNodeIDs, big.NewInt(0))

    // 6. Compute first share using Lagrange interpolation
    newShare := ComputeNewShare(receivedShares, coefficients)

    // 7. Store as first (active) version
    r.keystore.StoreKeyShareVersion(&KeyShareVersion{
        Version:        sessionTimestamp,
        PrivateShare:   newShare,
        Commitments:    commitments,
        IsActive:       true,
        ParticipantIDs: allNodeIDs,
    })

    return nil
}
```

#### Reshare Frequency

The system uses chain-specific intervals for automatic resharing:

```go
// pkg/node/scheduler.go
func GetChainInterval(chainID uint64) int64 {
    switch chainID {
    case 1:        // Ethereum Mainnet
        return 600  // 10 minutes
    case 11155111: // Sepolia Testnet
        return 120  // 2 minutes
    case 31337:    // Anvil (local)
        return 30   // 30 seconds
    default:
        return 600  // Default 10 minutes
    }
}
```

**Rationale:**
- **Mainnet (10min)**: Balance security (regular rotation) with operational cost
- **Sepolia (2min)**: Faster testing iteration without excessive load
- **Anvil (30sec)**: Rapid development and integration testing

#### Dynamic Operator Sets

Reshare supports operator set changes detected from the peering system:

```go
// At each interval boundary
currentOperators := peeringFetcher.GetOperators()

// Determine operator status
if isNewOperator(myAddress, currentOperators) {
    // Operator just joined operator set
    runReshareAsNewOperator(timestamp, currentOperators)
} else {
    // Operator was in previous operator set
    runReshareAsExistingOperator(timestamp, currentOperators)
}
```

**Operator Churn Scenarios:**

1. **Operator Joins**: New operator receives shares from existing operators, computes first share via Lagrange
2. **Operator Leaves**: Removed from operator set, stops participating, shares redistributed among remaining
3. **Multiple Changes**: System handles multiple joins/leaves simultaneously at interval boundary
4. **Threshold Adjustment**: Threshold recalculated based on new operator count: t = ⌈2n'/3⌉

#### Security Properties

1. **Master Secret Preservation**: The master secret S remains unchanged across all reshares
2. **Forward Secrecy**: Old shares cannot decrypt data encrypted after reshare
3. **Share Independence**: New shares are computationally independent from old shares
4. **Threshold Consistency**: t = ⌈2n/3⌉ maintained for new operator set
5. **No Trusted Dealer**: Reshare is distributed; no central party needed
6. **Operator Churn Support**: Handles joins/leaves without full DKG

#### Implementation Locations

- **Reshare Logic**: `pkg/reshare/reshare.go`
- **Lagrange Interpolation**: `pkg/reshare/lagrange.go`
- **Polynomial Generation**: `pkg/crypto/bls/polynomial.go`
- **HTTP Handlers**: `pkg/node/reshare_handlers.go`
- **Scheduler Integration**: `pkg/node/scheduler.go`
- **Tests**: `internal/tests/integration/reshare_integration_test.go`

### EigenLayer Protocol Integration

EigenX KMS operates as a native EigenLayer AVS, leveraging EigenLayer's restaking infrastructure for operator management, economic security, and cryptographic key registration. The integration spans multiple EigenLayer contracts and protocols.

#### Contract Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    EigenLayer Core Contracts                     │
│                                                                   │
│  ┌────────────────────┐  ┌──────────────────────────────────┐  │
│  │ DelegationManager  │  │   AllocationManager              │  │
│  │ - Operator reg     │  │   - Stake allocation tracking    │  │
│  │ - Delegations      │  │   - Slashing conditions          │  │
│  └────────────────────┘  └──────────────────────────────────┘  │
│                                                                   │
│  ┌────────────────────┐  ┌──────────────────────────────────┐  │
│  │ AVSDirectory       │  │   OperatorSetRegistrar           │  │
│  │ - AVS registry     │  │   - Operator set management      │  │
│  │ - Operator→AVS     │  │   - Join/leave operations        │  │
│  └────────────────────┘  └──────────────────────────────────┘  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│                    KMS AVS Contracts                             │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ KeyRegistrar                                              │  │
│  │ - BN254 public key registration                           │  │
│  │ - Key history tracking                                    │  │
│  │ - Operator key queries                                    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ KMS Release Manager (Future)                              │  │
│  │ - Configuration management                                │  │
│  │ - Interval updates                                        │  │
│  │ - Feature flags                                           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

#### Operator Registration Flow

An operator must complete several registration steps before participating in KMS operations:

```
Step 1: Register with EigenLayer
    │
    ├─→ Call DelegationManager.registerAsOperator()
    │   - Provides metadata (name, website, description)
    │   - Sets delegation terms
    │   - Becomes eligible for delegations
    │
Step 2: Generate BN254 Key Pair
    │
    ├─→ Generate BN254 private key
    │   privateKey := crypto.GenerateKey()  // 32 bytes
    │
    ├─→ Derive public key
    │   publicKey := privateKey.PublicKey()  // G1 point
    │
Step 3: Register with KMS AVS
    │
    ├─→ Call registerOperator via CLI tool:
    │   ./bin/register-operator \
    │     --operator-address "0x..." \
    │     --avs-address "0x..." \
    │     --bn254-private-key "0x..." \
    │     --rpc-url "https://..."
    │
    ├─→ Backend calls:
    │   a. KeyRegistrar.registerOperatorWithKey(operatorAddress, bn254PubKey)
    │      - Stores BN254 public key on-chain
    │      - Indexed for quick lookup
    │
    │   b. AVSDirectory.registerOperatorToAVS(operatorAddress, signature)
    │      - Links operator to KMS AVS
    │      - Enables operator set inclusion
    │
    │   c. OperatorSetRegistrar.registerOperatorToOperatorSet(operatorAddress, setId)
    │      - Adds operator to specific operator set
    │      - Triggers operator discovery by existing operators
    │
Step 4: Start KMS Node
    │
    └─→ ./bin/kms-server \
          --operator-address "0x..." \
          --bn254-private-key "0x..." \
          --avs-address "0x..." \
          --operator-set-id 0
```

**Implementation** (`cmd/registerOperator/main.go`):

```go
func registerOperator(
    operatorAddr common.Address,
    avsAddr common.Address,
    bn254PrivateKey *ecdsa.PrivateKey,
    rpcURL string,
) error {
    // 1. Connect to Ethereum client
    client, err := ethclient.Dial(rpcURL)
    if err != nil {
        return fmt.Errorf("failed to connect: %w", err)
    }

    // 2. Derive BN254 public key
    bn254PubKey := bn254PrivateKey.PublicKey()
    pubKeyBytes := crypto.MarshalBN254PublicKey(bn254PubKey)

    // 3. Register key with KeyRegistrar
    keyRegistrar := contracts.NewKeyRegistrar(keyRegistrarAddr, client)
    tx, err := keyRegistrar.RegisterOperatorWithKey(
        operatorAddr,
        pubKeyBytes,
    )
    if err != nil {
        return fmt.Errorf("failed to register key: %w", err)
    }
    receipt, _ := bind.WaitMined(context.Background(), client, tx)
    log.Printf("Key registered: tx=%s", receipt.TxHash.Hex())

    // 4. Sign operator registration
    digestHash := crypto.CalculateOperatorAVSRegistrationDigestHash(
        operatorAddr,
        avsAddr,
        salt,
        expiry,
    )
    signature, err := crypto.SignHash(digestHash, bn254PrivateKey)
    if err != nil {
        return fmt.Errorf("failed to sign: %w", err)
    }

    // 5. Register with AVSDirectory
    avsDirectory := contracts.NewAVSDirectory(avsDirectoryAddr, client)
    tx, err = avsDirectory.RegisterOperatorToAVS(
        operatorAddr,
        signature,
    )
    if err != nil {
        return fmt.Errorf("failed to register to AVS: %w", err)
    }
    receipt, _ = bind.WaitMined(context.Background(), client, tx)
    log.Printf("AVS registration: tx=%s", receipt.TxHash.Hex())

    // 6. Join operator set
    operatorSetRegistrar := contracts.NewOperatorSetRegistrar(opSetRegistrarAddr, client)
    tx, err = operatorSetRegistrar.RegisterOperatorToOperatorSet(
        operatorAddr,
        operatorSetID,
    )
    if err != nil {
        return fmt.Errorf("failed to join operator set: %w", err)
    }
    receipt, _ = bind.WaitMined(context.Background(), client, tx)
    log.Printf("Operator set registration: tx=%s", receipt.TxHash.Hex())

    return nil
}
```

#### Peering Data Fetcher

The KMS node discovers other operators through the peering system, which queries EigenLayer contracts:

**Production Implementation** (`pkg/peering/contract_fetcher.go`):

```go
type ContractPeeringDataFetcher struct {
    contractCaller *contract.ContractCaller
    avsAddress     common.Address
    operatorSetID  uint32
}

func (f *ContractPeeringDataFetcher) GetOperators() ([]OperatorSetPeer, error) {
    // Query OperatorSetRegistrar for operator set members
    members, err := f.contractCaller.GetOperatorSetMembersWithPeering(
        f.avsAddress,
        f.operatorSetID,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to get operators: %w", err)
    }

    peers := make([]OperatorSetPeer, 0, len(members))
    for _, member := range members {
        // Extract peering information
        peer := OperatorSetPeer{
            OperatorAddress:  member.OperatorAddress,
            SocketAddress:    member.Socket,  // "http://host:port"
            WrappedPublicKey: member.PubkeyG1,
            CurveType:        "BN254",
        }
        peers = append(peers, peer)
    }

    return peers, nil
}
```

**Contract Query Flow**:

```
KMS Node
    │
    ├─→ GetOperators()
    │
    ├─→ ContractCaller.GetOperatorSetMembersWithPeering(avsAddr, setId)
    │
    └─→ OperatorSetRegistrar.getOperatorSet(setId)
         ├─→ Returns: []Operator
         │    - operatorAddress
         │    - stakeWeight
         │    - joinedAt
         │
         └─→ KeyRegistrar.getOperatorKey(operatorAddress)
              ├─→ Returns: BN254PublicKey
              │    - G1 point (X, Y coordinates)
              │    - registeredAt timestamp
              │
              └─→ OperatorMetadata.getSocket(operatorAddress)
                   └─→ Returns: "http://ip:port"
```

#### Dynamic Operator Discovery

At each interval boundary, the scheduler queries the peering system to detect operator set changes:

```go
// pkg/node/scheduler.go
func (n *Node) schedulerLoop() {
    ticker := time.NewTicker(500 * time.Millisecond)
    defer ticker.Stop()

    for range ticker.C {
        now := time.Now()
        interval := GetChainInterval(n.chainID)
        roundedTime := (now.Unix() / interval) * interval

        // Skip if already processed
        if n.processedIntervals[roundedTime] {
            continue
        }

        // CRITICAL: Fetch current operators from blockchain
        currentOperators, err := n.peeringFetcher.GetOperators()
        if err != nil {
            log.Printf("Failed to fetch operators: %v", err)
            continue
        }

        // Detect operator set changes
        if operatorSetChanged(n.lastOperators, currentOperators) {
            log.Printf("Operator set changed: %d → %d operators",
                len(n.lastOperators), len(currentOperators))
        }

        // Determine if this node is new or existing
        wasInPrevious := containsOperator(n.lastOperators, n.operatorAddress)
        isInCurrent := containsOperator(currentOperators, n.operatorAddress)

        if !isInCurrent {
            log.Printf("Not in current operator set, skipping")
            continue
        }

        // Execute appropriate protocol
        if !wasInPrevious && isInCurrent {
            // Just joined operator set
            go n.runReshareAsNewOperator(roundedTime, currentOperators)
        } else if hasExistingShares() {
            // Existing operator with shares
            go n.runReshareAsExistingOperator(roundedTime, currentOperators)
        } else {
            // Genesis DKG needed
            go n.runDKG(roundedTime, currentOperators)
        }

        n.lastOperators = currentOperators
        n.processedIntervals[roundedTime] = true
    }
}
```

#### Economic Security Model

EigenLayer provides economic security through restaking and slashing:

**Restaking**: Operators stake ETH (native or liquid staking tokens) which is delegated to the KMS AVS, providing economic collateral.

**Slashing Conditions** (future implementation):
1. **Equivocation**: Sending different shares to different operators
2. **Unavailability**: Missing threshold number of reshare intervals
3. **Invalid Signatures**: Providing incorrect partial signatures
4. **Protocol Violations**: Deviating from DKG/reshare protocols

**Stake Weighting**: Currently unweighted (1 operator = 1 share), but architecture supports stake-weighted thresholds:

```go
// Future: Stake-weighted threshold calculation
func CalculateStakeWeightedThreshold(operators []Operator) *big.Int {
    totalStake := big.NewInt(0)
    for _, op := range operators {
        totalStake.Add(totalStake, op.StakeWeight)
    }

    // Threshold: 2/3 of total stake
    threshold := new(big.Int).Mul(totalStake, big.NewInt(2))
    threshold.Div(threshold, big.NewInt(3))

    return threshold
}
```

#### Contract Deployment

KMS AVS contracts must be deployed before operator registration:

```bash
# Deploy AVS contracts (Sepolia example)
forge script script/DeployKMSAVS.s.sol \
  --rpc-url https://sepolia.infura.io/v3/$INFURA_KEY \
  --broadcast \
  --verify

# Output:
# AVSDirectory: 0x...
# OperatorSetRegistrar: 0x...
# KeyRegistrar: 0x... (KMS-specific)
# AllocationManager: 0x...
```

#### Implementation Locations

- **Contract Bindings**: `pkg/contract/` (generated via abigen)
- **Peering Fetcher**: `pkg/peering/contract_fetcher.go`
- **Operator Registration**: `cmd/registerOperator/main.go`
- **Scheduler Integration**: `pkg/node/scheduler.go`
- **Contracts**: `contracts/` (Solidity source)
- **Deployment Scripts**: `scripts/deploy_avs.sh`

### HTTP API Interface

The KMS node exposes two categories of HTTP endpoints: **Protocol APIs** for inter-operator communication (authenticated with BN254 signatures) and **Application APIs** for client interactions.

#### Protocol APIs (Authenticated)

All protocol messages are wrapped in `AuthenticatedMessage` with BN254 signatures:

```go
type AuthenticatedMessage struct {
    Payload   []byte   `json:"payload"`    // Serialized message
    Hash      [32]byte `json:"hash"`       // keccak256(payload)
    Signature []byte   `json:"signature"`  // BN254 signature over hash
}
```

**DKG Endpoints:**

```
POST /dkg/commitment
Body: AuthenticatedMessage {
    Payload: {
        FromOperatorAddress: "0x...",
        ToOperatorAddress: "0x0",  // Broadcast (zero address)
        SessionTimestamp: 1640995200,
        Commitments: [G2Point, ...]  // Polynomial commitments
    }
}
Response: 200 OK

POST /dkg/share
Body: AuthenticatedMessage {
    Payload: {
        FromOperatorAddress: "0x...",
        ToOperatorAddress: "0x...",  // Specific recipient
        SessionTimestamp: 1640995200,
        Share: "0x..."  // Encrypted BLS12-381 Fr element
    }
}
Response: 200 OK

POST /dkg/ack
Body: AuthenticatedMessage {
    Payload: {
        FromOperatorAddress: "0x...",  // Receiver
        ToOperatorAddress: "0x...",    // Dealer
        SessionTimestamp: 1640995200,
        ShareHash: "0x..."  // keccak256(share)
    }
}
Response: 200 OK
```

**Reshare Endpoints:**

```
POST /reshare/commitment
POST /reshare/share
POST /reshare/ack
POST /reshare/complete

// Same structure as DKG endpoints
```

**Authentication Handler** (`pkg/node/middleware.go`):

```go
func AuthenticateOperatorMessage(
    peeringFetcher peering.IPeeringDataFetcher,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // 1. Parse authenticated message
        var authMsg transport.AuthenticatedMessage
        if err := json.NewDecoder(r.Body).Decode(&authMsg); err != nil {
            http.Error(w, "invalid message", http.StatusBadRequest)
            return
        }

        // 2. Verify payload hash
        computedHash := crypto.Keccak256Hash(authMsg.Payload)
        if computedHash != authMsg.Hash {
            http.Error(w, "hash mismatch", http.StatusUnauthorized)
            return
        }

        // 3. Extract sender address from payload
        var baseMsg types.BaseMessage
        json.Unmarshal(authMsg.Payload, &baseMsg)

        // 4. Get sender's BN254 public key from peering
        operators, _ := peeringFetcher.GetOperators()
        var senderPubKey *ecdsa.PublicKey
        for _, op := range operators {
            if op.OperatorAddress == baseMsg.FromOperatorAddress {
                senderPubKey = op.WrappedPublicKey
                break
            }
        }
        if senderPubKey == nil {
            http.Error(w, "unknown operator", http.StatusUnauthorized)
            return
        }

        // 5. Verify BN254 signature
        if !crypto.VerifySignature(senderPubKey, authMsg.Hash[:], authMsg.Signature) {
            http.Error(w, "invalid signature", http.StatusUnauthorized)
            return
        }

        // 6. Verify recipient (if not broadcast)
        if baseMsg.ToOperatorAddress != (common.Address{}) {
            if baseMsg.ToOperatorAddress != nodeAddress {
                http.Error(w, "message not for this operator", http.StatusForbidden)
                return
            }
        }

        // Success: forward to handler
        r = r.WithContext(context.WithValue(r.Context(), "authMsg", authMsg))
        next.ServeHTTP(w, r)
    }
}
```

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

#### HTTP Server Implementation

**Server Setup** (`pkg/node/server.go`):

```go
func (n *Node) StartServer(port int) error {
    mux := http.NewServeMux()

    // Protocol endpoints (authenticated)
    mux.HandleFunc("/dkg/commitment",
        AuthenticateOperatorMessage(n.peeringFetcher)(n.handleDKGCommitment))
    mux.HandleFunc("/dkg/share",
        AuthenticateOperatorMessage(n.peeringFetcher)(n.handleDKGShare))
    mux.HandleFunc("/dkg/ack",
        AuthenticateOperatorMessage(n.peeringFetcher)(n.handleDKGAck))

    mux.HandleFunc("/reshare/commitment",
        AuthenticateOperatorMessage(n.peeringFetcher)(n.handleReshareCommitment))
    mux.HandleFunc("/reshare/share",
        AuthenticateOperatorMessage(n.peeringFetcher)(n.handleReshareShare))

    // Application endpoints (public)
    mux.HandleFunc("/pubkey", n.handleGetPublicKey)
    mux.HandleFunc("/app/sign", n.handleApplicationSign)
    mux.HandleFunc("/secrets", n.handleSecrets)
    mux.HandleFunc("/health", n.handleHealth)

    // CORS and logging middleware
    handler := loggingMiddleware(corsMiddleware(mux))

    server := &http.Server{
        Addr:         fmt.Sprintf(":%d", port),
        Handler:      handler,
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
    }

    log.Printf("Starting KMS server on port %d", port)
    return server.ListenAndServe()
}
```

#### Client Request Flow

**KMS Client Example** (`pkg/client/client.go`):

```go
type KMSClient struct {
    operatorEndpoints []string
    httpClient        *http.Client
}

// GetMasterPublicKey aggregates commitments from operators
func (c *KMSClient) GetMasterPublicKey(appID string) (*MasterPublicKey, error) {
    commitmentSets := make([][]G2Point, 0, len(c.operatorEndpoints))

    // Query each operator
    for _, endpoint := range c.operatorEndpoints {
        resp, err := c.httpClient.Get(endpoint + "/pubkey")
        if err != nil {
            continue  // Try other operators
        }

        var pubkeyResp PubkeyResponse
        json.NewDecoder(resp.Body).Decode(&pubkeyResp)
        commitmentSets = append(commitmentSets, pubkeyResp.Commitments)
    }

    // Aggregate commitments (should be identical)
    masterCommitments := aggregateCommitments(commitmentSets)
    return &MasterPublicKey{Commitments: masterCommitments}, nil
}

// CollectPartialSignatures collects threshold signatures
func (c *KMSClient) CollectPartialSignatures(
    appID string,
    threshold int,
) ([]PartialSignature, error) {
    partialSigs := make([]PartialSignature, 0, threshold)

    req := ApplicationSignRequest{
        AppID:           appID,
        AttestationTime: time.Now().Unix(),
    }

    for _, endpoint := range c.operatorEndpoints {
        resp, err := c.httpClient.Post(
            endpoint+"/app/sign",
            "application/json",
            marshalJSON(req),
        )
        if err != nil {
            continue
        }

        var sigResp PartialSignatureResponse
        json.NewDecoder(resp.Body).Decode(&sigResp)
        partialSigs = append(partialSigs, sigResp.PartialSignature)

        // Stop once we have threshold signatures
        if len(partialSigs) >= threshold {
            break
        }
    }

    if len(partialSigs) < threshold {
        return nil, fmt.Errorf("insufficient signatures: got %d, need %d",
            len(partialSigs), threshold)
    }

    return partialSigs, nil
}
```

#### Implementation Locations

- **HTTP Server**: `pkg/node/server.go`
- **Protocol Handlers**: `pkg/node/*_handlers.go`
- **Authentication Middleware**: `pkg/node/middleware.go`
- **KMS Client**: `pkg/client/client.go`
- **CLI Tool**: `cmd/kmsClient/main.go`

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

```go
// Polynomial generation (pkg/crypto/bls/polynomial.go)
func GeneratePolynomial(degree int) ([]*fr.Element, error) {
    coefficients := make([]*fr.Element, degree)
    for i := 0; i < degree; i++ {
        coeff, err := rand.Int(rand.Reader, fr.Modulus())
        if err != nil {
            return nil, err
        }
        coefficients[i] = new(fr.Element).SetBigInt(coeff)
    }
    return coefficients, nil
}

// Polynomial evaluation: f(x) = Σ(aₖ·xᵏ)
func EvaluatePolynomial(polynomial []*fr.Element, x int) *fr.Element {
    result := fr.NewElement().SetZero()
    xPower := fr.NewElement().SetOne()
    xElement := fr.NewElement().SetInt64(int64(x))

    for _, coeff := range polynomial {
        term := fr.NewElement()
        term.Mul(coeff, xPower)
        result.Add(result, term)
        xPower.Mul(xPower, xElement)
    }

    return result
}

// Commitment generation: Cₖ = aₖ·G₂
func ComputeCommitments(polynomial []*fr.Element) []bls12381.G2Affine {
    commitments := make([]bls12381.G2Affine, len(polynomial))
    generator := bls12381.G2Generator()

    for i, coeff := range polynomial {
        commitments[i].ScalarMultiplication(generator, coeff.BigInt())
    }

    return commitments
}
```

**Share Verification:**

```go
// Verify: s·G₂ = Σ(Cₖ·xᵏ) for k=0 to t-1
func VerifyShare(
    share *fr.Element,
    nodeID int,
    commitments []bls12381.G2Affine,
) bool {
    // Left side: share·G₂
    leftSide := new(bls12381.G2Affine)
    leftSide.ScalarMultiplication(bls12381.G2Generator(), share.BigInt())

    // Right side: Σ(Cₖ·nodeIDᵏ)
    rightSide := new(bls12381.G2Affine).SetInfinity()
    nodeIDPower := big.NewInt(1)
    nodeIDBig := big.NewInt(int64(nodeID))

    for _, commitment := range commitments {
        term := new(bls12381.G2Affine)
        term.ScalarMultiplication(&commitment, nodeIDPower)
        rightSide.Add(rightSide, term)
        nodeIDPower.Mul(nodeIDPower, nodeIDBig)
    }

    return leftSide.Equal(rightSide)
}
```

**Partial Signature Generation:**

```go
// Generate partial signature: σᵢ = H₁(appID)^(xᵢ)
func GeneratePartialSignature(
    appID string,
    privateShare *fr.Element,
) *bls12381.G1Affine {
    // Hash app ID to G1 point
    Q := HashToG1(appID)

    // Compute partial signature: Q^(privateShare)
    partialSig := new(bls12381.G1Affine)
    partialSig.ScalarMultiplication(Q, privateShare.BigInt())

    return partialSig
}

// Recover full signature using Lagrange interpolation
func RecoverSignature(
    partialSigs []bls12381.G1Affine,
    operatorNodeIDs []int,
) *bls12381.G1Affine {
    // Compute Lagrange coefficients at x=0
    coeffs := ComputeLagrangeCoefficients(operatorNodeIDs, big.NewInt(0))

    // Aggregate: σ = Σ(λᵢ·σᵢ)
    signature := new(bls12381.G1Affine).SetInfinity()
    for i, partialSig := range partialSigs {
        term := new(bls12381.G1Affine)
        term.ScalarMultiplication(&partialSig, coeffs[i].BigInt())
        signature.Add(signature, term)
    }

    return signature
}
```

### BN254 Message Authentication

**Purpose**: Authenticate all inter-operator P2P messages

**Key Properties:**
- EigenLayer standard curve for operator keys
- Solidity-compatible (ecrecover-style verification on-chain)
- Efficient signature generation and verification

**Message Signing** (`pkg/transport/signing.go`):

```go
func SignMessage(
    payload []byte,
    privateKey *ecdsa.PrivateKey,
) (AuthenticatedMessage, error) {
    // 1. Compute payload hash
    hash := crypto.Keccak256Hash(payload)

    // 2. Sign hash with BN254 private key
    signature, err := crypto.Sign(hash.Bytes(), privateKey)
    if err != nil {
        return AuthenticatedMessage{}, err
    }

    // 3. Return authenticated message
    return AuthenticatedMessage{
        Payload:   payload,
        Hash:      hash,
        Signature: signature,
    }, nil
}

func VerifyMessage(
    authMsg AuthenticatedMessage,
    publicKey *ecdsa.PublicKey,
) bool {
    // 1. Verify payload hash
    computedHash := crypto.Keccak256Hash(authMsg.Payload)
    if computedHash != authMsg.Hash {
        return false
    }

    // 2. Recover signer from signature
    recoveredPubKey, err := crypto.SigToPub(authMsg.Hash.Bytes(), authMsg.Signature)
    if err != nil {
        return false
    }

    // 3. Compare with expected public key
    return publicKey.Equal(recoveredPubKey)
}
```

### Identity-Based Encryption (IBE)

**Concept**: Encrypt data using simple identifiers (app IDs) without pre-shared keys

**Encryption Flow:**

```go
// 1. Hash app ID to G1 point
func HashToG1(appID string) *bls12381.G1Affine {
    hash := sha256.Sum256([]byte(appID))
    point := bls12381.HashToG1(hash[:])
    return point
}

// 2. Encrypt with master public key
func IBEEncrypt(
    appID string,
    masterPublicKey []bls12381.G2Affine,  // Commitments
    plaintext []byte,
) ([]byte, error) {
    // Derive encryption key from master public key
    Q := HashToG1(appID)
    encryptionKey := ComputePairingKey(Q, masterPublicKey[0])  // Use constant term

    // AES-GCM encryption with derived key
    keyBytes := encryptionKey.Bytes()
    block, _ := aes.NewCipher(keyBytes[:32])
    gcm, _ := cipher.NewGCM(block)

    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)

    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}

// 3. Decrypt with recovered app private key
func IBEDecrypt(
    appPrivateKey *bls12381.G1Affine,  // Recovered via threshold sigs
    ciphertext []byte,
) ([]byte, error) {
    // Derive decryption key from app private key
    decryptionKey := appPrivateKey.Bytes()

    // Extract nonce
    block, _ := aes.NewCipher(decryptionKey[:32])
    gcm, _ := cipher.NewGCM(block)
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

    // AES-GCM decryption
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    return plaintext, err
}
```

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

**BLS12-381 Serialization** (`pkg/crypto/bls/serialization.go`):

```go
// G1 point (48 bytes compressed)
func SerializeG1(point *bls12381.G1Affine) []byte {
    return point.Compressed()  // 48 bytes
}

func DeserializeG1(data []byte) (*bls12381.G1Affine, error) {
    point := new(bls12381.G1Affine)
    err := point.Uncompress(data)
    return point, err
}

// G2 point (96 bytes compressed)
func SerializeG2(point *bls12381.G2Affine) []byte {
    return point.Compressed()  // 96 bytes
}

func DeserializeG2(data []byte) (*bls12381.G2Affine, error) {
    point := new(bls12381.G2Affine)
    err := point.Uncompress(data)
    return point, err
}

// Fr element (32 bytes)
func SerializeFr(element *fr.Element) []byte {
    return element.Bytes()  // 32 bytes big-endian
}

func DeserializeFr(data []byte) (*fr.Element, error) {
    element := new(fr.Element)
    element.SetBytes(data)
    return element, nil
}
```

#### Implementation Locations

- **BLS12-381 Operations**: `pkg/crypto/bls/`
- **BN254 Signing**: `pkg/transport/signing.go`
- **IBE**: `pkg/crypto/ibe/` (future extraction)
- **Hash Functions**: `pkg/crypto/hash.go`
- **Serialization**: `pkg/crypto/bls/serialization.go`
- **Library**: `github.com/consensys/gnark-crypto` (BLS12-381, BN254)

## Security Model

### Threat Model

**Adversary Capabilities:**
- Control up to ⌊n/3⌋ operators (Byzantine fault tolerance)
- Network-level adversary (delay, reorder, drop messages)
- Passive observation of all network traffic
- Access to historical key shares (compromised operator)

**System Assumptions:**
- Honest majority: At least ⌈2n/3⌉ operators follow protocol correctly
- Computational hardness: Discrete log problem in BLS12-381, ECDLP in BN254
- EigenLayer slashing: Economic disincentive for misbehavior
- Blockchain liveness: Ethereum available for operator discovery

### Security Properties

**1. Confidentiality**

**Property**: No coalition of fewer than t = ⌈2n/3⌉ operators can learn application secrets

**Mechanism**:
- Master secret S distributed via Shamir secret sharing
- Any subset of t operators can reconstruct via Lagrange interpolation
- Subsets smaller than t gain zero information (information-theoretic security)

**Attack Resistance**:
- Passive adversary with ⌊n/3⌋ compromised operators: Cannot recover any app keys
- Reshare with forward secrecy: Old shares useless after rotation

**2. Integrity**

**Property**: Invalid shares, signatures, or messages are detectable

**Mechanisms**:
- Share verification via polynomial commitments (Pedersen VSS)
- BN254 signatures on all P2P messages
- Acknowledgement system prevents equivocation
- Application signature verification via pairing checks

**Attack Resistance**:
- Malicious dealer sending invalid shares: Detected during verification phase
- Message tampering: Signature verification fails
- Dealer equivocation: Prevented by acknowledgement requirement

**3. Availability**

**Property**: System remains operational with up to ⌊n/3⌋ faulty operators

**Mechanisms**:
- Threshold t = ⌈2n/3⌉ ensures availability with ⌊n/3⌋ failures
- Automatic reshare handles operator churn
- No single point of failure

**Attack Resistance**:
- DoS on ⌊n/3⌋ operators: Remaining operators sufficient for operations
- Network partitions: Clients collect threshold signatures from available operators

**4. Non-Repudiation**

**Property**: Operators cannot deny participation or equivocate

**Mechanisms**:
- Signed acknowledgements during DKG/reshare
- BN254 signatures on all messages
- On-chain operator registration and key publication

**Attack Resistance**:
- Dealer claims different operators sent invalid shares: Acknowledgements provide proof
- Operator denies participation: Signature verification proves authorship

**5. Forward Secrecy**

**Property**: Compromise of current shares doesn't compromise historical data encrypted with old keys

**Mechanism**:
- Automatic periodic reshare generates new shares
- Old shares computationally independent from new shares
- Applications should re-encrypt with new keys periodically

**Limitation**: Doesn't protect against data encrypted with old master public key (master secret unchanged)

**Future Enhancement**: Master secret rotation via full DKG (breaking backward compatibility)

### Attack Scenarios

**Scenario 1: Malicious Dealer in DKG**

```
Attack: Operator i sends different shares to different operators (equivocation)

Defense:
  1. All operators receive same commitments (broadcast)
  2. Each operator verifies share against commitments
  3. If valid, operator sends signed acknowledgement to dealer
  4. Dealer must collect ALL acknowledgements before proceeding
  5. If dealer sent different shares, verification fails for some operators
  6. Missing acknowledgements cause protocol abort

Result: Equivocation detected, protocol aborts safely
```

**Scenario 2: Compromised Operator Shares**

```
Attack: Adversary compromises ⌊n/3⌋ operators and steals private shares

Impact Analysis:
  - Operators compromised: 3 out of 10
  - Threshold: ⌈20/3⌉ = 7
  - Adversary has: 3 shares (insufficient)

Defense:
  - Threshold cryptography: 3 < 7, cannot recover master secret
  - Information-theoretic security: 3 shares reveal zero information
  - Reshare invalidates compromised shares after next interval

Result: No secret leakage, automatic recovery via reshare
```

**Scenario 3: Message Replay Attack**

```
Attack: Adversary captures valid DKG share message, replays in future protocol

Defense:
  1. SessionTimestamp in message payload ties message to specific protocol run
  2. Nodes reject messages with SessionTimestamp not matching current session
  3. BN254 signature ensures message authenticity
  4. ToOperatorAddress ensures message intended for specific recipient

Result: Replay detected and rejected
```

**Scenario 4: Application Key Request Spoofing**

```
Attack: Malicious client requests partial signatures for victim's appID

Defense:
  - No defense at protocol level (by design)
  - Application-layer authentication required:
    a. TEE attestation (Intel TDX quote verification)
    b. OAuth/JWT tokens
    c. IP allowlisting
    d. Rate limiting

Result: Protocol provides cryptographic primitives; application handles access control
```

**Scenario 5: Network Partition During Reshare**

```
Attack: Network partition isolates ⌊n/3⌋ operators during reshare

Impact:
  - Operators in minority partition: Cannot complete reshare (lack threshold)
  - Operators in majority partition: ⌈2n/3⌉ still available, reshare succeeds

Defense:
  - Interval-based timing: Minority partition will retry at next interval
  - Historical key versions: Old keys still valid for historical attestation times
  - Graceful degradation: System continues with available operators

Result: Majority partition completes reshare, minority rejoins at next interval
```

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

## Key Management

### KeyShareVersion Structure

```go
type KeyShareVersion struct {
    Version        int64           // Session timestamp (epoch)
    PrivateShare   *fr.Element     // This operator's secret share
    Commitments    []G2Point       // Polynomial commitments (public)
    IsActive       bool            // Currently used for signing
    ParticipantIDs []int           // Operator node IDs in this version
    CreatedAt      time.Time       // Local creation timestamp
}
```

**Version Semantics:**
- `Version`: Unix timestamp of interval boundary when DKG/reshare occurred
- Serves as epoch identifier for time-based key lookups
- Globally consistent across all operators (interval-synchronized)

**Storage** (`pkg/keystore/keystore.go`):

```go
type KeyStore struct {
    mu            sync.RWMutex
    keyVersions   map[int64]*KeyShareVersion  // version → KeyShareVersion
    activeVersion int64                        // Currently active version
}

func (ks *KeyStore) StoreKeyShareVersion(version *KeyShareVersion) error {
    ks.mu.Lock()
    defer ks.mu.Unlock()

    // Mark previous active version as inactive
    if ks.activeVersion != 0 {
        if prev, exists := ks.keyVersions[ks.activeVersion]; exists {
            prev.IsActive = false
        }
    }

    // Store new version as active
    version.IsActive = true
    ks.keyVersions[version.Version] = version
    ks.activeVersion = version.Version

    log.Printf("Stored key version: %d (active)", version.Version)
    return nil
}

func (ks *KeyStore) GetActiveKeyShare() *KeyShareVersion {
    ks.mu.RLock()
    defer ks.mu.RUnlock()

    if ks.activeVersion == 0 {
        return nil
    }

    return ks.keyVersions[ks.activeVersion]
}

func (ks *KeyStore) GetKeyVersionAtTime(attestationTime int64) *KeyShareVersion {
    ks.mu.RLock()
    defer ks.mu.RUnlock()

    // Find latest version at or before attestation time
    var latestVersion int64
    for version := range ks.keyVersions {
        if version <= attestationTime && version > latestVersion {
            latestVersion = version
        }
    }

    if latestVersion == 0 {
        return nil
    }

    return ks.keyVersions[latestVersion]
}
```

### Version Lifecycle

```
Lifecycle:

Genesis (t=0):
  │
  ├─→ DKG execution
  │   Version: 1640995200 (session timestamp)
  │   IsActive: true
  │
Interval 1 (t=600):
  │
  ├─→ Reshare execution
  │   Version: 1640995800
  │   IsActive: true
  │   Previous version (1640995200) marked IsActive: false
  │
Interval 2 (t=1200):
  │
  ├─→ Reshare execution
  │   Version: 1641000400
  │   IsActive: true
  │   Previous version (1640995800) marked IsActive: false
  │
Historical Lookups:
  │
  ├─→ App requests signature with attestationTime = 1640995500
  │   GetKeyVersionAtTime(1640995500) → version 1640995200
  │
  └─→ App requests signature with attestationTime = 1641000500
      GetKeyVersionAtTime(1641000500) → version 1641000400
```

### Time-Based Key Lookup

**Use Case**: TEE applications with attestation timestamps

**Flow:**

```go
// Application handler (pkg/node/handlers.go)
func (n *Node) handleApplicationSign(w http.ResponseWriter, r *http.Request) {
    var req ApplicationSignRequest
    json.NewDecoder(r.Body).Decode(&req)

    // Get appropriate key version for attestation time
    var keyVersion *KeyShareVersion
    if req.AttestationTime != 0 {
        // Historical key lookup
        keyVersion = n.keystore.GetKeyVersionAtTime(req.AttestationTime)
    } else {
        // Use active key
        keyVersion = n.keystore.GetActiveKeyShare()
    }

    if keyVersion == nil {
        http.Error(w, "no key available", http.StatusNotFound)
        return
    }

    // Generate partial signature with appropriate version
    partialSig := crypto.GeneratePartialSignature(
        req.AppID,
        keyVersion.PrivateShare,
    )

    response := PartialSignatureResponse{
        OperatorAddress:  n.operatorAddress,
        PartialSignature: partialSig,
        Version:          keyVersion.Version,
    }

    json.NewEncoder(w).Encode(response)
}
```

**Attestation Time Semantics:**

```
Example:
  - DKG at t=1000, active until t=1600
  - Reshare at t=1600, new keys active
  - TEE application started at t=1200, generates attestation

Client request:
  {
    "appID": "my-app",
    "attestationTime": 1200  // TEE start time
  }

Operator response:
  - Looks up key version at t=1200 → version 1000
  - Generates partial signature with v1000 share
  - Returns signature with version=1000

Client aggregation:
  - Collects partial signatures from threshold operators
  - All should have version=1000 for attestationTime=1200
  - Aggregates to recover app private key from v1000 master key
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

### Persistence (Future)

Current implementation uses in-memory storage. Planned persistence:

**Design Goals:**
1. Encrypted at rest (AES-256-GCM with operator-derived key)
2. Atomic writes (no partial state corruption)
3. Version history retention (configurable retention period)
4. Fast lookup by version timestamp

**Proposed Schema** (BoltDB/SQLite):

```sql
CREATE TABLE key_versions (
    version INTEGER PRIMARY KEY,      -- Session timestamp
    encrypted_share BLOB NOT NULL,    -- AES-encrypted private share
    commitments BLOB NOT NULL,        -- Serialized G2 points
    is_active BOOLEAN NOT NULL,
    participant_ids BLOB NOT NULL,    -- Serialized []int
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_active ON key_versions(is_active);
CREATE INDEX idx_created_at ON key_versions(created_at);
```

**Encryption Scheme:**

```go
func EncryptKeyShare(
    share *fr.Element,
    operatorPrivateKey *ecdsa.PrivateKey,
) ([]byte, error) {
    // Derive encryption key from operator BN254 private key
    keyMaterial := sha256.Sum256(operatorPrivateKey.D.Bytes())

    block, _ := aes.NewCipher(keyMaterial[:])
    gcm, _ := cipher.NewGCM(block)

    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)

    plaintext := share.Bytes()
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

    return ciphertext, nil
}
```

### Backend Keystore Integration (Future)

Support for external key management systems:

**Supported Backends:**
1. **AWS KMS**: Store BN254 private key, derive encryption key for shares
2. **GCP KMS**: Similar to AWS KMS
3. **HashiCorp Vault**: Transit secrets engine for encryption
4. **Hardware Security Modules (HSMs)**: PKCS#11 interface

**Architecture:**

```go
type KeyBackend interface {
    // Encrypt key share using backend
    EncryptShare(share *fr.Element) ([]byte, error)

    // Decrypt key share using backend
    DecryptShare(ciphertext []byte) (*fr.Element, error)

    // Sign message using operator private key
    SignMessage(hash []byte) ([]byte, error)
}

// AWS KMS implementation
type AWSKMSBackend struct {
    kmsClient *kms.Client
    keyID     string
}

func (b *AWSKMSBackend) EncryptShare(share *fr.Element) ([]byte, error) {
    plaintext := share.Bytes()

    result, err := b.kmsClient.Encrypt(context.Background(), &kms.EncryptInput{
        KeyId:     aws.String(b.keyID),
        Plaintext: plaintext,
    })

    return result.CiphertextBlob, err
}
```

#### Implementation Locations

- **KeyStore**: `pkg/keystore/keystore.go`
- **Persistence (future)**: `pkg/keystore/persistent_store.go`
- **Backend Interface (future)**: `pkg/keystore/backend/`
- **Tests**: `pkg/keystore/keystore_test.go`

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

#### Complete TEE Integration Flow

For EigenX TEE-based applications, the complete integration:

```
┌──────────────────────────────────────────────────────────────────┐
│ TEE Application (Inside Intel TDX Enclave)                       │
│                                                                   │
│ Step 1: Generate Attestation                                     │
│   quote = TDX.GenerateQuote(reportData)                          │
│   ephemeralRSAKey = RSA.GenerateKey(2048)                        │
│                                                                   │
│ Step 2: Request Secrets from KMS Operators                       │
│   for operator in operators:                                      │
│       response = POST operator/secrets                            │
│                    Body: {                                        │
│                      "app_id": "my-tee-app",                      │
│                      "attestation": base64(quote),                │
│                      "rsa_pubkey_tmp": ephemeralRSAKey.Public(),  │
│                      "attest_time": currentTimestamp              │
│                    }                                              │
│                                                                   │
│       // Operator verifies attestation before responding          │
│       encryptedPartialSig = response.encrypted_partial_sig        │
│       decryptedPartialSig = RSA.Decrypt(ephemeralRSAKey,          │
│                                         encryptedPartialSig)       │
│       partialSigs.append(decryptedPartialSig)                     │
│                                                                   │
│ Step 3: Recover App Private Key (Inside TEE)                     │
│   sk_app = RecoverSignature(partialSigs, operatorNodeIDs)        │
│                                                                   │
│ Step 4: Decrypt Application Secrets                              │
│   secrets = IBE.Decrypt(sk_app, encryptedSecrets)                │
│   // Use secrets for database connections, API calls, etc.       │
└───────────────────────────────────────────────────────────────────┘
```

**Operator-Side Attestation Verification** (`pkg/node/tee_handler.go`):

```go
func (n *Node) handleSecrets(w http.ResponseWriter, r *http.Request) {
    var req SecretsRequest
    json.NewDecoder(r.Body).Decode(&req)

    // 1. Verify Intel TDX attestation quote
    attestation, err := base64.StdEncoding.DecodeString(req.Attestation)
    if err != nil {
        http.Error(w, "invalid attestation", http.StatusBadRequest)
        return
    }

    valid, err := tee.VerifyTDXQuote(attestation)
    if err != nil || !valid {
        http.Error(w, "attestation verification failed", http.StatusUnauthorized)
        return
    }

    // 2. Extract measurements from quote
    quote, _ := tee.ParseTDXQuote(attestation)

    // 3. Verify measurements match expected values for app
    expectedMeasurements := n.appRegistry.GetExpectedMeasurements(req.AppID)
    if !bytes.Equal(quote.RTMR0, expectedMeasurements.RTMR0) {
        http.Error(w, "measurement mismatch", http.StatusUnauthorized)
        return
    }

    // 4. Get key version for attestation time
    keyVersion := n.keystore.GetKeyVersionAtTime(req.AttestTime)
    if keyVersion == nil {
        http.Error(w, "no key for attestation time", http.StatusNotFound)
        return
    }

    // 5. Generate partial signature
    partialSig := crypto.GeneratePartialSignature(
        req.AppID,
        keyVersion.PrivateShare,
    )

    // 6. Encrypt partial signature with ephemeral RSA key
    rsaPubKey, _ := x509.ParsePKIXPublicKey([]byte(req.RSAPubKeyTmp))
    encryptedPartialSig, _ := rsa.EncryptOAEP(
        sha256.New(),
        rand.Reader,
        rsaPubKey.(*rsa.PublicKey),
        partialSig.Bytes(),
        nil,
    )

    // 7. Return encrypted response
    response := SecretsResponse{
        EncryptedEnv:         encryptSecrets(req.AppID),  // AES-encrypted
        PublicEnv:            getPublicEnv(req.AppID),
        EncryptedPartialSig:  base64.StdEncoding.EncodeToString(encryptedPartialSig),
    }

    json.NewEncoder(w).Encode(response)
}
```

**Security Properties:**
1. **Attestation Verification**: Only valid TEE instances receive secrets
2. **Measurement Binding**: Secrets tied to specific application code (RTMR0)
3. **Ephemeral Encryption**: Partial signatures encrypted with TEE-generated RSA key
4. **Forward Secrecy**: Ephemeral RSA key used once, then discarded

### Client Library Usage

**Go Client Example:**

```go
import "github.com/eigenx/kms-go/pkg/client"

func main() {
    // Initialize client
    kmsClient := client.NewKMSClient(&client.Config{
        AVSAddress:      common.HexToAddress("0xAVS..."),
        OperatorSetID:   0,
        RPCURL:          "https://sepolia.infura.io/v3/...",
        Timeout:         30 * time.Second,
    })

    // Encrypt secrets
    plaintext := []byte("DATABASE_URL=postgres://...")
    ciphertext, err := kmsClient.Encrypt("my-app", plaintext)
    if err != nil {
        log.Fatal(err)
    }

    // Save ciphertext to database/file
    saveEncryptedSecrets("my-app", ciphertext)

    // Later: decrypt secrets
    ciphertext = loadEncryptedSecrets("my-app")
    plaintext, err = kmsClient.Decrypt("my-app", ciphertext, 0)  // attestationTime=0 (use active key)
    if err != nil {
        log.Fatal(err)
    }

    // Use plaintext secrets
    log.Printf("Decrypted: %s", plaintext)
}
```

#### Implementation Locations

- **KMS Client**: `pkg/client/client.go`
- **CLI Tool**: `cmd/kmsClient/main.go`
- **TEE Handler**: `pkg/node/tee_handler.go`
- **TEE Verification (future)**: `pkg/tee/tdx_verifier.go`
- **Examples**: `examples/encrypt_decrypt/`

## What's Next

The current implementation provides a solid foundation for distributed key management with threshold cryptography. The following enhancements are planned for future releases:

### 1. Persistent Key Storage

**Current State**: Key shares stored in-memory, lost on node restart

**Planned Implementation**:
- **Storage Backend**: BoltDB or SQLite for embedded persistence
- **Encryption at Rest**: AES-256-GCM encryption of key shares using operator-derived keys
- **Atomic Operations**: Transactional writes to prevent partial state corruption
- **Version History**: Configurable retention policy for historical key versions
- **Backup/Restore**: Secure backup procedures with encrypted exports

**Design Considerations**:
```go
// Proposed persistent keystore interface
type PersistentKeyStore interface {
    // Store encrypted key share version
    StoreKeyVersion(version *KeyShareVersion) error

    // Load active key share
    LoadActiveKeyShare() (*KeyShareVersion, error)

    // Load key version by timestamp
    LoadKeyVersionAtTime(timestamp int64) (*KeyShareVersion, error)

    // List all stored versions
    ListVersions() ([]int64, error)

    // Prune old versions (beyond retention period)
    PruneOldVersions(retentionPeriod time.Duration) error
}
```

**Timeline**: Q2 2024

### 2. Intel TDX Attestation Verification

**Current State**: TEE `/secrets` endpoint exists but attestation verification is placeholder

**Planned Implementation**:
- **Quote Verification**: Full Intel TDX quote validation including:
  - Signature verification using Intel attestation keys
  - RTMR (Runtime Measurement Register) validation
  - TCB (Trusted Computing Base) level checking
  - Freshness verification (nonce/timestamp)

- **Measurement Registry**: On-chain or configuration-based registry of expected measurements:
  ```go
  type AppMeasurements struct {
      AppID              string
      ExpectedRTMR0      [48]byte  // Measurement of initial TEE state
      ExpectedRTMR1      [48]byte  // Measurement of runtime configuration
      MinTCBLevel        uint32     // Minimum acceptable TCB version
      AllowedSignerKeys  [][]byte   // Intel signing keys
  }
  ```

- **Attestation Flow**:
  ```
  1. TEE generates quote with report data containing:
     - Hash of ephemeral RSA public key
     - Application ID
     - Timestamp

  2. Operator verifies:
     - Quote signature (Intel signing key)
     - Report data integrity
     - Measurements match expected values
     - TCB level acceptable
     - Freshness (timestamp within window)

  3. If valid, operator returns encrypted partial signature
  ```

**Intel SGX Support**: Similar attestation flow for SGX enclaves (DCAP verification)

**Timeline**: Q3 2024

### 3. Backend Keystore Integration

**Current State**: BN254 private keys managed manually by operators

**Planned Implementation**:
- **AWS KMS Integration**:
  - Store operator BN254 private key in AWS KMS
  - Use KMS for message signing operations
  - Encrypt key shares using KMS data keys

- **GCP Cloud KMS Integration**:
  - Similar to AWS KMS
  - Support for GCP HSM-backed keys

- **HashiCorp Vault Integration**:
  - Store operator keys in Vault Transit engine
  - Use Vault for encryption/decryption of key shares
  - Dynamic credentials for enhanced security

- **Hardware Security Modules (HSMs)**:
  - PKCS#11 interface for standards-compliant HSMs
  - Support for network-attached HSMs (nShield, Thales, etc.)

**Interface Design**:
```go
type KeyBackend interface {
    // Sign message using operator private key
    SignMessage(hash []byte) (signature []byte, err error)

    // Encrypt key share for persistent storage
    EncryptShare(share *fr.Element) (ciphertext []byte, err error)

    // Decrypt key share from storage
    DecryptShare(ciphertext []byte) (share *fr.Element, err error)

    // Get operator public key
    GetPublicKey() (*ecdsa.PublicKey, error)
}

// Example: AWS KMS backend
type AWSKMSBackend struct {
    kmsClient    *kms.Client
    signingKeyID string
    dataKeyID    string
}

// Example: Vault backend
type VaultBackend struct {
    vaultClient *vault.Client
    transitPath string
    keyName     string
}
```

**Configuration**:
```yaml
# kms-config.yaml
keyBackend:
  type: aws-kms  # Options: aws-kms, gcp-kms, vault, hsm, local
  awsKMS:
    signingKeyID: "arn:aws:kms:us-east-1:123456789012:key/..."
    dataKeyID: "arn:aws:kms:us-east-1:123456789012:key/..."
    region: us-east-1
  vault:
    address: "https://vault.example.com:8200"
    transitPath: "/transit"
    keyName: "kms-operator-key"
    authMethod: kubernetes  # or aws, gcp, token
```

**Timeline**: Q3-Q4 2024

### 4. Additional Future Enhancements

**Metrics and Observability**:
- Prometheus metrics export
- Protocol success/failure rates
- Latency tracking for DKG/reshare operations
- Operator availability monitoring

**Performance Optimizations**:
- Parallel share verification
- Batch message processing
- Connection pooling for operator communication
- Caching of operator public keys

**Protocol Enhancements**:
- Proactive secret sharing for reduced round trips
- Batch DKG for multiple applications
- Master secret rotation (full key refresh)

**Governance**:
- On-chain configuration management
- Operator voting for parameter changes
- Emergency pause mechanisms

**Cross-Chain Support**:
- Deployment to additional EVM chains (Arbitrum, Optimism, Base)
- Cross-chain key synchronization

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

**Option 2: Go + Native Libraries (gnark-crypto, eigensdk-go)**
- **gnark-crypto**: Production-grade elliptic curve cryptography library by Consensys
- **eigensdk-go**: Official EigenLayer SDK for AVS development
- **Benefits**: Excellent library support, team expertise, mature ecosystem
- **Challenges**: Manual protocol implementation required

### Decision: Go + Native Libraries

**Primary Factors:**

1. **Team Expertise**
   - **Sean (Lead Developer)**: Expert-level Go experience, limited Rust experience
   - **Development Velocity**: Immediate productivity vs. learning curve
   - **Debugging Efficiency**: Familiar tooling and debugging workflows
   - **Code Review**: Easier review process with team's Go background

   **Impact**: Estimated 2-3x faster development time with Go vs. learning Rust + Commonware

2. **Cryptographic Library Maturity: gnark-crypto**
   - **Battle-Tested**: Used in production by major projects (Polygon zkEVM, Scroll, Linea)
   - **Audit Status**: Extensively audited by Trail of Bits, Consensys Diligence, and others
   - **BLS12-381 Support**: Complete implementation with pairing operations
   - **BN254 Support**: Native EigenLayer-compatible curve
   - **Performance**: Highly optimized assembly implementations for critical operations
   - **Documentation**: Comprehensive docs and examples

   **Example Performance** (Apple M1):
   ```
   BLS12-381 Operations (gnark-crypto):
   - G1 scalar multiplication: ~1.2ms
   - G2 scalar multiplication: ~3.5ms
   - Pairing operation: ~8ms
   - Share verification: ~4ms

   Sufficient for KMS use case (not latency-critical)
   ```

   **Commonware Status** (at decision time):
   - Emerging library with less battle-testing
   - Smaller audit history
   - Growing but less comprehensive documentation
   - Excellent for consensus protocols, less focused on threshold cryptography

3. **EigenLayer Ecosystem Compatibility**
   - **eigensdk-go**: Official AVS SDK with contract bindings, operator utilities
   - **Reference Implementations**: Multiple production AVSs written in Go
   - **Tooling**: Established patterns for operator registration, contract interaction
   - **Community Support**: Larger Go-based AVS developer community

   **Rust/Commonware Status**:
   - EigenLayer Rust SDK exists but less mature
   - Fewer reference implementations
   - Smaller community of Rust AVS developers

4. **Development Ecosystem**
   - **Go Benefits**:
     - Mature testing frameworks (testify, mock, integration test patterns)
     - Rich HTTP ecosystem (net/http, chi, gin)
     - Excellent profiling and debugging tools (pprof, delve)
     - Fast compilation times
     - Simple dependency management (go modules)

   - **Rust Tradeoffs**:
     - Longer compilation times (impacts iteration speed)
     - More complex dependency resolution
     - Steeper learning curve for contributors

5. **Threshold Cryptography Implementation**
   - **Go Approach**: Manual DKG/reshare implementation using gnark-crypto primitives
     - Full control over protocol details
     - Transparent implementation for auditing
     - Customizable for EigenLayer-specific requirements

   - **Commonware Approach**: Would provide higher-level abstractions
     - Less flexibility for custom protocol requirements
     - Potential overhead from generalized framework

### What Commonware Excels At

It's important to note that Commonware is **excellent for certain use cases**:

1. **Consensus-Heavy Applications**: Raft, PBFT, or other consensus protocols are first-class
2. **Generic Distributed State Machines**: Framework abstractions handle replication elegantly
3. **Rust Performance-Critical Systems**: Memory safety + performance for systems programming
4. **Novel Protocol Research**: Quick prototyping of new distributed protocols

**EigenX KMS Fit**: Our system uses **interval-based scheduling** rather than consensus, and **threshold cryptography** rather than state machine replication. This doesn't align with Commonware's sweet spot.

### Technical Trade-offs Accepted

**By choosing Go, we accepted:**

1. **Manual Protocol Implementation**: Had to implement DKG/reshare from scratch
   - **Mitigation**: Comprehensive integration tests, formal verification (future), external audits

2. **No Built-in Consensus**: Using interval-based timing instead
   - **Mitigation**: Blockchain provides truth for operator discovery, deterministic scheduling

3. **Memory Safety via Convention**: Go's GC vs. Rust's compile-time guarantees
   - **Mitigation**: Careful code review, static analysis (golangci-lint), fuzzing

**Benefits Gained:**

1. **Faster Time-to-Market**: 3-4 month timeline vs. estimated 6-9 months with Rust learning curve
2. **Code Confidence**: Deep understanding of Go idioms and pitfalls
3. **Library Confidence**: gnark-crypto's audit trail and production usage
4. **Team Scalability**: Easier to onboard future Go developers than Rust experts
5. **Debugging Efficiency**: Familiar tools significantly reduce bug investigation time

### Architectural Validation

**Indicators this was the right choice:**

1. **Rapid Prototyping**: Proof-of-concept completed in 4 weeks
2. **Integration Success**: EigenLayer integration worked first-try with eigensdk-go
3. **Testing Coverage**: Comprehensive integration tests with testutil patterns
4. **Performance**: Threshold cryptography operations complete in acceptable timeframes:
   - DKG (7 operators): ~2-3 seconds
   - Reshare (7 operators): ~1-2 seconds
   - App signature collection: ~500-800ms

5. **Code Quality**: Maintainable, reviewable codebase with clear separation of concerns

### Future Considerations

**If we were to reconsider Rust/Commonware:**

1. **Consensus Requirement**: If we added leader election or Byzantine agreement
2. **Ultra-Low Latency**: If signature collection needed <100ms latencies
3. **Memory-Critical Deployment**: Embedded systems or resource-constrained environments
4. **Team Evolution**: If team gained significant Rust expertise
5. **Commonware Maturity**: If Commonware added robust threshold crypto primitives with audits

**Current Recommendation**: **Stick with Go** unless one of the above scenarios materializes.

### Conclusion

The decision to use **Go with gnark-crypto and eigensdk-go** was driven by:
- Team expertise and development velocity
- Production-ready, audited cryptographic libraries
- Strong EigenLayer ecosystem fit
- Appropriate performance characteristics for the use case

While **Commonware/Rust offers compelling benefits** for consensus-heavy or performance-critical systems, the EigenX KMS architecture (interval-based scheduling + threshold cryptography) is well-served by Go's mature ecosystem and the team's existing expertise.

This decision can be revisited as the team, tools, and requirements evolve, but the current implementation validates that Go was the pragmatic and effective choice for this project.

---

**Contributors to this decision**:
- Sean McGary (Lead Developer, Go expert)
- EigenX Team (Architecture review)

**Date**: Q4 2023

**Reviewed**: Ongoing (reassess annually or when requirements change significantly)
