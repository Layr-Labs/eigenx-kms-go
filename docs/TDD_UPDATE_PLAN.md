# TDD Update Plan - Systematic Changes Needed

## Completed ✅
- [x] Updated Goals section to include Pedersen-VSS implementation path
- [x] Updated Key System Guarantees section with comprehensive guarantees

## Changes to Make

### 1. Component Responsibilities (Replace entire section)

**Current Issue**: Too code-focused, shows implementation details
**Needed**: API contracts, architectural boundaries, data flows

**New Content Structure**:
```markdown
### Component Responsibilities and API Contracts

#### KMS Node Server
**Responsibility**: Manages protocol lifecycle and exposes HTTP APIs for inter-operator communication and application requests.

**Public API Contract**:
- Protocol endpoints (authenticated): `/dkg/*`, `/reshare/*`
- Application endpoints (public): `/pubkey`, `/app/sign`, `/secrets`
- Health monitoring: `/health`, `/metrics`

**Key Behaviors**:
- Automatic protocol scheduling at interval boundaries
- Session management for concurrent DKG/reshare runs
- Request authentication via BN254 signature verification

---

#### Protocol Engines (DKG/Reshare)
**Responsibility**: Execute distributed cryptographic protocols for key generation and rotation.

**Interface Contract**:
```
GenerateShares() → (shares map[nodeID]share, commitments []G2Point)
VerifyShare(nodeID, share, commitments) → bool
FinalizeKeyShare(shares, commitments, participants) → KeyShareVersion
```

**Key Behaviors**:
- Pedersen-VSS with dual polynomial commitments (production)
- Feldman-VSS with single polynomial (alpha testnet)
- Three-phase execution: commit, verify, finalize
- Acknowledgement system for equivocation prevention

---

#### Transport Layer
**Responsibility**: Provides authenticated, reliable message delivery between operators.

**Message Contract**:
```
AuthenticatedMessage {
    payload: serialized message
    hash: keccak256(payload)
    signature: BN254_sign(hash, privateKey)
}
```

**Key Behaviors**:
- Automatic message signing/verification
- Retry logic with exponential backoff
- Broadcast support (zero-address routing)
- Peer validation via peering system

---

#### Cryptographic Operations
**Responsibility**: Provides primitive cryptographic operations for threshold protocols.

**Operation Contract**:
- BLS12-381: polynomial operations, share verification, Lagrange interpolation
- BN254: message signing/verification for P2P authentication
- IBE: identity-based encryption/decryption for application secrets

**Key Behaviors**:
- Constant-time operations where possible
- Input validation and error handling
- Deterministic output for same inputs

---

#### Key Store
**Responsibility**: Manages versioned key share storage with time-based lookups.

**Storage Interface**:
```
StoreKeyShareVersion(version KeyShareVersion) → error
GetActiveKeyShare() → KeyShareVersion
GetKeyVersionAtTime(timestamp int64) → KeyShareVersion
```

**Key Behaviors**:
- Epoch-based versioning using session timestamps
- Active/inactive version tracking
- Historical version retention for attestation time validation
```

### 2. Automatic Scheduling (Simplify - remove all code)

**Keep**: High-level description and diagram
**Remove**: All Go code examples, implementation details

**New Content**:
```markdown
### Automatic Scheduling

The system uses interval-based scheduling to coordinate protocol execution without consensus:

**Scheduling Mechanism**:
1. Operators query current time and compute next interval boundary
2. At boundary, operators fetch current operator set from blockchain
3. Operators determine protocol (DKG if no keys, Reshare if keys exist)
4. Protocol executes in background goroutine
5. Session timestamp ensures all operators coordinate on same execution

**Interval Configuration**:
- Mainnet: 10 minutes (production security/cost balance)
- Sepolia: 2 minutes (faster testing iteration)
- Anvil: 30 seconds (rapid development)

**Benefits**:
- No leader election required (deterministic timing)
- Supports operator churn (set fetched each interval)
- Resilient to transient failures (retry at next interval)
```

### 3. DKG Process (Update for Pedersen-VSS)

**Changes Needed**:
1. Update protocol description to show Pedersen-VSS flow
2. Add section explaining Feldman vs Pedersen tradeoffs
3. Keep mathematical descriptions, remove code

**New Section to Add**:
```markdown
#### Pedersen-VSS vs Feldman-VSS

**Alpha Testnet (Current)**: Feldman-VSS
- Single polynomial: f_i(z)
- Commitments: C_ik = g^(a_ik)
- Security: Computational (discrete log assumption)
- Vulnerability: Timing-based bias attacks possible
- Mitigation: Economic security via slashing

**Production Target**: Pedersen-VSS
- Dual polynomials: f_i(z), f'_i(z)
- Commitments: C_ik = g^(a_ik) * h^(b_ik)
- Security: Information-theoretic hiding
- Protection: Bias attacks cryptographically impossible
- Requirement: Generate h via distributed coin flip

**Migration Path**:
1. Deploy alpha with Feldman-VSS + fraud proofs
2. Implement Pedersen-VSS in parallel branch
3. Test on testnet with both protocols
4. Audit Pedersen implementation
5. Upgrade before mainnet launch
```

### 4. Operator Scenarios (Convert to plain English)

**Remove**: All Go code
**Keep**: Scenario descriptions as narratives

**New Format**:
```markdown
#### Reshare Scenarios

**Scenario 1: Existing Operator (Routine Key Rotation)**

An operator that participated in the previous DKG or reshare executes periodic key rotation:

1. **Retrieve Current Share**: Operator loads active key share from local keystore
2. **Generate Reshare Polynomial**: Creates new polynomial where f'(0) = currentShare
   - Critical: Constant term must equal current share to preserve master secret
   - Higher-degree terms chosen randomly
3. **Distribute New Shares**: Evaluates polynomial at all operator node IDs
   - Sends shares to both existing and new operators
   - Broadcasts commitments to all participants
4. **Compute New Share**: Uses Lagrange interpolation to compute updated share
   - Coefficients computed for existing operator set
   - New share = Σ(λ_i * received_share_i)
5. **Activate New Version**: Stores new key share version, marks previous inactive

**Properties**:
- Master secret S remains unchanged: S' = S
- Old shares become cryptographically useless (forward secrecy)
- New threshold may differ if operator set size changed

---

**Scenario 2: New Operator (Joining Cluster)**

An operator joining an existing cluster for the first time:

1. **Passive Participation**: Operator does NOT generate or distribute shares
   - Only existing operators share their current secrets
   - New operator is a receiver only in this reshare
2. **Receive Shares**: Collects shares from all existing operators
3. **Verify Shares**: Validates each share against commitments
4. **Compute First Share**: Uses Lagrange interpolation with existing operators' node IDs
   - Same computation as existing operators
   - Results in valid share of unchanged master secret
5. **Store Initial Version**: Saves first key share, becomes full participant

**Properties**:
- New operator cannot influence master secret (passive receiver)
- Master secret S unchanged despite operator set expansion
- Immediately capable of participating in threshold operations
```

### 5. Remove Entire Sections

Delete these sections completely:
- "Operator Registration Flow" (standard EigenLayer)
- "Peering Data Fetcher" implementation details
- "HTTP Server Implementation"
- "Client Request Flow" (covered by diagrams)
- All "Implementation Locations" subsections
- Code examples in "Cryptographic Components"

### 6. Simplify Peering System

**Replace detailed implementation with**:
```markdown
### Operator Discovery and Peering

**High-Level Flow**:
```
┌─────────────┐
│  KMS Node   │
└──────┬──────┘
       │
       │ 1. Query operator set
       ▼
┌─────────────────────┐
│ OperatorSetRegistrar│  (EigenLayer Contract)
│ Smart Contract      │
└──────┬──────────────┘
       │ Returns: [operatorAddress, ...]
       │
       │ 2. For each operator, fetch BN254 key + socket
       ▼
┌─────────────────────┐
│  KeyRegistrar       │
│  Smart Contract     │
└──────┬──────────────┘
       │ Returns: [(address, publicKey, socketAddress), ...]
       │
       │ 3. Build peer list
       ▼
┌──────────────────────────┐
│  OperatorSetPeer[]       │
│  - address               │
│  - bn254PublicKey        │
│  - socketAddress (HTTP)  │
└──────────────────────────┘
```

**Interface Contract**:
```
GetOperators() → []OperatorSetPeer
```

**Implementations**:
- `ContractPeeringDataFetcher`: Production (queries blockchain)
- `LocalPeeringDataFetcher`: Testing (uses ChainConfig)
```

### 7. Protocol APIs (Remove all Go code)

Keep API contract definitions only:

```markdown
### Protocol API Specification

#### Authenticated Endpoints (Inter-Operator)

All protocol messages wrapped in `AuthenticatedMessage` with BN254 signature.

**DKG Endpoints**:
```
POST /dkg/commitment
  Body: AuthenticatedMessage<CommitmentMessage>
  Response: 200 OK | 400 Bad Request

POST /dkg/share
  Body: AuthenticatedMessage<ShareMessage>
  Response: 200 OK | 400 Bad Request | 401 Unauthorized

POST /dkg/ack
  Body: AuthenticatedMessage<AcknowledgementMessage>
  Response: 200 OK | 400 Bad Request
```

**Reshare Endpoints**:
```
POST /reshare/commitment
POST /reshare/share
POST /reshare/ack
POST /reshare/complete
  (Same message format as DKG)
```

#### Application Endpoints (Public)

**Master Public Key Query**:
```
GET /pubkey
  Response: {
    operatorAddress: string,
    commitments: G2Point[],
    version: int64,
    isActive: bool
  }
```

**Partial Signature Request**:
```
POST /app/sign
  Request: {
    appID: string,
    attestationTime?: int64
  }
  Response: {
    operatorAddress: string,
    partialSignature: G1Point,
    version: int64
  }
```

**TEE Secret Delivery** (Attestation-verified):
```
POST /secrets
  Request: {
    app_id: string,
    attestation: string (base64 TDX quote),
    rsa_pubkey_tmp: string (PEM),
    attest_time: int64
  }
  Response: {
    encrypted_env: string,
    public_env: string,
    encrypted_partial_sig: string
  }
```
```

### 8. Security Model (Major Update)

Add comprehensive analysis covering:
1. Pedersen-VSS security properties
2. Threat model
3. Attack scenarios and defenses
4. Comparison with Feldman-VSS
5. Economic security model

See separate document for full content.

### 9. Add Slashing Conditions Section

New section after Security Model:

```markdown
## Fraud Detection and Slashing

### Overview

The KMS implements cryptographic fraud proofs enabling on-chain detection and punishment of protocol violations. Operators monitor each other's behavior and submit verifiable proofs of misbehavior to the slashing contract.

### Detectable Fraud Types

1. **Invalid Share**: Dealer sends share that doesn't verify against broadcast commitments
2. **Equivocation**: Dealer sends different shares to different operators
3. **Commitment Inconsistency**: Dealer broadcasts different commitments to different operators
4. **Protocol Deviation**: Operator fails to follow DKG/reshare specification

### Fraud Proof Mechanism

**Detection**: Operator identifies violation during protocol execution
**Proof Construction**: Operator collects cryptographic evidence (signatures, commitments, shares)
**Submission**: Proof submitted to `EigenKMSSlashing` smart contract via transaction
**Verification**: Contract verifies proof on-chain (cryptographic validation)
**Slashing**: Verified fraud triggers automatic slashing via AllocationManager

### Slashing Thresholds

**Invalid Shares**:
- Threshold: 3 independent complaints
- Penalty: 0.1 ETH per fraud (escalating)
- Action: Slash + monitor for repeated violations

**Equivocation**:
- Threshold: 1 cryptographic proof
- Penalty: 1 ETH (severe violation)
- Action: Immediate slash + ejection consideration

**Repeated Violations**:
- Threshold: 3 sessions with fraud
- Penalty: Full stake slash
- Action: Automatic ejection from operator set

### Security Properties

- **Economic Deterrence**: Cost of fraud exceeds any potential gain
- **Self-Healing**: Malicious operators automatically removed
- **Transparent**: All fraud proofs publicly verifiable on-chain
- **Trustless**: Smart contract verification (no human adjudication)

See `docs/003_fraudProofs.md` for implementation details.
```

### 10. Persistence Section (Update to interface-based)

Replace implementation-specific content:

```markdown
### Key Share Persistence

**Current State**: In-memory only (ephemeral)
**Production Requirement**: Durable persistence with encryption at rest

#### Persistence Interface

```
type KeySharePersistence interface {
    // Store encrypted key share version
    Store(version *KeyShareVersion) error

    // Load active key share
    LoadActive() (*KeyShareVersion, error)

    // Load key version by timestamp
    LoadAtTime(timestamp int64) (*KeyShareVersion, error)

    // List all stored versions
    ListVersions() ([]int64, error)

    // Prune old versions beyond retention period
    Prune(retentionPeriod time.Duration) error
}
```

#### Design Requirements

1. **Encryption at Rest**: All key shares encrypted with operator-derived key
2. **Atomic Writes**: Prevent partial state corruption during crashes
3. **Version History**: Configurable retention period (default: 30 days)
4. **Fast Lookups**: Index by version timestamp for O(log n) retrieval
5. **Crash Recovery**: Restore consistent state after unexpected shutdown

#### Candidate Implementations

**BadgerDB** (Embedded Key-Value Store):
- Pros: Pure Go, ACID guarantees, fast lookups, built-in encryption
- Cons: Single-writer limitation, requires periodic compaction
- Use Case: Default implementation for most deployments

**SQLite** (Embedded Relational DB):
- Pros: SQL queries, widely understood, excellent tooling
- Cons: Write performance lower than BadgerDB
- Use Case: Operators preferring SQL for operations/debugging

**External KMS** (HashiCorp Vault, AWS KMS, etc.):
- Pros: Enterprise-grade security, centralized key management
- Cons: External dependency, network latency
- Use Case: Enterprise deployments with existing KMS infrastructure

#### Encryption Scheme

```
Key Derivation: HKDF-SHA256(operatorBN254PrivateKey, "kms-keyshare-encryption")
Encryption: AES-256-GCM (authenticated encryption)
Key Rotation: Supported via re-encryption with new derived key
```
```

### 11. TEE Integration (Add Intel API callout)

Add to TEE Integration section:

```markdown
### Intel TDX Attestation Verification

**Attestation Provider**: Intel Trust Authority (production) or Intel DCAP libraries (self-hosted)

**Verification Flow**:
1. TEE generates attestation quote via TDX APIs
2. KMS receives quote in `/secrets` request
3. KMS calls Intel's attestation verification API:
   ```
   POST https://api.trustauthority.intel.com/appraisal/v2/attest
   Headers:
     Authorization: Bearer <api-key>
   Body:
     quote: <base64-encoded-tdx-quote>
     runtime_data: <nonce-or-pubkey-hash>
   Response:
     token: <jwt-with-verification-result>
     tcb_status: <up-to-date|out-of-date|revoked>
     measurements: { rtmr0, rtmr1, rtmr2, rtmr3 }
   ```
4. KMS validates JWT signature (Intel signing key)
5. KMS checks TCB status and measurements
6. If valid, proceeds with key delivery

**Security Properties**:
- Intel as root of trust for hardware authenticity
- JWT prevents MITM on verification results
- TCB status ensures up-to-date firmware
- RTMR measurements bind to specific code

**Implementation**: Use Intel's official Go SDK for attestation verification
```

### 12. Implementation Timeline (New Section)

Add before "What's Next" section:

```markdown
## Implementation Timeline

### Phase 1: Alpha Testnet (Weeks 1-8)

**Week 1-2: Fraud Proof System**
- [ ] Deploy `EigenKMSSlashing.sol` contract
- [ ] Implement fraud detection in DKG/Reshare handlers
- [ ] Add fraud proof submission logic
- [ ] Configure slashing thresholds
- Deliverable: Working fraud detection on Anvil testnet

**Week 3-4: Feldman-VSS Hardening**
- [ ] Comprehensive integration test suite
- [ ] Fuzz testing for DKG/Reshare protocols
- [ ] Performance benchmarking (7, 10, 15 operators)
- [ ] Monitoring and alerting infrastructure
- Deliverable: Production-ready Feldman implementation

**Week 5-6: TEE Integration**
- [ ] Intel Trust Authority API integration
- [ ] Attestation verification implementation
- [ ] RTMR measurement validation logic
- [ ] `/secrets` endpoint with attestation checks
- Deliverable: End-to-end TEE authentication flow

**Week 7-8: Alpha Deployment**
- [ ] Deploy to Sepolia testnet
- [ ] Onboard 5-7 test operators
- [ ] Run continuous DKG/Reshare cycles
- [ ] Monitor for fraud attempts and performance
- Deliverable: Public alpha testnet

### Phase 2: Pedersen-VSS Migration (Weeks 9-14)

**Week 9-10: Pedersen-VSS Implementation**
- [ ] Implement dual-polynomial VSS
- [ ] Distributed coin flip for h generation
- [ ] Two-phase DKG protocol
- [ ] Unit and integration tests
- Deliverable: Complete Pedersen-VSS implementation

**Week 11-12: Migration Tooling**
- [ ] Protocol version negotiation
- [ ] Parallel testnet (Feldman + Pedersen)
- [ ] Migration testing and validation
- [ ] Performance comparison
- Deliverable: Proven migration path

**Week 13-14: Security Audit Prep**
- [ ] Code freeze for audit scope
- [ ] Documentation review and updates
- [ ] Threat model formalization
- [ ] Test coverage >90%
- Deliverable: Audit-ready codebase

### Phase 3: Production Readiness (Weeks 15-20)

**Week 15-17: External Security Audit**
- [ ] Contract audit (2 weeks)
- [ ] Protocol audit (2 weeks)
- [ ] Address findings (1 week)
- Deliverable: Audit report with no critical issues

**Week 18-19: Persistence Layer**
- [ ] Implement BadgerDB persistence
- [ ] Key share encryption at rest
- [ ] Crash recovery testing
- [ ] Backup/restore procedures
- Deliverable: Durable key storage

**Week 20: Mainnet Launch Prep**
- [ ] Mainnet deployment plan
- [ ] Operator onboarding docs
- [ ] Incident response playbook
- [ ] Monitoring and alerts
- Deliverable: Ready for mainnet launch

### Phase 4: Mainnet and Beyond (Week 21+)

**Week 21-22: Mainnet Launch**
- [ ] Deploy contracts to Ethereum mainnet
- [ ] Onboard initial operator set (5-7 operators)
- [ ] Execute genesis DKG
- [ ] Monitor first 48 hours closely
- Deliverable: Live production KMS

**Ongoing: Enhancements**
- Backend keystore integration (AWS KMS, Vault, HSMs)
- Cross-chain deployment (Arbitrum, Optimism, Base)
- Advanced monitoring and analytics
- Operator reputation system
```

## Summary of Changes

Total sections affected: ~15
Lines of code to remove: ~2000+
New architectural content: ~1000 lines
Focus shift: Implementation → Architecture/Security/API contracts
