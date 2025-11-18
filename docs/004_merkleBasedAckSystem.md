# Merkle-Based Acknowledgement System - Implementation Execution Plan

## Document Purpose
This document provides a detailed, step-by-step execution plan for implementing the merkle-based acknowledgement system described in `docs/merkle-based-ack-system.md`. It maps the theoretical design to concrete code changes in the EigenX KMS codebase.

---

## Implementation Status

**Overall Progress:** 4/7 phases complete (57%)

**Current Phase:** Phase 5 - Transport Layer Enhancements

**Last Updated:** Phase 4 completed with all quality gates passed

---

## Table of Contents
1. [Development Guidelines](#development-guidelines)
2. [Architecture Overview](#architecture-overview)
3. [Current State Analysis](#current-state-analysis)
4. [Implementation Phases](#implementation-phases)
5. [Detailed Implementation Steps](#detailed-implementation-steps)
6. [Testing Strategy](#testing-strategy)
7. [Security Considerations](#security-considerations)
8. [Cost Analysis](#cost-analysis)

---

## Development Guidelines

### Critical Requirements

**⚠️ MANDATORY: These guidelines MUST be followed for every phase of implementation.**

#### 1. Sequential Execution
- **Complete milestones/phases strictly in order** (Phase 1 → Phase 2 → Phase 3 → ...)
- **Do NOT skip ahead** or work on multiple phases simultaneously
- **Do NOT start Phase N+1** until Phase N is 100% complete and verified

#### 2. Self-Contained Milestones
Each phase/milestone must be:
- **Self-contained** with all relevant code changes
- **Fully tested** with comprehensive test coverage
- **Independently verifiable** without depending on future phases

**Each phase MUST include:**
- ✅ Implementation code
- ✅ Unit tests for new functionality
- ✅ Integration tests (where applicable)
- ✅ Documentation updates
- ✅ All tests passing (no regressions)
- ✅ Code passing linter checks

#### 3. Test-As-You-Go
- **DO NOT save testing for the end**
- **Write tests alongside implementation** (TDD encouraged)
- **Run tests continuously** during development
- **Every commit should have passing tests**

#### 4. Definition of "Complete"
A milestone is considered complete when:
1. ✅ **All implementation code is written** according to spec
2. ✅ **All unit tests are written and passing** (no skipped tests)
3. ✅ **All integration tests are written and passing** (where applicable)
4. ✅ **No test regressions** (all existing tests still pass)
5. ✅ **Linter passes with zero warnings/errors** (`make lint`)
6. ✅ **Code is formatted** (`make fmt`)
7. ✅ **Documentation is updated** (inline comments, README, etc.)

#### 5. Quality Gates
Before moving to the next phase, verify:

```bash
# Run all tests
make test

# Run linter
make lint

# Check formatting
make fmtcheck

# Build all binaries (ensure no compile errors)
make all
```

**All commands must exit with code 0 (success) before proceeding.**

#### 6. Phase Completion Checklist
After completing each phase, verify:
- [ ] All deliverables from phase specification are complete
- [ ] `make test` passes with 100% of tests passing
- [ ] `make lint` passes with zero warnings
- [ ] `make fmt` applied successfully
- [ ] All new code has test coverage
- [ ] No existing tests broken (regression check)
- [ ] Documentation updated (inline comments, function docs)
- [ ] Code reviewed (self-review or peer review)
- [ ] Git commit with clear message describing phase completion

#### 7. Rollback Strategy
If a phase cannot be completed:
- **Do NOT proceed to next phase**
- **Document blockers** and issues encountered
- **Seek clarification** or architectural guidance
- **Consider alternative approaches** within the current phase
- **Only proceed when phase can be completed successfully**

---

## Architecture Overview

### High-Level Changes

The merkle-based acknowledgement system transforms the acknowledgement phase of DKG/Reshare protocols:

**Current Flow:**
```
Phase 1: Share Distribution
Phase 2: Send Acks � Wait for Threshold Acks
Phase 3: Finalize (sum shares)
```

**New Flow:**
```
Phase 1: Share Distribution
Phase 2: Send Acks � Collect ALL Acks � Build Merkle Tree � Submit to Contract
Phase 3: Broadcast Commitments + Acks + Proofs � Verify Against Contract
Phase 4: Finalize (sum shares)
```

### Key Benefits
1. **Fraud Detection:** Merkle roots committed on-chain prevent equivocation
2. **Cost Efficient:** 64 bytes per operator per epoch (~$17/month for 10 operators)
3. **Verifiable:** Any operator can verify others' dealings against on-chain roots
4. **Symmetric:** Every operator is both dealer and player

---

## Current State Analysis

### Existing Components (Reusable)

#### 1. DKG Protocol (`pkg/dkg/dkg.go`)
-  Fully distributed: every operator generates polynomial and deals to everyone
-  Three-phase protocol structure
-  BLS12-381 G2 commitments for verification
-  Address-to-NodeID conversion
-  Threshold calculation: 2n/3	

#### 2. Acknowledgement Structure (`pkg/types/types.go`)
-  `Acknowledgement` struct with dealer/player IDs
-  Commitment hash included
-  BN254 signature for authentication
- � **Missing:** ShareHash field (needs to be added)
- � **Missing:** Epoch field (needs to be added)

#### 3. Transport Layer (`pkg/transport/client.go`)
-  Authenticated messaging with BN254 signatures
-  Retry logic with exponential backoff
-  Dedicated functions for each message type
- � **Missing:** Broadcast with operator-specific merkle proofs

#### 4. Node Orchestration (`pkg/node/node.go`)
-  Session management with timestamp-based coordination
-  Storage maps for shares, commitments, acks
-  Wait-for-session logic for race conditions
- � **Needs modification:** Collect ALL acks, not just threshold

#### 5. Contract Interaction (`pkg/contractCaller/`)
-  Operator set queries
-  Registration functions
- � **Missing:** Commitment submission/query functions

### Components to Create (New)

#### 1. Merkle Tree Package (`pkg/merkle/`)
- L Tree builder with deterministic ordering
- L Proof generator
- L Proof verifier
- L Keccak256 hashing for Solidity compatibility

#### 2. Commitment Registry Contract (`contracts/src/`)
- L Storage: epoch � operator � (commitmentHash, ackMerkleRoot)
- L Submit commitment function
- L Query commitment function
- L Events for monitoring

---

## Implementation Phases

### Phase Progress Tracker

- [x] **Phase 1**: Core Merkle Tree Infrastructure ✅
- [x] **Phase 2**: Smart Contract Extensions ✅
- [x] **Phase 3**: Data Structure Updates ✅
- [x] **Phase 4**: DKG/Reshare Protocol Modifications ✅
- [ ] **Phase 5**: Transport Layer Enhancements
- [ ] **Phase 6**: Verification Flow
- [ ] **Phase 7**: End-to-End Integration Testing
- [ ] **Phase 8**: Fraud Detection (Future/Optional)

---

### Phase 1: Core Merkle Tree Infrastructure (2-3 days) ✅ COMPLETE

**Goal:** Create production-ready merkle tree package with full test coverage

**Deliverables:**
- [x] `pkg/merkle/merkle.go` - Core implementation
- [x] `pkg/merkle/merkle_test.go` - Comprehensive unit tests
- [x] `pkg/merkle/types.go` - Data structures

**Key Features:**
- [x] Binary merkle tree with keccak256 hashing
- [x] Deterministic ordering (sort by player address)
- [x] Efficient proof generation
- [x] Proof verification matching Solidity behavior

**Completion Criteria:**
- [x] All merkle tree functions implemented (BuildMerkleTree, GenerateProof, VerifyProof, etc.)
- [x] Unit tests covering 1, 2, 3, 4, 7, 8, 15, 16 acknowledgements (power-of-2 and non-power-of-2)
- [x] Tests for sorting determinism
- [x] Tests for proof verification (valid and invalid proofs)
- [x] Tests for edge cases (empty list, single ack, etc.)
- [x] Benchmark tests for performance measurement
- [x] `go test ./pkg/merkle/... -v` passes with 100% tests passing
- [x] `make lint` passes with zero warnings in pkg/merkle/
- [x] All functions have godoc comments
- [x] No dependencies on other phases (Phase 1 is standalone)

**Quality Gate:**
```bash
go test ./pkg/merkle/... -v -race -coverprofile=coverage.out
go tool cover -func=coverage.out | grep total  # Should show >90% coverage
make lint
```

---

### Phase 2: Smart Contract Extensions (2-3 days) ✅ COMPLETE

**Goal:** Deploy commitment registry with submission and query capabilities

**Deliverables:**
- [x] `contracts/src/EigenKMSCommitmentRegistry.sol` - Main contract
- [x] `contracts/test/EigenKMSCommitmentRegistry.t.sol` - Foundry tests
- [x] `pkg/contractCaller/caller/commitmentRegistry.go` - Go wrapper functions
- [x] Updated `scripts/compileMiddlewareBindings.sh` for binding generation

**Key Features:**
- [x] Per-epoch, per-operator storage
- [x] Gas-optimized submission (~74k gas per operator in tests)
- [x] Query functions for verification phase
- [x] Event emission for off-chain monitoring

**Completion Criteria:**
- [x] Solidity contract implemented with all functions (submitCommitment, getCommitment)
- [x] Foundry tests covering all contract functions (14 tests total)
- [x] Test for successful submission
- [x] Test for duplicate submission rejection
- [x] Test for invalid parameter rejection
- [x] Test for event emission
- [x] Gas cost measurement test (verified < 100k gas)
- [x] Go bindings generated using `abigen` via compilation script
- [x] Go wrapper functions in `pkg/contractCaller/caller/commitmentRegistry.go`
- [x] Go unit tests for contract caller functions
- [x] `forge test` passes with 100% tests passing (14/14)
- [x] `forge fmt` applied to all Solidity files
- [x] `./scripts/goTest.sh ./pkg/contractCaller/...` passes
- [x] `make lint` passes for Go code (0 issues)
- [x] All contracts have NatSpec documentation

**Quality Gate:**
```bash
# Solidity tests
cd contracts
forge test -vv
forge fmt --check

# Go tests
go test ./pkg/contractCaller/... -v -race
make lint
```

---

### Phase 3: Data Structure Updates (1 day) ✅ COMPLETE

**Goal:** Extend acknowledgement structures to support merkle system

**Deliverables:**
- [x] Updated `pkg/types/types.go`
- [x] Updated hashing functions in `pkg/crypto/bls.go`
- [x] New message types for commitment broadcasts
- [x] Updated merkle package to use new fields

**Changes:**
- [x] Add `ShareHash [32]byte` to `Acknowledgement`
- [x] Add `Epoch int64` to `Acknowledgement`
- [x] Create `CommitmentBroadcast` message type
- [x] Create `CommitmentBroadcastMessage` wrapper type
- [x] Update signature comment to reflect new fields

**Completion Criteria:**
- [x] `Acknowledgement` struct updated with `ShareHash` and `Epoch` fields
- [x] `CommitmentBroadcast` and `CommitmentBroadcastMessage` types created
- [x] `HashAcknowledgementForMerkle()` function implemented in `pkg/crypto/bls.go`
- [x] `HashShareForAck()` function implemented in `pkg/crypto/bls.go`
- [x] Unit tests for new hash functions (8 test functions in hash_test.go)
- [x] Test hash output uses keccak256 (Solidity-compatible)
- [x] Test hash determinism (same input = same output)
- [x] Merkle package updated to hash all fields (player, dealer, epoch, shareHash, commitmentHash)
- [x] Merkle tests updated for new fields
- [x] `./scripts/goTest.sh ./pkg/crypto/...` passes (all hash tests passing)
- [x] `./scripts/goTest.sh ./pkg/merkle/...` passes (no regressions)
- [x] No regression in existing tests (make test passes)
- [x] `make lint` passes (0 issues)
- [x] All new structs and functions have godoc comments

**Quality Gate:**
```bash
# Test updated types and crypto functions
go test ./pkg/types/... -v -race
go test ./pkg/crypto/... -v -race

# Ensure no regressions
make test

# Linter
make lint
```

---

### Phase 4: DKG/Reshare Protocol Modifications (2-3 days) ✅ COMPLETE

**Goal:** Integrate merkle tree building and contract submission into protocols

**Deliverables:**
- [x] Updated `pkg/dkg/dkg.go`
- [x] Updated `pkg/reshare/reshare.go`
- [x] Updated `pkg/node/node.go` orchestration

**Key Changes:**
- [x] Modify acknowledgement creation to include shareHash and epoch
- [x] Add merkle tree building functions
- [x] Update session state machine to include merkle state
- [x] Initialize new fields in session creation

**Completion Criteria:**
- [x] `CreateAcknowledgement()` updated to include shareHash and epoch (DKG and Reshare)
- [x] `BuildAcknowledgementMerkleTree()` function added to DKG
- [x] Same function added to reshare protocol
- [x] `ProtocolSession` struct updated with merkle tree state fields
- [x] Session initialization updated to create verifiedOperators map
- [x] Node orchestration updated to call new CreateAcknowledgement signature
- [x] Unit tests for DKG acknowledgement creation with shareHash (testCreateAcknowledgement)
- [x] Unit tests for merkle tree building in DKG (Test_BuildAcknowledgementMerkleTree)
- [x] Unit tests for reshare acknowledgement (Test_CreateAcknowledgement)
- [x] Unit tests for reshare merkle tree (Test_BuildAcknowledgementMerkleTree_Reshare)
- [x] Tests verify epoch field is set correctly
- [x] Tests verify shareHash field is set correctly
- [x] Tests verify merkle tree is built with correct number of leaves
- [x] `./scripts/goTest.sh ./pkg/dkg/...` passes (all tests + 2 new)
- [x] `./scripts/goTest.sh ./pkg/reshare/...` passes (all tests + 2 new)
- [x] No regression in existing DKG/reshare tests
- [x] `make test` passes (full suite)
- [x] `make lint` passes (0 issues)
- [x] All modified functions have updated godoc comments

**Note:** Phase 4 adds the data structures and functions. Actual contract submission and verification logic will be implemented in Phases 5-6.

**Quality Gate:**
```bash
# Test DKG and reshare packages
go test ./pkg/dkg/... -v -race
go test ./pkg/reshare/... -v -race
go test ./pkg/node/... -v -race

# Ensure no regressions across entire codebase
make test

# Linter
make lint
```

---

### Phase 5: Transport Layer Enhancements (1 day) ⏳ PENDING

**Goal:** Enable broadcasting commitments with operator-specific merkle proofs

**Deliverables:**
- [ ] New `BroadcastCommitmentsWithProofs()` function
- [ ] Updated message handling in `pkg/node/server.go`

**Key Features:**
- [ ] Generate merkle proof for each recipient
- [ ] Include proof in broadcast message
- [ ] Reuse existing authentication wrapper

**Completion Criteria:**
- [ ] `BroadcastCommitmentsWithProofs()` implemented in `pkg/transport/client.go`
- [ ] Function generates unique merkle proof for each recipient
- [ ] Broadcast message includes commitments + all acks + proof
- [ ] Message handler in `pkg/node/server.go` updated to receive broadcasts
- [ ] Handler extracts and stores broadcast data in session
- [ ] Unit tests for broadcast function
- [ ] Test proof generation for each operator
- [ ] Test broadcast message construction
- [ ] Mock transport tests (no real network needed)
- [ ] `go test ./pkg/transport/... -v` passes
- [ ] No regression in existing transport tests
- [ ] `make lint` passes
- [ ] All new functions have godoc comments

**Quality Gate:**
```bash
go test ./pkg/transport/... -v -race
go test ./pkg/node/... -v -race
make test
make lint
```

---

### Phase 6: Verification Flow (1-2 days) ⏳ PENDING

**Goal:** Implement full verification against on-chain commitment data

**Deliverables:**
- [ ] Verification logic in `pkg/node/node.go`
- [ ] Contract query integration
- [ ] Error handling and operator exclusion

**Verification Steps:**
1. [ ] Query contract for operator's (commitmentHash, ackMerkleRoot)
2. [ ] Verify: hash(broadcast commitments) == commitmentHash
3. [ ] Find own ack in operator's ack list
4. [ ] Verify: ack.shareHash == keccak256(received share)
5. [ ] Verify: merkleProof(ack) validates against ackMerkleRoot
6. [ ] Accept/reject operator's commitments

**Completion Criteria:**
- [ ] `VerifyOperatorBroadcast()` function implemented
- [ ] Function queries contract for commitment data
- [ ] Function verifies commitment hash matches broadcast
- [ ] Function finds and verifies own ack in broadcast
- [ ] Function verifies shareHash matches received share
- [ ] Function verifies merkle proof against on-chain root
- [ ] `WaitForVerifications()` function implemented
- [ ] Function waits for all operators to be verified
- [ ] Operator exclusion logic for failed verifications
- [ ] Unit tests for verification logic
- [ ] Test successful verification path
- [ ] Test rejection on commitment hash mismatch
- [ ] Test rejection on shareHash mismatch
- [ ] Test rejection on invalid merkle proof
- [ ] Test with mock contract data
- [ ] `go test ./pkg/node/... -v` passes
- [ ] No regression in existing tests
- [ ] `make lint` passes
- [ ] All new functions have godoc comments

**Quality Gate:**
```bash
go test ./pkg/node/... -v -race
make test
make lint
```

---

### Phase 7: End-to-End Integration Testing (1-2 days) ⏳ PENDING

**Goal:** Comprehensive testing of complete merkle-based DKG/Reshare protocol

**Deliverables:**
- [ ] Integration tests in `internal/tests/integration/`
- [ ] Test scenarios for fraud detection
- [ ] Performance benchmarks

**Test Cases:**
- [ ] 4-node DKG with merkle acks
- [ ] 10-node DKG (stress test)
- [ ] Reshare protocol with merkle acks
- [ ] Invalid proof rejection
- [ ] Missing ack handling
- [ ] Contract submission failures

**Completion Criteria:**
- [ ] `TestDKGWithMerkleAcknowledgements` test implemented
- [ ] Test runs full DKG with 4 operators
- [ ] Test verifies all operators have same master public key
- [ ] Test verifies contract submissions for all operators
- [ ] `TestReshareWithMerkleAcknowledgements` test implemented
- [ ] `TestDKGWithInvalidProof` test implemented (fraud detection)
- [ ] Test verifies malicious operator is excluded
- [ ] `TestDKGWithMissingAcks` test implemented (timeout handling)
- [ ] Benchmark tests for merkle operations
- [ ] All integration tests pass
- [ ] `go test ./internal/tests/integration/... -v` passes
- [ ] No regression in existing integration tests
- [ ] `make test` passes for entire codebase
- [ ] `make lint` passes for entire codebase
- [ ] Performance benchmarks documented

**Quality Gate:**
```bash
# Run all integration tests
go test ./internal/tests/integration/... -v -race -timeout=5m

# Run all tests across entire codebase
make test

# Linter check
make lint

# Build all binaries to ensure no compile errors
make all
```

**Note:** This phase completes the implementation. All 7 phases must pass their quality gates before the implementation is considered complete.

---

### Phase 8: Fraud Detection (Future/Optional) 🔮 FUTURE

**Goal:** Enable on-chain slashing for equivocation

**Deliverables:**
- Gossip protocol for share comparison
- `proveEquivocation()` contract function
- Fraud proof construction
- EigenLayer slashing integration

**Note:** This can be implemented later as an enhancement

---

## Detailed Implementation Steps

### Step 1: Create Merkle Tree Package

**File:** `pkg/merkle/types.go`

```go
package merkle

// MerkleTree represents a binary merkle tree
type MerkleTree struct {
    Leaves [][]byte     // Original leaf data (hashed)
    Nodes  [][]byte     // All nodes in the tree (bottom-up, left-to-right)
    Root   [32]byte     // Root hash
}

// MerkleProof represents a proof that a leaf is in the tree
type MerkleProof struct {
    LeafIndex int        // Index of the leaf in the sorted array
    Leaf      [32]byte   // Hash of the leaf
    Proof     [][32]byte // Sibling hashes from leaf to root
}
```

**File:** `pkg/merkle/merkle.go`

Key functions to implement:

```go
// BuildMerkleTree creates a merkle tree from acknowledgements
// Acks are sorted by player address before hashing
func BuildMerkleTree(acks []*types.Acknowledgement) (*MerkleTree, error)

// GenerateProof creates a merkle proof for a specific ack
func (mt *MerkleTree) GenerateProof(leafIndex int) (*MerkleProof, error)

// VerifyProof checks if a leaf is in the tree with the given root
func VerifyProof(proof *MerkleProof, root [32]byte) bool

// HashAcknowledgement creates a keccak256 hash of an ack (for leaf)
func HashAcknowledgement(ack *types.Acknowledgement) [32]byte

// SortAcknowledgements sorts acks by player address (deterministic)
func SortAcknowledgements(acks []*types.Acknowledgement) []*types.Acknowledgement
```

**Implementation Details:**

1. **Sorting:** Sort acks by player Ethereum address (ascending)
2. **Leaf Hashing:** `keccak256(abi.encodePacked(player, dealer, epoch, shareHash, commitmentHash))`
3. **Node Hashing:** `keccak256(abi.encodePacked(leftChild, rightChild))`
4. **Padding:** If odd number of nodes, duplicate last node
5. **Proof Format:** Array of sibling hashes from leaf to root

**Testing Requirements:**
- Test with 1, 2, 3, 4, 7, 8, 15, 16 acks (powers of 2 and non-powers)
- Test sorting determinism
- Test proof verification
- Test invalid proof rejection
- Test empty ack list handling

---

### Step 2: Smart Contract Implementation

**File:** `contracts/src/EigenKMSCommitmentRegistry.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract EigenKMSCommitmentRegistry {

    // Storage structure per operator per epoch
    struct OperatorCommitment {
        bytes32 commitmentHash;    // hash(polynomial commitments)
        bytes32 ackMerkleRoot;     // root of ack merkle tree
        uint256 submittedAt;       // block number
    }

    // epoch => operator => commitment
    mapping(uint64 => mapping(address => OperatorCommitment)) public commitments;

    // Events
    event CommitmentSubmitted(
        uint64 indexed epoch,
        address indexed operator,
        bytes32 commitmentHash,
        bytes32 ackMerkleRoot
    );

    // Submit commitment and ack merkle root
    function submitCommitment(
        uint64 epoch,
        bytes32 _commitmentHash,
        bytes32 _ackMerkleRoot
    ) external {
        require(_commitmentHash != bytes32(0), "Invalid commitment hash");
        require(_ackMerkleRoot != bytes32(0), "Invalid merkle root");
        require(
            commitments[epoch][msg.sender].commitmentHash == bytes32(0),
            "Commitment already submitted"
        );

        commitments[epoch][msg.sender] = OperatorCommitment({
            commitmentHash: _commitmentHash,
            ackMerkleRoot: _ackMerkleRoot,
            submittedAt: block.number
        });

        emit CommitmentSubmitted(epoch, msg.sender, _commitmentHash, _ackMerkleRoot);
    }

    // Query commitment
    function getCommitment(uint64 epoch, address operator)
        external
        view
        returns (bytes32 commitmentHash, bytes32 ackMerkleRoot, uint256 submittedAt)
    {
        OperatorCommitment memory c = commitments[epoch][operator];
        return (c.commitmentHash, c.ackMerkleRoot, c.submittedAt);
    }

    // Future: Equivocation proof (Phase 8)
    function proveEquivocation(
        uint64 epoch,
        address dealer,
        bytes calldata ack1,
        bytes32[] calldata proof1,
        bytes calldata ack2,
        bytes32[] calldata proof2
    ) external {
        // TODO: Implement in Phase 8
        revert("Not implemented");
    }
}
```

**File:** `contracts/test/EigenKMSCommitmentRegistry.t.sol`

Test cases:
- Submit commitment successfully
- Reject duplicate submission
- Query commitment
- Reject invalid parameters
- Event emission verification
- Gas cost measurement

**File:** `pkg/contractCaller/commitmentRegistry.go`

```go
// SubmitCommitment submits commitment hash and ack merkle root to contract
func (c *ContractCaller) SubmitCommitment(
    epoch int64,
    commitmentHash [32]byte,
    ackMerkleRoot [32]byte,
) (*types.Transaction, error)

// GetCommitment queries commitment data from contract
func (c *ContractCaller) GetCommitment(
    epoch int64,
    operator common.Address,
) (commitmentHash [32]byte, ackMerkleRoot [32]byte, err error)
```

---

### Step 3: Update Acknowledgement Structure

**File:** `pkg/types/types.go`

```go
// Update existing Acknowledgement struct
type Acknowledgement struct {
    DealerID       int            // Operator who sent the share
    PlayerID       int            // Operator who received the share
    Epoch          int64          // NEW: Which reshare round
    ShareHash      [32]byte       // NEW: keccak256(share) - commits to received share
    CommitmentHash [32]byte       // hash(dealer's commitments)
    Signature      []byte         // BN254 signature over all above fields
}

// New message type for Phase 3 broadcast
type CommitmentBroadcast struct {
    FromOperatorAddress common.Address
    Epoch              int64
    Commitments        []G2Point          // Dealer's polynomial commitments
    Acknowledgements   []*Acknowledgement // All n-1 acks collected
    MerkleProof        [][32]byte        // Proof for specific recipient
}

// Wrapper for authenticated transport
type CommitmentBroadcastMessage struct {
    FromOperatorAddress common.Address
    ToOperatorAddress   common.Address
    SessionTimestamp    int64
    Broadcast          *CommitmentBroadcast
}
```

**File:** `pkg/crypto/bls.go` (add new functions)

```go
// HashAcknowledgementForMerkle creates keccak256 hash for merkle leaf
func HashAcknowledgementForMerkle(ack *types.Acknowledgement) [32]byte {
    // Use same field order as Solidity for verification
    // keccak256(abi.encodePacked(player, dealer, epoch, shareHash, commitmentHash))
    h := crypto.Keccak256Hash(
        common.BigToAddress(big.NewInt(int64(ack.PlayerID))).Bytes(),
        common.BigToAddress(big.NewInt(int64(ack.DealerID))).Bytes(),
        big.NewInt(ack.Epoch).Bytes(),
        ack.ShareHash[:],
        ack.CommitmentHash[:],
    )
    return [32]byte(h)
}

// HashShareForAck creates keccak256 hash of a share
func HashShareForAck(share *fr.Element) [32]byte {
    return crypto.Keccak256Hash(share.Bytes())
}
```

---

### Step 4: Modify DKG Protocol

**File:** `pkg/dkg/dkg.go`

**Update CreateAcknowledgement:**

```go
// CreateAcknowledgement creates an acknowledgement for a received share
func (dkg *DKG) CreateAcknowledgement(
    dealerID int,
    share *fr.Element,
    commitments []types.G2Point,
    epoch int64,
) (*types.Acknowledgement, error) {

    // Hash the share
    shareHash := crypto.HashShareForAck(share)

    // Hash the commitments
    commitmentHash := crypto.HashCommitment(commitments)

    // Create ack structure
    ack := &types.Acknowledgement{
        DealerID:       dealerID,
        PlayerID:       dkg.PlayerID,
        Epoch:          epoch,
        ShareHash:      shareHash,
        CommitmentHash: commitmentHash,
    }

    // Sign with BN254 key (existing logic)
    signature, err := signAcknowledgement(dkg.PrivateKey, ack)
    if err != nil {
        return nil, err
    }
    ack.Signature = signature

    return ack, nil
}
```

**Add Merkle Tree Building:**

```go
// BuildAcknowledgementMerkleTree creates merkle tree from collected acks
func (dkg *DKG) BuildAcknowledgementMerkleTree(
    acks []*types.Acknowledgement,
) (*merkle.MerkleTree, error) {

    if len(acks) == 0 {
        return nil, fmt.Errorf("no acknowledgements to build tree")
    }

    // Build tree (sorting happens inside)
    tree, err := merkle.BuildMerkleTree(acks)
    if err != nil {
        return nil, fmt.Errorf("failed to build merkle tree: %w", err)
    }

    return tree, nil
}
```

---

### Step 5: Update Node Orchestration

**File:** `pkg/node/node.go`

**Update Session Structure:**

```go
type ProtocolSession struct {
    SessionTimestamp    int64
    Operators          []peering.OperatorSetPeer
    ReceivedShares     map[int]*fr.Element
    ReceivedCommitments map[int][]types.G2Point
    ReceivedAcks       map[int]map[int]*types.Acknowledgement  // [dealerID][playerID]

    // NEW: Merkle tree state
    MyAckMerkleTree    *merkle.MerkleTree    // Tree I built from acks I collected as dealer
    MyCommitmentHash   [32]byte              // Hash of my commitments
    ContractSubmitted  bool                  // Whether I submitted to contract

    // NEW: Verification state
    VerifiedOperators  map[int]bool          // Operators whose broadcasts I verified

    mu sync.RWMutex
}
```

**Modified Protocol Flow:**

```go
// Phase 2: Acknowledgement Collection (MODIFIED)
func (n *Node) CollectAcknowledgements(sessionTimestamp int64) error {
    session := n.getSession(sessionTimestamp)

    // Wait for ALL n-1 acknowledgements (not just threshold)
    expectedAcks := len(session.Operators) - 1

    timeout := time.After(30 * time.Second)
    ticker := time.NewTicker(500 * time.Millisecond)
    defer ticker.Stop()

    for {
        select {
        case <-timeout:
            received := len(session.ReceivedAcks[n.OperatorID])
            return fmt.Errorf("timeout waiting for acks: received %d/%d", received, expectedAcks)
        case <-ticker.C:
            session.mu.RLock()
            acksReceived := len(session.ReceivedAcks[n.OperatorID])
            session.mu.RUnlock()

            if acksReceived >= expectedAcks {
                return nil  // Got all acks
            }
        }
    }
}

// NEW: Build Merkle Tree and Submit to Contract
func (n *Node) BuildMerkleTreeAndSubmit(sessionTimestamp int64) error {
    session := n.getSession(sessionTimestamp)

    // Extract acks I collected as dealer
    session.mu.RLock()
    myAcks := make([]*types.Acknowledgement, 0)
    for _, ack := range session.ReceivedAcks[n.OperatorID] {
        myAcks = append(myAcks, ack)
    }
    myCommitments := session.ReceivedCommitments[n.OperatorID]  // My own commitments
    session.mu.RUnlock()

    // Build merkle tree
    tree, err := merkle.BuildMerkleTree(myAcks)
    if err != nil {
        return fmt.Errorf("failed to build merkle tree: %w", err)
    }

    // Hash my commitments
    commitmentHash := crypto.HashCommitment(myCommitments)

    // Submit to contract
    _, err = n.contractCaller.SubmitCommitment(
        sessionTimestamp,  // epoch
        commitmentHash,
        tree.Root,
    )
    if err != nil {
        return fmt.Errorf("failed to submit commitment: %w", err)
    }

    // Store in session
    session.mu.Lock()
    session.MyAckMerkleTree = tree
    session.MyCommitmentHash = commitmentHash
    session.ContractSubmitted = true
    session.mu.Unlock()

    return nil
}
```

---

### Step 6: Transport Layer for Proofs

**File:** `pkg/transport/client.go`

```go
// BroadcastCommitmentsWithProofs broadcasts commitments and acks with operator-specific proofs
func (c *Client) BroadcastCommitmentsWithProofs(
    sessionTimestamp int64,
    commitments []types.G2Point,
    acks []*types.Acknowledgement,
    merkleTree *merkle.MerkleTree,
    operators []peering.OperatorSetPeer,
) error {

    for _, operator := range operators {
        if operator.Address == c.myAddress {
            continue  // Don't send to myself
        }

        // Find the ack for this operator
        var recipientAck *types.Acknowledgement
        var leafIndex int
        for i, ack := range acks {
            if ack.PlayerID == operator.OperatorID {
                recipientAck = ack
                leafIndex = i
                break
            }
        }

        if recipientAck == nil {
            return fmt.Errorf("no ack found for operator %d", operator.OperatorID)
        }

        // Generate merkle proof for this specific operator
        proof, err := merkleTree.GenerateProof(leafIndex)
        if err != nil {
            return fmt.Errorf("failed to generate proof for operator %d: %w", operator.OperatorID, err)
        }

        // Create broadcast message
        broadcast := &types.CommitmentBroadcast{
            FromOperatorAddress: c.myAddress,
            Epoch:              sessionTimestamp,
            Commitments:        commitments,
            Acknowledgements:   acks,
            MerkleProof:        proof.Proof,
        }

        // Send to operator
        err = c.sendCommitmentBroadcast(operator, broadcast)
        if err != nil {
            log.Printf("Failed to send commitment broadcast to %s: %v", operator.Address.Hex(), err)
            // Continue sending to others
        }
    }

    return nil
}
```

---

### Step 7: Verification Flow

**File:** `pkg/node/node.go`

```go
// VerifyOperatorBroadcast verifies a commitment broadcast against on-chain data
func (n *Node) VerifyOperatorBroadcast(
    sessionTimestamp int64,
    broadcast *types.CommitmentBroadcast,
) error {

    // Step 1: Query contract for operator's commitment
    commitmentHash, ackMerkleRoot, err := n.contractCaller.GetCommitment(
        sessionTimestamp,
        broadcast.FromOperatorAddress,
    )
    if err != nil {
        return fmt.Errorf("failed to query contract: %w", err)
    }

    // Step 2: Verify commitment hash matches broadcast
    broadcastCommitmentHash := crypto.HashCommitment(broadcast.Commitments)
    if broadcastCommitmentHash != commitmentHash {
        return fmt.Errorf("commitment hash mismatch: expected %x, got %x",
            commitmentHash, broadcastCommitmentHash)
    }

    // Step 3: Find MY ack in the broadcast
    var myAck *types.Acknowledgement
    for _, ack := range broadcast.Acknowledgements {
        if ack.PlayerID == n.OperatorID {
            myAck = ack
            break
        }
    }
    if myAck == nil {
        return fmt.Errorf("my ack not found in broadcast")
    }

    // Step 4: Verify MY ack's shareHash matches the share I received
    session := n.getSession(sessionTimestamp)
    session.mu.RLock()
    receivedShare := session.ReceivedShares[broadcast.FromOperatorID]
    session.mu.RUnlock()

    if receivedShare == nil {
        return fmt.Errorf("no share received from operator")
    }

    expectedShareHash := crypto.HashShareForAck(receivedShare)
    if myAck.ShareHash != expectedShareHash {
        return fmt.Errorf("share hash mismatch: ack says %x, actual is %x",
            myAck.ShareHash, expectedShareHash)
    }

    // Step 5: Verify merkle proof
    leafHash := crypto.HashAcknowledgementForMerkle(myAck)
    proof := &merkle.MerkleProof{
        Leaf:  leafHash,
        Proof: broadcast.MerkleProof,
    }

    if !merkle.VerifyProof(proof, ackMerkleRoot) {
        return fmt.Errorf("merkle proof verification failed")
    }

    // All checks passed - mark operator as verified
    session.mu.Lock()
    session.VerifiedOperators[broadcast.FromOperatorID] = true
    session.mu.Unlock()

    return nil
}

// WaitForVerifications waits for all operators to be verified
func (n *Node) WaitForVerifications(sessionTimestamp int64) error {
    session := n.getSession(sessionTimestamp)
    expectedVerifications := len(session.Operators) - 1

    timeout := time.After(60 * time.Second)
    ticker := time.NewTicker(500 * time.Millisecond)
    defer ticker.Stop()

    for {
        select {
        case <-timeout:
            session.mu.RLock()
            verified := len(session.VerifiedOperators)
            session.mu.RUnlock()
            return fmt.Errorf("timeout waiting for verifications: verified %d/%d",
                verified, expectedVerifications)
        case <-ticker.C:
            session.mu.RLock()
            verified := len(session.VerifiedOperators)
            session.mu.RUnlock()

            if verified >= expectedVerifications {
                return nil
            }
        }
    }
}
```

---

## Testing Strategy

### Unit Tests

#### Merkle Tree Tests (`pkg/merkle/merkle_test.go`)

```go
func TestBuildMerkleTree(t *testing.T) {
    testCases := []struct {
        name     string
        numAcks  int
    }{
        {"Single ack", 1},
        {"Two acks", 2},
        {"Three acks", 3},
        {"Four acks (power of 2)", 4},
        {"Seven acks", 7},
        {"Eight acks (power of 2)", 8},
        {"Fifteen acks", 15},
        {"Sixteen acks (power of 2)", 16},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            acks := createTestAcknowledgements(tc.numAcks)
            tree, err := merkle.BuildMerkleTree(acks)
            require.NoError(t, err)
            require.NotNil(t, tree)

            // Verify root is non-zero
            require.NotEqual(t, [32]byte{}, tree.Root)

            // Generate and verify proofs for all leaves
            for i := 0; i < tc.numAcks; i++ {
                proof, err := tree.GenerateProof(i)
                require.NoError(t, err)
                require.True(t, merkle.VerifyProof(proof, tree.Root))
            }
        })
    }
}

func TestMerkleProofVerification(t *testing.T) {
    acks := createTestAcknowledgements(4)
    tree, _ := merkle.BuildMerkleTree(acks)

    // Valid proof
    proof, _ := tree.GenerateProof(0)
    require.True(t, merkle.VerifyProof(proof, tree.Root))

    // Invalid proof (wrong root)
    invalidRoot := [32]byte{1, 2, 3}
    require.False(t, merkle.VerifyProof(proof, invalidRoot))

    // Invalid proof (tampered leaf)
    proof.Leaf[0] ^= 0xFF
    require.False(t, merkle.VerifyProof(proof, tree.Root))
}

func TestAcknowledgementSorting(t *testing.T) {
    acks := createTestAcknowledgements(10)

    // Shuffle
    rand.Shuffle(len(acks), func(i, j int) {
        acks[i], acks[j] = acks[j], acks[i]
    })

    // Sort twice
    sorted1 := merkle.SortAcknowledgements(acks)
    sorted2 := merkle.SortAcknowledgements(acks)

    // Should be deterministic
    for i := range sorted1 {
        require.Equal(t, sorted1[i].PlayerID, sorted2[i].PlayerID)
    }
}
```

#### Contract Tests (`contracts/test/EigenKMSCommitmentRegistry.t.sol`)

```solidity
function testSubmitCommitment() public {
    uint64 epoch = 5;
    bytes32 commitmentHash = keccak256("test commitment");
    bytes32 ackMerkleRoot = keccak256("test root");

    vm.prank(operator1);
    registry.submitCommitment(epoch, commitmentHash, ackMerkleRoot);

    (bytes32 storedHash, bytes32 storedRoot, uint256 submittedAt) =
        registry.getCommitment(epoch, operator1);

    assertEq(storedHash, commitmentHash);
    assertEq(storedRoot, ackMerkleRoot);
    assertGt(submittedAt, 0);
}

function testCannotSubmitTwice() public {
    uint64 epoch = 5;
    bytes32 commitmentHash = keccak256("test commitment");
    bytes32 ackMerkleRoot = keccak256("test root");

    vm.prank(operator1);
    registry.submitCommitment(epoch, commitmentHash, ackMerkleRoot);

    vm.prank(operator1);
    vm.expectRevert("Commitment already submitted");
    registry.submitCommitment(epoch, commitmentHash, ackMerkleRoot);
}

function testGasCost() public {
    uint64 epoch = 5;
    bytes32 commitmentHash = keccak256("test commitment");
    bytes32 ackMerkleRoot = keccak256("test root");

    vm.prank(operator1);
    uint256 gasBefore = gasleft();
    registry.submitCommitment(epoch, commitmentHash, ackMerkleRoot);
    uint256 gasUsed = gasBefore - gasleft();

    // Should be ~21,000 gas
    assertLt(gasUsed, 25000);
    emit log_named_uint("Gas used for submitCommitment", gasUsed);
}
```

### Integration Tests

#### End-to-End DKG with Merkle Acks (`internal/tests/integration/merkle_dkg_test.go`)

```go
func TestDKGWithMerkleAcknowledgements(t *testing.T) {
    // Setup 4-node cluster
    cluster := testutil.NewTestCluster(t, 4)
    defer cluster.Shutdown()

    // Start DKG on all nodes
    sessionTimestamp := time.Now().Unix()
    for _, node := range cluster.Nodes {
        go node.StartDKG(sessionTimestamp)
    }

    // Wait for completion
    time.Sleep(30 * time.Second)

    // Verify all nodes have same master public key
    var mpk []types.G2Point
    for i, node := range cluster.Nodes {
        keyShare := node.KeyStore.GetActiveKeyShare()
        require.NotNil(t, keyShare)

        if i == 0 {
            mpk = keyShare.Commitments[0]  // MPK is sum of all C_0
        } else {
            require.Equal(t, mpk, keyShare.Commitments[0])
        }
    }

    // Verify contract submissions
    for _, node := range cluster.Nodes {
        commitmentHash, merkleRoot, err := cluster.ContractCaller.GetCommitment(
            sessionTimestamp,
            node.Address,
        )
        require.NoError(t, err)
        require.NotEqual(t, [32]byte{}, commitmentHash)
        require.NotEqual(t, [32]byte{}, merkleRoot)
    }
}

func TestDKGWithInvalidProof(t *testing.T) {
    cluster := testutil.NewTestCluster(t, 4)
    defer cluster.Shutdown()

    // Inject malicious node that sends invalid merkle proofs
    maliciousNode := cluster.Nodes[0]
    maliciousNode.SendInvalidProofs = true

    sessionTimestamp := time.Now().Unix()
    for _, node := range cluster.Nodes {
        go node.StartDKG(sessionTimestamp)
    }

    time.Sleep(30 * time.Second)

    // Verify other nodes excluded the malicious node
    for _, node := range cluster.Nodes[1:] {
        session := node.GetSession(sessionTimestamp)
        require.False(t, session.VerifiedOperators[maliciousNode.OperatorID])
    }
}
```

### Performance Benchmarks

```go
func BenchmarkMerkleTreeBuild(b *testing.B) {
    sizes := []int{10, 50, 100, 200}

    for _, size := range sizes {
        b.Run(fmt.Sprintf("Acks_%d", size), func(b *testing.B) {
            acks := createTestAcknowledgements(size)
            b.ResetTimer()

            for i := 0; i < b.N; i++ {
                _, _ = merkle.BuildMerkleTree(acks)
            }
        })
    }
}

func BenchmarkMerkleProofGeneration(b *testing.B) {
    acks := createTestAcknowledgements(100)
    tree, _ := merkle.BuildMerkleTree(acks)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = tree.GenerateProof(i % 100)
    }
}
```

---

## Security Considerations

### 1. Hash Function Consistency

**Issue:** Go and Solidity must use identical hash functions for verification

**Solution:**
- Use `crypto.Keccak256Hash()` in Go (from go-ethereum)
- Use `keccak256(abi.encodePacked(...))` in Solidity
- Test cross-compatibility with known test vectors

### 2. Signature Verification

**Issue:** Acknowledgement signatures must be unforgeable

**Solution:**
- Continue using BN254 signatures (existing implementation)
- Include shareHash in signed message
- Verify signature before accepting acks

### 3. Equivocation Prevention

**Issue:** Dealer could send different shares with different acks

**Solution:**
- Merkle root committed on-chain prevents modification
- Each player verifies their ack's shareHash matches received share
- Gossip protocol (Phase 8) enables fraud proof construction

### 4. Contract Submission Race Conditions

**Issue:** Operator could submit multiple commitments for same epoch

**Solution:**
- Contract enforces single submission per operator per epoch
- Revert on duplicate submission attempt

### 5. Denial of Service

**Issue:** Malicious operator could withhold acks

**Solution:**
- Timeout after 30 seconds if not all acks received
- Operator excluded from protocol for that epoch
- System continues if threshold operators succeed

### 6. Merkle Proof Forgery

**Issue:** Attacker could generate fake proofs

**Solution:**
- Proof verification against on-chain root (trustless)
- Invalid proofs cause operator exclusion (no system impact)

---

## Cost Analysis

### Gas Costs (Ethereum Mainnet @ 20 gwei)

**Per Operator Submission:**
- Storage: 2 � 32 bytes (commitmentHash + ackMerkleRoot) = 64 bytes
- Gas: ~21,000 (SSTORE � 2 + overhead)
- Cost: 21,000 � 20 gwei = 0.00042 ETH H $0.0004 @ $1000/ETH

**With 10 Operators:**
- Per Epoch: 10 � $0.0004 = $0.004
- Per Hour (6 epochs): $0.024
- Per Day: $0.576
- **Per Month: ~$17**

**Comparison:**
- Full acks on-chain: ~$43,000/month
- No acks (insecure): ~$15/month
- **Merkle acks: ~$17/month**

**Security premium: $2/month for fraud detection**

### Off-Chain Costs

**Computation:**
- Merkle tree building: O(n log n) for n operators
- Proof generation: O(log n) per operator
- Negligible for n < 100

**Network Bandwidth:**
- Broadcast includes all n-1 acks (not just threshold)
- Each ack: ~200 bytes
- For 10 operators: ~2KB per broadcast
- Total per node: ~20KB (broadcasting to 9 others)
- **Negligible bandwidth overhead**

---

## Timeline and Milestones

### Week 1: Foundation
- **Day 1-2:** Implement merkle tree package with tests
- **Day 3:** Create smart contract with Foundry tests
- **Day 4:** Deploy contract to testnet, create Go bindings
- **Day 5:** Update acknowledgement data structures

**Deliverable:** Working merkle tree library + deployed contract

### Week 2: Protocol Integration
- **Day 6-7:** Modify DKG/Reshare protocols for merkle acks
- **Day 8:** Update node orchestration and session management
- **Day 9:** Implement transport layer proof broadcasts
- **Day 10:** Implement verification flow

**Deliverable:** Fully integrated merkle-based protocol

### Week 3: Testing and Validation
- **Day 11-12:** Write integration tests
- **Day 13:** Performance testing and optimization
- **Day 14:** Security audit (code review)
- **Day 15:** Documentation and deployment guide

**Deliverable:** Production-ready system with tests

---

## Rollout Plan

### Phase 1: Testnet Deployment
1. Deploy commitment registry contract to testnet (Sepolia)
2. Update operator binaries with merkle ack support
3. Run 10-node testnet for 1 week
4. Monitor gas costs, verify fraud detection

### Phase 2: Mainnet Deployment
1. Security audit of contract and Go code
2. Deploy commitment registry to mainnet
3. Coordinate operator upgrades (all must upgrade simultaneously)
4. Activate merkle ack protocol at specific epoch

### Phase 3: Monitoring
1. Monitor contract submissions (events)
2. Track verification success rate
3. Monitor for equivocation attempts
4. Collect performance metrics

---

## Future Enhancements (Phase 8)

### Gossip-Based Fraud Detection

**Goal:** Enable slashing for equivocation

**Implementation:**
1. Operators gossip received shares off-chain
2. If two operators received different shares from same dealer:
   - Both shares verify against commitments (VSS property allows this)
   - But shareHashes in acks are different
3. Either operator constructs fraud proof:
   ```
   Proof {
       dealer: address
       commitments: [C_0, C_1, ...]
       ack1: {player1, shareHash1, signature1}
       proof1: merkleProof1
       share1: actual share value
       ack2: {player2, shareHash2, signature2}
       proof2: merkleProof2
       share2: actual share value
   }
   ```
4. Submit to `proveEquivocation(proof)` contract function
5. Contract verifies:
   - Both acks in dealer's merkle tree
   - Both shares verify against commitments
   - shareHash1 ` shareHash2
6. Slash dealer via EigenLayer

**Benefits:**
- Cryptographically proven fraud detection
- Economic incentive for honest behavior
- No trusted third party required

---

## Success Metrics

### Functional Requirements
-  All operators can complete DKG with merkle acks
-  Contract submissions succeed for all operators
-  Verification rejects invalid proofs
-  System handles operator failures gracefully

### Performance Requirements
-  Merkle tree building < 1 second for 100 operators
-  Proof generation < 100ms per operator
-  Protocol completion time < 2 minutes for 10 operators
-  Gas cost < $0.001 per operator per epoch

### Security Requirements
-  No operator can forge merkle proofs
-  Equivocation detectable via verification
-  Contract enforces single submission per epoch
-  System continues with e2n/3	 honest operators

---

## Conclusion

This implementation plan provides a comprehensive roadmap for adding merkle-based acknowledgement system to the EigenX KMS AVS. The design:

1. **Maintains security** - Fraud detection via on-chain commitments
2. **Reduces costs** - $17/month vs $43,000/month for full acks
3. **Preserves architecture** - Minimal changes to existing DKG/Reshare protocols
4. **Enables future enhancements** - Foundation for slashing and governance

The phased approach allows for incremental development, testing, and deployment with clear milestones and success criteria.

**Estimated Development Time:** 2-3 weeks for full implementation and testing

**Next Steps:**
1. Review and approve this plan
2. Create GitHub issues for each phase
3. Begin Phase 1 implementation (merkle tree package)
4. Set up testnet environment for integration testing

---

## Implementation Workflow Summary

### Phase Execution Order (STRICT)

```
Phase 1: Merkle Tree Infrastructure
   ↓ (Complete with all tests passing + linter)
Phase 2: Smart Contract Extensions
   ↓ (Complete with all tests passing + linter)
Phase 3: Data Structure Updates
   ↓ (Complete with all tests passing + linter)
Phase 4: DKG/Reshare Protocol Modifications
   ↓ (Complete with all tests passing + linter)
Phase 5: Transport Layer Enhancements
   ↓ (Complete with all tests passing + linter)
Phase 6: Verification Flow
   ↓ (Complete with all tests passing + linter)
Phase 7: End-to-End Integration Testing
   ↓ (Complete with all tests passing + linter)
✅ Implementation Complete
```

### Daily Workflow for Each Phase

1. **Start of Day:**
   - Review phase specification and deliverables
   - Identify specific tasks for the day
   - Ensure previous phase is 100% complete

2. **During Implementation:**
   - Write code incrementally
   - Write tests alongside code (TDD)
   - Run tests frequently: `go test ./pkg/[package]/... -v`
   - Run linter periodically: `make lint`

3. **End of Day:**
   - Run full test suite: `make test`
   - Run linter: `make lint`
   - Check test coverage: `go test -coverprofile=coverage.out`
   - Commit working code with descriptive messages

4. **Phase Completion:**
   - Review phase completion criteria checklist
   - Run quality gate commands
   - Ensure ALL criteria are met
   - Do NOT proceed to next phase until 100% complete
   - Document any issues or deviations

### Red Flags (STOP and Reassess)

🚫 **DO NOT continue if:**
- Tests are failing
- Linter shows warnings/errors
- Coverage drops significantly
- Existing tests break (regression)
- Phase is taking significantly longer than estimated
- Requirements are unclear

✅ **Instead:**
- Fix all failing tests before continuing
- Address all linter issues
- Investigate and fix regressions
- Document blockers and seek guidance
- Re-estimate time if needed

### Success Indicators

✅ **You're on track if:**
- All tests pass consistently
- Linter shows zero warnings
- Code coverage stays high (>80%)
- No regressions in existing tests
- Each phase completes within estimated time
- Documentation is up-to-date

---

## Quick Reference: Make Commands

```bash
# Run all tests
make test

# Run linter
make lint

# Format code
make fmt

# Check formatting
make fmtcheck

# Build all binaries
make all

# Run specific package tests
go test ./pkg/[package]/... -v -race

# Run tests with coverage
go test ./pkg/[package]/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

---

## Contact and Support

If you encounter issues during implementation:
1. Review the phase specification carefully
2. Check the detailed implementation steps
3. Consult existing code patterns in the codebase
4. Document the blocker clearly
5. Seek guidance from team leads

**Remember:** Quality over speed. It's better to take extra time to complete a phase correctly than to rush and create technical debt.
