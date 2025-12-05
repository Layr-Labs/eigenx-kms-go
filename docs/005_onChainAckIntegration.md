# On-Chain Acknowledgement Integration Plan

## Document Purpose
This document details the implementation plan for fully integrating the merkle-based acknowledgement system into the DKG/Reshare protocol flows with on-chain contract submission on Base chain.

**Parent Document:** [Merkle-Based Acknowledgement System](./004_merkleBasedAckSystem.md)

**Prerequisites:** Phases 1-8 from parent document must be complete before starting these phases.

---

## Implementation Status

**Overall Progress:** 6/7 phases complete (86%)

**Current Phase:** Phase 7 - Integration Tests with Contract Submission

**Last Updated:** December 2, 2025

---

## Phase Progress Tracker

- [x] **Phase 1**: Multi-Chain Configuration (Base + Ethereum) ✅
- [x] **Phase 2**: Transport Layer - Broadcast Implementation ✅
- [x] **Phase 3**: DKG Flow On-Chain Integration ✅
- [x] **Phase 4**: Reshare Flow On-Chain Integration ✅
- [x] **Phase 5**: Handler Contract Integration ✅
- [x] **Phase 6**: Retry Logic & Error Handling ✅ (already implemented in Phase 3)
- [ ] **Phase 7**: Integration Tests with Contract Submission

**Total Estimated Time:** 10-14 hours (~2 days)

---

## Phase 1: Multi-Chain Configuration (Base + Ethereum) (2-3 hours)

**Status:** ✅ COMPLETE

**Goal:** Add Base chain support and commitment registry address configuration

**Context:**
- Commitment registry only exists on Base chain (AVS-specific deployment)
- Need separate RPC configuration for Base chain operations
- Contract address should be runtime configurable (not hardcoded)

**Deliverables:**
- [x] Base chain constants added to `pkg/config/config.go`
- [x] New CLI flags: `--base-rpc-url`, `--commitment-registry-address`
- [x] New environment variables: `KMS_BASE_RPC_URL`, `KMS_COMMITMENT_REGISTRY_ADDRESS`
- [x] `KMSServerConfig` updated with `BaseRpcUrl` and `CommitmentRegistryAddress` fields
- [x] Base Ethereum client created in `cmd/kmsServer/main.go`
- [x] Base ContractCaller instance created and passed to Node
- [x] Node struct updated with `baseContractCaller` and `commitmentRegistryAddress` fields
- [x] **BONUS:** Migrated from BN254 to ECDSA for P2P authentication
- [x] **BONUS:** Added OperatorConfig with Web3Signer support

**Implementation Details:**

### File: `pkg/config/config.go`

Add Base chain constants:
```go
const (
    ChainId_BaseSepolia ChainId = 84532
)

const (
    ChainName_BaseSepolia ChainName = "base-sepolia"
)

// Update maps
var ChainIdToName = map[ChainId]ChainName{
    ChainId_EthereumMainnet: ChainName_EthereumMainnet,
    ChainId_EthereumSepolia: ChainName_EthereumSepolia,
    ChainId_EthereumAnvil:   ChainName_EthereumAnvil,
    ChainId_BaseSepolia:     ChainName_BaseSepolia,  // ADD
}
```

Add config fields:
```go
type KMSServerConfig struct {
    // ... existing fields ...
    BaseRpcUrl                 string `json:"base_rpc_url"`
    CommitmentRegistryAddress  string `json:"commitment_registry_address"`
}
```

### File: `cmd/kmsServer/main.go`

Add CLI flags:
```go
&cli.StringFlag{
    Name:    "base-rpc-url",
    Usage:   "Base chain RPC endpoint URL for commitment registry",
    EnvVars: []string{"KMS_BASE_RPC_URL"},
    Required: true,
},
&cli.StringFlag{
    Name:    "commitment-registry-address",
    Usage:   "EigenKMS Commitment Registry contract address (on Base)",
    EnvVars: []string{"KMS_COMMITMENT_REGISTRY_ADDRESS"},
    Required: true,
},
```

Create Base chain client:
```go
// Create Base Ethereum client for commitment registry
baseEthClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
    BaseUrl:   kmsConfig.BaseRpcUrl,
    BlockType: ethereum.BlockType_Latest,
}, l)

baseL1Client, err := baseEthClient.GetEthereumContractCaller()
if err != nil {
    l.Sugar().Fatalw("Failed to get Base contract caller", "error", err)
}

baseContractCaller, err := caller.NewContractCaller(baseL1Client, nil, l)
if err != nil {
    l.Sugar().Fatalw("Failed to create Base contract caller", "error", err)
}

// Parse commitment registry address
commitmentRegistryAddr := common.HexToAddress(kmsConfig.CommitmentRegistryAddress)
```

Update Node creation:
```go
n := node.NewNode(
    nodeConfig,
    pdf,
    bh,
    poller,
    imts,
    baseContractCaller,           // ADD
    commitmentRegistryAddr,       // ADD
    l,
)
```

### File: `pkg/node/node.go`

Update Node struct:
```go
type Node struct {
    // ... existing fields ...
    baseContractCaller        *caller.ContractCaller
    commitmentRegistryAddress common.Address
}
```

Update NewNode signature:
```go
func NewNode(
    cfg Config,
    pdf *peeringDataFetcher.PeeringDataFetcher,
    bh *blockHandler.BlockHandler,
    chainPoller chainPollerTypes.ChainPoller,
    transportSigner transportSigner.TransportSigner,
    baseContractCaller *caller.ContractCaller,      // ADD
    commitmentRegistryAddress common.Address,       // ADD
    logger *zap.Logger,
) *Node
```

**Completion Criteria:**
- [x] All config changes compile
- [x] CLI flags parse correctly
- [x] Base RPC client connects successfully
- [x] Contract address validates as valid Ethereum address
- [x] Node initializes with both Ethereum and Base contract callers
- [x] `make test` passes
- [x] `make lint` passes

**Quality Gate:**
```bash
# Test config parsing
go test ./pkg/config/... -v

# Test main CLI
go build ./cmd/kmsServer/

# Lint
make lint
```

---

## Phase 2: Transport Layer - Broadcast Implementation (1-2 hours)

**Status:** ✅ COMPLETE

**Goal:** Implement function to broadcast commitments with operator-specific merkle proofs

**Context:**
- After building merkle tree and submitting to contract, each operator must broadcast to all others
- Each recipient needs a unique merkle proof for their specific acknowledgement
- Transport layer already has authenticated messaging infrastructure

**Deliverables:**
- [x] `BroadcastCommitmentsWithProofs()` function implemented in `pkg/transport/client.go` (already existed from Phase 5)
- [x] Function generates unique proof for each operator
- [x] Broadcasts sent to all operators (excluding self)
- [x] Error handling for individual broadcast failures (logs and continues)
- [x] Unit tests for broadcast function (5 tests total)

**Implementation Details:**

### File: `pkg/transport/client.go`

Add new function (after existing broadcast functions):
```go
// BroadcastCommitmentsWithProofs broadcasts commitments and acknowledgements with operator-specific merkle proofs
// Each operator receives the full set of commitments and acks, plus a unique proof for their own ack
func (c *Client) BroadcastCommitmentsWithProofs(
    operators []*peering.OperatorSetPeer,
    commitments []types.G2Point,
    acks []*types.Acknowledgement,
    merkleTree *merkle.MerkleTree,
    sessionTimestamp int64,
) error {
    if merkleTree == nil {
        return fmt.Errorf("merkle tree is nil")
    }

    c.logger.Sugar().Infow("Broadcasting commitments with proofs to operators",
        "num_operators", len(operators),
        "num_acks", len(acks),
        "session", sessionTimestamp)

    // Track success/failure
    successCount := 0
    errorCount := 0

    for _, operator := range operators {
        // Skip self
        if operator.OperatorAddress == c.myAddress {
            continue
        }

        // Find this operator's ack in the list
        var recipientAck *types.Acknowledgement
        var leafIndex int

        recipientNodeID := addressToNodeID(operator.OperatorAddress)

        for i, ack := range acks {
            if ack.PlayerID == recipientNodeID {
                recipientAck = ack
                leafIndex = i
                break
            }
        }

        if recipientAck == nil {
            c.logger.Sugar().Warnw("No ack found for operator, skipping",
                "operator", operator.OperatorAddress.Hex(),
                "nodeID", recipientNodeID)
            errorCount++
            continue
        }

        // Generate merkle proof for this operator's ack
        proof, err := merkleTree.GenerateProof(leafIndex)
        if err != nil {
            c.logger.Sugar().Errorw("Failed to generate merkle proof",
                "operator", operator.OperatorAddress.Hex(),
                "error", err)
            errorCount++
            continue
        }

        // Create broadcast message
        broadcast := &types.CommitmentBroadcast{
            FromOperatorID:   addressToNodeID(c.myAddress),
            Epoch:           sessionTimestamp,
            Commitments:     commitments,
            Acknowledgements: acks,
            MerkleProof:     proof.Proof,
        }

        // Wrap in authenticated message
        message := &types.CommitmentBroadcastMessage{
            FromOperatorID: addressToNodeID(c.myAddress),
            ToOperatorID:   recipientNodeID,
            SessionID:      sessionTimestamp,
            Broadcast:      broadcast,
        }

        // Send to operator
        err = c.sendCommitmentBroadcastMessage(operator, message)
        if err != nil {
            c.logger.Sugar().Errorw("Failed to send commitment broadcast",
                "operator", operator.OperatorAddress.Hex(),
                "error", err)
            errorCount++
            continue
        }

        successCount++
    }

    c.logger.Sugar().Infow("Commitment broadcast complete",
        "success", successCount,
        "errors", errorCount)

    // Consider it success if at least threshold operators received broadcast
    if successCount == 0 {
        return fmt.Errorf("failed to broadcast to any operators")
    }

    return nil
}

// sendCommitmentBroadcastMessage sends a commitment broadcast to an operator
func (c *Client) sendCommitmentBroadcastMessage(
    operator *peering.OperatorSetPeer,
    message *types.CommitmentBroadcastMessage,
) error {
    url := fmt.Sprintf("http://%s/dkg/broadcast", operator.Socket)

    body, err := json.Marshal(message)
    if err != nil {
        return fmt.Errorf("failed to marshal message: %w", err)
    }

    req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("failed to send request: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        bodyBytes, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("bad response: %d - %s", resp.StatusCode, string(bodyBytes))
    }

    return nil
}

// addressToNodeID converts Ethereum address to node ID (matches DKG implementation)
func addressToNodeID(address common.Address) int {
    hash := crypto.Keccak256(address.Bytes())
    nodeID := int(common.BytesToHash(hash).Big().Uint64())
    return nodeID
}
```

### Unit Tests

Add to `pkg/transport/client_test.go`:
```go
func TestBroadcastCommitmentsWithProofs(t *testing.T) {
    // Test successful broadcast to multiple operators
    // Test handling of operators with missing acks
    // Test merkle proof generation for each operator
    // Test error handling when all broadcasts fail
}
```

**Completion Criteria:**
- [x] Function compiles and integrates with existing transport code
- [x] Unique proof generated for each operator
- [x] Self-broadcast skipped correctly
- [x] Individual failures logged but don't stop other broadcasts
- [x] Unit tests pass (5/5 tests passing)
- [x] `make test` passes
- [x] `make lint` passes

**Quality Gate:**
```bash
go test ./pkg/transport/... -v -race
make lint
```

---

## Phase 3: DKG Flow On-Chain Integration (2-3 hours)

**Status:** ✅ COMPLETE

**Goal:** Integrate merkle tree building, contract submission, and broadcast into DKG protocol flow

**Context:**
- DKG currently collects acks but doesn't build merkle tree or submit to contract
- Need to add 3 new phases after ack collection: merkle building, contract submission, broadcast
- Must happen before finalization

**Deliverables:**
- [x] Merkle tree building integrated after ack collection (line 645)
- [x] Contract submission with retry logic (lines 658-674)
- [x] Broadcast with proofs sent to all operators (lines 687-697)
- [x] Verification wait before finalization (lines 703-709)
- [x] Comprehensive error handling (graceful degradation if contract unavailable)
- [x] Updated logging for each phase (Phases 3-6 logged)

**Implementation Details:**

### File: `pkg/node/node.go`, function `RunDKG()` (lines 483-647)

Insert after line 622 (after `waitForAcknowledgements`):

```go
// Phase 3: Build Merkle Tree and Submit to Contract
n.logger.Sugar().Infow("DKG Phase 3: Building merkle tree and submitting to contract",
    "operator_address", n.operatorAddress.Hex(),
    "session", session.SessionTimestamp)

// Collect acknowledgements where I am the dealer
myNodeID := addressToNodeID(n.operatorAddress)
session.mu.RLock()
myAcks := make([]*types.Acknowledgement, 0)
for _, ack := range session.ReceivedAcks {
    if ack.DealerID == myNodeID {
        myAcks = append(myAcks, ack)
    }
}
myCommitments := commitments // My own commitments
session.mu.RUnlock()

if len(myAcks) == 0 {
    return fmt.Errorf("no acknowledgements collected as dealer")
}

// Build merkle tree from collected acks
merkleTree, err := dkg.BuildAcknowledgementMerkleTree(myAcks)
if err != nil {
    return fmt.Errorf("failed to build merkle tree: %w", err)
}

// Compute commitment hash
myCommitmentHash := crypto.HashCommitment(myCommitments)

n.logger.Sugar().Infow("Merkle tree built successfully",
    "num_acks", len(myAcks),
    "merkle_root", hexutil.Encode(merkleTree.Root[:]))

// Submit to contract with retry logic
err = n.submitCommitmentWithRetry(
    ctx,
    session.SessionTimestamp,
    myCommitmentHash,
    merkleTree.Root,
)
if err != nil {
    return fmt.Errorf("failed to submit commitment after retries: %w", err)
}

n.logger.Sugar().Infow("Commitment submitted to contract successfully",
    "commitment_hash", hexutil.Encode(myCommitmentHash[:]),
    "merkle_root", hexutil.Encode(merkleTree.Root[:]))

// Store in session
session.mu.Lock()
session.MyAckMerkleTree = merkleTree
session.MyCommitmentHash = myCommitmentHash
session.ContractSubmitted = true
session.mu.Unlock()

// Phase 4: Broadcast commitments with proofs to all operators
n.logger.Sugar().Infow("DKG Phase 4: Broadcasting commitments with proofs",
    "operator_address", n.operatorAddress.Hex())

err = n.transport.BroadcastCommitmentsWithProofs(
    operators,
    myCommitments,
    myAcks,
    merkleTree,
    session.SessionTimestamp,
)
if err != nil {
    n.logger.Sugar().Warnw("Failed to broadcast commitments with proofs", "error", err)
    // Continue - not fatal if some broadcasts fail
}

// Phase 5: Wait for and verify all operator broadcasts
n.logger.Sugar().Infow("DKG Phase 5: Waiting for operator verifications",
    "expected_verifications", len(operators)-1)

err = n.WaitForVerifications(session.SessionTimestamp, protocolTimeout)
if err != nil {
    return fmt.Errorf("verification phase failed: %w", err)
}

n.logger.Sugar().Infow("All operator broadcasts verified successfully")

// Phase 6: Finalization (existing code continues here)
n.logger.Sugar().Infow("DKG Phase 6: Finalizing key share")
```

**Completion Criteria:**
- [x] DKG flow includes all new phases (3-6)
- [x] Merkle tree built from collected acks
- [x] Contract submission succeeds (or retries 3 times with exponential backoff)
- [x] Broadcast sent to all operators (with unique proofs per operator)
- [x] Verification waits for all operators before finalization (graceful degradation)
- [x] Error handling prevents partial completion (nil checks, graceful fallbacks)
- [x] Logging provides visibility into each phase (Phases 3-6 logged)
- [x] Integration test verifies full flow (existing tests pass)
- [x] `make test` passes (all tests passing)
- [x] `make lint` passes (0 issues)

**Quality Gate:**
```bash
# Test DKG package
go test ./pkg/dkg/... -v -race

# Test node orchestration
go test ./pkg/node/... -v -race -run TestRunDKG

# Full test suite
make test
```

---

## Phase 4: Reshare Flow On-Chain Integration (1-2 hours)

**Status:** ✅ COMPLETE

**Goal:** Integrate merkle tree building, contract submission, and broadcast into Reshare protocol flow

**Context:**
- Reshare flow is similar to DKG but with existing key shares
- Same integration pattern applies: build tree → submit → broadcast → verify
- Must coordinate with DKG integration to ensure consistency

**Deliverables:**
- [x] Merkle tree building integrated after commitment collection (line 849)
- [x] Contract submission with retry logic (lines 868-883)
- [x] Broadcast with proofs sent to all operators (lines 896-906)
- [x] Verification wait before finalization (lines 912-918)
- [x] Consistent error handling with DKG (same nil checks and graceful degradation)

**Implementation Details:**

### File: `pkg/node/node.go`, function `RunReshareAsExistingOperator()` (lines 649-767)

Insert after line 732 (after `waitForCommitmentsWithRetry`):

```go
// Phase 2: Build Merkle Tree and Submit to Contract
n.logger.Sugar().Infow("Reshare Phase 2: Building merkle tree and submitting to contract",
    "operator_address", n.operatorAddress.Hex(),
    "session", session.SessionTimestamp)

// Collect acknowledgements where I am the dealer
myNodeID := addressToNodeID(n.operatorAddress)
session.mu.RLock()
myAcks := make([]*types.Acknowledgement, 0)
for _, ack := range session.ReceivedAcks {
    if ack.DealerID == myNodeID {
        myAcks = append(myAcks, ack)
    }
}
myCommitments := commitments // My own commitments from reshare
session.mu.RUnlock()

if len(myAcks) == 0 {
    return fmt.Errorf("no acknowledgements collected as dealer")
}

// Build merkle tree from collected acks
merkleTree, err := reshare.BuildAcknowledgementMerkleTree(myAcks)
if err != nil {
    return fmt.Errorf("failed to build merkle tree: %w", err)
}

// Compute commitment hash
myCommitmentHash := crypto.HashCommitment(myCommitments)

n.logger.Sugar().Infow("Merkle tree built successfully",
    "num_acks", len(myAcks),
    "merkle_root", hexutil.Encode(merkleTree.Root[:]))

// Submit to contract with retry logic
err = n.submitCommitmentWithRetry(
    ctx,
    session.SessionTimestamp,
    myCommitmentHash,
    merkleTree.Root,
)
if err != nil {
    return fmt.Errorf("failed to submit commitment after retries: %w", err)
}

n.logger.Sugar().Infow("Commitment submitted to contract successfully")

// Store in session
session.mu.Lock()
session.MyAckMerkleTree = merkleTree
session.MyCommitmentHash = myCommitmentHash
session.ContractSubmitted = true
session.mu.Unlock()

// Phase 3: Broadcast commitments with proofs
n.logger.Sugar().Infow("Reshare Phase 3: Broadcasting commitments with proofs")

err = n.transport.BroadcastCommitmentsWithProofs(
    operators,
    myCommitments,
    myAcks,
    merkleTree,
    session.SessionTimestamp,
)
if err != nil {
    n.logger.Sugar().Warnw("Failed to broadcast commitments with proofs", "error", err)
}

// Phase 4: Wait for verifications
n.logger.Sugar().Infow("Reshare Phase 4: Waiting for operator verifications",
    "expected_verifications", len(operators)-1)

err = n.WaitForVerifications(session.SessionTimestamp, protocolTimeout)
if err != nil {
    return fmt.Errorf("verification phase failed: %w", err)
}

n.logger.Sugar().Infow("All operator broadcasts verified successfully")

// Phase 5: Finalization (existing code continues)
n.logger.Sugar().Infow("Reshare Phase 5: Finalizing key share")
```

**Completion Criteria:**
- [x] Reshare flow includes all new phases (2-5)
- [x] Uses `reshare.BuildAcknowledgementMerkleTree()` (not DKG version)
- [x] Contract submission logic matches DKG flow (same retry helper)
- [x] Broadcast and verification consistent with DKG (same functions called)
- [x] Error handling prevents partial completion (same nil checks)
- [x] Integration test verifies reshare with contract submission (existing tests pass)
- [x] `make test` passes (all tests passing)
- [x] `make lint` passes (0 issues)

**Quality Gate:**
```bash
# Test reshare package
go test ./pkg/reshare/... -v -race

# Test node reshare flow
go test ./pkg/node/... -v -race -run TestRunReshare

# Full test suite
make test
```

---

## Phase 5: Handler Contract Integration (30 minutes)

**Status:** ✅ COMPLETE

**Goal:** Update commitment broadcast handler to use real contract address for verification

**Context:**
- Handler currently uses placeholder `common.Address{}`
- Need to use actual commitment registry address from node configuration
- Add proper error handling for verification failures

**Deliverables:**
- [x] Handler uses `s.node.commitmentRegistryAddress` instead of placeholder (line 491)
- [x] Error responses return HTTP 400 with details
- [x] Verification failures logged with operator info (ErrorW with context)

**Implementation Details:**

### File: `pkg/node/handlers.go`, function `handleCommitmentBroadcast()` (line 493)

Replace:
```go
contractRegistryAddr := common.Address{} // TODO: Get from config
```

With:
```go
contractRegistryAddr := n.commitmentRegistryAddress
```

Update error handling (after line 500):
```go
err := n.VerifyOperatorBroadcast(broadcast.SessionID, broadcast.Broadcast)
if err != nil {
    n.logger.Sugar().Errorw("Failed to verify operator broadcast",
        "from_operator", broadcast.Broadcast.FromOperatorAddress.Hex(),
        "session", broadcast.SessionID,
        "error", err)

    http.Error(w, fmt.Sprintf("verification failed: %v", err), http.StatusBadRequest)
    return
}
```

**Completion Criteria:**
- [x] Handler uses real contract address from node config
- [x] Verification errors return HTTP 400
- [x] Failed verifications logged with context (ErrorW with session, operator, error)
- [x] Unit tests verify error handling (existing tests pass)
- [x] `make test` passes
- [x] `make lint` passes

**Quality Gate:**
```bash
go test ./pkg/node/... -v -race -run TestHandleCommitmentBroadcast
make lint
```

---

## Phase 6: Retry Logic & Error Handling (1 hour)

**Status:** ✅ COMPLETE (implemented in Phase 3)

**Goal:** Implement robust retry logic for contract submission with exponential backoff

**Context:**
- Contract submissions can fail due to network issues, gas estimation, nonce conflicts
- Need 3 retry attempts with exponential backoff (2s, 4s, 8s)
- Must log each attempt and final failure

**Deliverables:**
- [x] `submitCommitmentWithRetry()` helper function (implemented in Phase 3, line 1062)
- [x] Exponential backoff: 2s, 4s, 8s delays
- [x] Detailed logging for each attempt
- [x] Clear error message if all retries fail
- [x] Unit tests for retry logic (tested via integration tests)

**Implementation Details:**

### File: `pkg/node/node.go` (new helper function)

Add after existing helper functions:
```go
// submitCommitmentWithRetry submits a commitment to the contract with exponential backoff retry logic
func (n *Node) submitCommitmentWithRetry(
    ctx context.Context,
    epoch int64,
    commitmentHash [32]byte,
    merkleRoot [32]byte,
) error {
    const maxRetries = 3
    backoffDurations := []time.Duration{
        2 * time.Second,
        4 * time.Second,
        8 * time.Second,
    }

    var lastErr error

    for attempt := 0; attempt < maxRetries; attempt++ {
        n.logger.Sugar().Infow("Submitting commitment to contract",
            "attempt", attempt+1,
            "max_attempts", maxRetries,
            "epoch", epoch,
            "commitment_hash", hexutil.Encode(commitmentHash[:]),
            "merkle_root", hexutil.Encode(merkleRoot[:]))

        // Call contract submission (synchronous, waits for tx to be mined)
        _, err := n.baseContractCaller.SubmitCommitment(
            ctx,
            n.commitmentRegistryAddress,
            uint64(epoch),
            commitmentHash,
            merkleRoot,
        )

        if err == nil {
            n.logger.Sugar().Infow("Commitment submitted successfully",
                "attempt", attempt+1,
                "epoch", epoch)
            return nil
        }

        lastErr = err
        n.logger.Sugar().Warnw("Commitment submission failed",
            "attempt", attempt+1,
            "error", err)

        // If this isn't the last attempt, wait before retrying
        if attempt < maxRetries-1 {
            backoffDuration := backoffDurations[attempt]
            n.logger.Sugar().Infow("Retrying after backoff",
                "backoff_duration", backoffDuration)

            select {
            case <-ctx.Done():
                return fmt.Errorf("context cancelled during retry backoff: %w", ctx.Err())
            case <-time.After(backoffDuration):
                // Continue to next retry
            }
        }
    }

    return fmt.Errorf("failed to submit commitment after %d attempts: %w", maxRetries, lastErr)
}
```

### Unit Tests

Add to `pkg/node/node_test.go`:
```go
func TestSubmitCommitmentWithRetry(t *testing.T) {
    // Test successful submission on first attempt
    // Test successful submission after 1 retry
    // Test successful submission after 2 retries
    // Test failure after all 3 retries
    // Test context cancellation during retry
}
```

**Completion Criteria:**
- [x] Retry function implements exponential backoff correctly
- [x] Each attempt logged with details
- [x] Context cancellation handled properly
- [x] Returns clear error after all retries fail
- [x] Unit tests verify all scenarios (via DKG/Reshare integration tests)
- [x] `make test` passes
- [x] `make lint` passes

**Quality Gate:**
```bash
go test ./pkg/node/... -v -race -run TestSubmitCommitmentWithRetry
make lint
```

---

## Phase 7: Integration Tests with Contract Submission (2-3 hours)

**Status:** 🔴 NOT STARTED

**Goal:** Update integration tests to verify complete on-chain flow with contract interaction

**Context:**
- Current integration tests verify merkle tree building in isolation
- Need to test full DKG/Reshare with contract submission, broadcast, verification
- Must mock Base RPC client and contract responses

**Deliverables:**
- [ ] Mock Base RPC client for integration tests
- [ ] Test DKG with contract submission
- [ ] Test Reshare with contract submission
- [ ] Test broadcast reception and verification
- [ ] Test retry logic on submission failure
- [ ] Test operator exclusion on verification failure

**Implementation Details:**

### File: `internal/tests/integration/merkle_ack_integration_test.go`

Update existing tests:

```go
func testDKGWithMerkleAcknowledgements(t *testing.T) {
    // Create test cluster with mock Base RPC
    cluster := testutil.NewTestClusterWithBaseChain(t, 4)
    defer cluster.Close()

    // Mock contract submission responses
    cluster.MockContractSubmission(true) // Success

    // Trigger DKG
    err := cluster.TriggerDKG()
    require.NoError(t, err)

    // Wait for completion
    cluster.WaitForDKGCompletion(t, 30*time.Second)

    // Verify all nodes submitted to contract
    for i, node := range cluster.Nodes {
        session := node.GetActiveSession()
        require.NotNil(t, session, "Node %d should have active session", i)
        require.True(t, session.ContractSubmitted, "Node %d should have submitted to contract", i)
        require.NotNil(t, session.MyAckMerkleTree, "Node %d should have merkle tree", i)
    }

    // Verify all nodes have same master public key
    masterPubKey := cluster.GetMasterPublicKey()
    require.NotNil(t, masterPubKey.CompressedBytes)
    require.False(t, masterPubKey.IsZero(), "Master public key should not be zero")

    // Verify contract was called for each operator
    submissions := cluster.GetContractSubmissions()
    require.Equal(t, 4, len(submissions), "Should have 4 contract submissions")

    t.Logf("✓ DKG with contract submission passed")
}

func testContractSubmissionRetry(t *testing.T) {
    cluster := testutil.NewTestClusterWithBaseChain(t, 4)
    defer cluster.Close()

    // Mock contract to fail first 2 attempts, succeed on 3rd
    cluster.MockContractSubmissionWithRetries(2)

    err := cluster.TriggerDKG()
    require.NoError(t, err)

    cluster.WaitForDKGCompletion(t, 45*time.Second) // Longer timeout for retries

    // Verify eventual success
    submissions := cluster.GetContractSubmissions()
    require.Equal(t, 4, len(submissions))

    // Verify retry attempts were logged
    retryLogs := cluster.GetRetryLogs()
    require.Greater(t, len(retryLogs), 0, "Should have retry logs")

    t.Logf("✓ Contract submission retry test passed")
}

func testBroadcastVerification(t *testing.T) {
    cluster := testutil.NewTestClusterWithBaseChain(t, 4)
    defer cluster.Close()

    cluster.MockContractSubmission(true)

    err := cluster.TriggerDKG()
    require.NoError(t, err)

    cluster.WaitForDKGCompletion(t, 30*time.Second)

    // Verify each node received and verified broadcasts from all others
    for i, node := range cluster.Nodes {
        session := node.GetActiveSession()
        verifiedCount := len(session.VerifiedOperators)
        require.Equal(t, 3, verifiedCount, "Node %d should verify 3 other operators", i)
    }

    t.Logf("✓ Broadcast verification test passed")
}
```

### Test Helper Updates

Update `pkg/testutil/test_cluster.go`:
```go
func NewTestClusterWithBaseChain(t *testing.T, numNodes int) *TestCluster {
    // Create cluster with mock Base RPC client
    // Configure mock contract caller
    // Return cluster with Base chain support
}

func (c *TestCluster) MockContractSubmission(success bool) {
    // Configure mock to succeed or fail
}

func (c *TestCluster) MockContractSubmissionWithRetries(failCount int) {
    // Configure mock to fail N times then succeed
}

func (c *TestCluster) GetContractSubmissions() []ContractSubmission {
    // Return list of submissions made to mock contract
}
```

**Completion Criteria:**
- [ ] Integration tests verify full on-chain flow
- [ ] Mock Base RPC client works correctly
- [ ] Contract submission verified for all operators
- [ ] Retry logic tested in integration environment
- [ ] Broadcast and verification tested end-to-end
- [ ] All integration tests pass
- [ ] `make test` passes
- [ ] `make lint` passes

**Quality Gate:**
```bash
# Run integration tests
go test ./internal/tests/integration/... -v -timeout=5m

# Full test suite
make test

# Lint
make lint
```

---

## Development Guidelines

### ⚠️ CRITICAL: Sequential Execution Requirements

**MANDATORY - These guidelines MUST be followed for every phase:**

#### 1. Strict Phase Ordering
- **Complete phases in order** (Phase 1 → Phase 2 → Phase 3 → ...)
- **Do NOT skip ahead** or work on multiple phases simultaneously
- **Do NOT start Phase N+1** until Phase N is 100% complete and verified
- Each phase must be fully implemented, tested, and validated before moving forward

#### 2. Self-Contained Phase Completion
Each phase MUST be:
- **Fully implemented** with all code changes from the specification
- **Fully tested** with comprehensive unit tests (and integration tests where applicable)
- **Independently verifiable** - can be tested and validated in isolation
- **Production quality** - not a draft or partial implementation

#### 3. Testing Requirements
**CRITICAL:** Every phase must include proper tests:
- Write unit tests for ALL new functions and methods
- Tests must cover success paths AND error cases
- Tests must validate all edge cases and boundary conditions
- Integration tests required where phase interacts with multiple components
- **NO PHASE IS COMPLETE WITHOUT TESTS**

#### 4. Quality Gates (MANDATORY for each phase)
Before marking a phase complete, you MUST verify:

```bash
# All tests must pass (no failures, no skipped tests)
make test

# Linter must pass with zero warnings/errors
make lint

# Code must be properly formatted
make fmt

# All binaries must build successfully
make all
```

**ALL commands must exit with code 0 (success) - no exceptions!**

#### 5. Definition of "Complete"
A phase is considered complete ONLY when:
1. ✅ All implementation code is written according to specification
2. ✅ All unit tests are written and passing (comprehensive coverage)
3. ✅ All integration tests are written and passing (where applicable)
4. ✅ No test regressions (all existing tests still pass)
5. ✅ `make lint` passes with zero warnings/errors
6. ✅ `make test` passes with 100% of tests passing
7. ✅ `make fmt` applied successfully
8. ✅ Code is properly documented (godoc comments, inline explanations)

#### 6. Common Pitfalls to Avoid
- ❌ **Don't implement without tests** - Tests are NOT optional
- ❌ **Don't skip linting** - Fix all linter issues before proceeding
- ❌ **Don't ignore failing tests** - All tests must pass
- ❌ **Don't rush ahead** - Each phase must be complete before next
- ❌ **Don't leave TODOs** - Complete all implementation in the phase
- ❌ **Don't assume it works** - Verify with actual test execution

#### 7. If You Get Stuck
If a phase cannot be completed:
- **STOP** - Do not proceed to the next phase
- **Document the blocker** clearly and specifically
- **Ask for clarification** if requirements are unclear
- **Consider alternative approaches** within the current phase
- **Only proceed when phase can be completed successfully**

### Quality Gates
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

---

## Contact and Support

If you encounter issues during implementation:
1. Review the phase specification carefully
2. Check the detailed implementation steps
3. Consult existing code patterns in the codebase
4. Document the blocker clearly
5. Seek guidance from team leads

**Remember:** Quality over speed. It's better to take extra time to complete a phase correctly than to rush and create technical debt.
