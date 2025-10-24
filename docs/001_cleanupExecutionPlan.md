# KMS Implementation Execution Plan

## Overview

This document outlines the implementation plan for completing the EigenX KMS system. Each milestone must be completed in full, with all tests passing and no linter errors, before proceeding to the next milestone.

---

## Milestone 1: Fix Integration Testing Infrastructure

**Goal**: Restore comprehensive integration testing that was regressed during refactoring.

**Why First**: We need working integration tests to validate all subsequent changes. Currently, testutil creates empty nodes without running DKG, causing integration tests to fail.

### Tasks:
- [x] Update `testutil.NewTestCluster()` to actually execute DKG protocol
  - [x] Have nodes coordinate DKG execution
  - [x] Wait for DKG completion with timeout
  - [x] Populate `cluster.MasterPubKey` from commitments
  - [x] Ensure all nodes have active key versions
- [x] Verify restored integration tests pass:
  - [x] `Test_ReshareIntegration/FullReshareProtocol`
  - [x] `Test_ReshareIntegration/ReshareWithThresholdChange`
  - [x] `Test_ReshareIntegration/ReshareSecretConsistency`
  - [x] `Test_DKGIntegration/FullDKGProtocol`
- [x] Run all tests: `go test ./...` (all must pass)
- [x] Run linter: `make lint` (0 issues)
- [x] Fixed critical authentication bug: `VerifySolidityCompatible` vs `Verify`

### Success Criteria:
- ✅ All integration tests pass with real DKG execution
- ✅ Tests verify cryptographic properties (secret preservation, threshold correctness)
- ✅ No test skips or stubs remaining
- ✅ Authentication working correctly with BN254 signatures

---

## Milestone 2: Session Management for Concurrent Protocols

**Goal**: Add session tracking to handle concurrent/overlapping DKG and reshare operations safely.

**Why Second**: Before adding automatic scheduling, we need sessions to prevent message confusion between different protocol runs.

### Tasks:
- [x] Add session tracking to Node struct
  - [x] Add `activeSessions map[int64]*ProtocolSession`
  - [x] Add `sessionMutex sync.RWMutex`
  - [x] Define `ProtocolSession` struct with type, timestamp, phase, state
- [x] Update all message types with `SessionTimestamp int64`:
  - [x] `ShareMessage`
  - [x] `CommitmentMessage`
  - [x] `AcknowledgementMessage`
  - [x] `CompletionMessage`
- [x] Update message handlers to route by session:
  - [x] `handleDKGShare` - find session, store share in session context
  - [x] `handleDKGCommitment` - route to session
  - [x] `handleDKGAck` - route to session
  - [x] Store in both session state and global state for compatibility
- [x] Update `RunDKG()` to use sessions:
  - [x] Create session at start with timestamp
  - [x] Include session timestamp in all outgoing messages
  - [x] Clean up session on completion/failure via defer
- [x] Update `RunReshare()` to use sessions:
  - [x] Create session at start
  - [x] Include session timestamp in messages
  - [x] Clean up on completion
- [x] Refactor transport layer for clarity:
  - [x] Renamed `SendShareWithRetry` to `SendDKGShare` and `SendReshareShare`
  - [x] Renamed `BroadcastCommitments` to `BroadcastDKGCommitments` and `BroadcastReshareCommitments`
  - [x] Removed endpoint parameter - transport methods now know their endpoints
  - [x] Split `SendAcknowledgement` into `SendDKGAcknowledgement` and `SendReshareAcknowledgement`
- [x] Add session timeout and cleanup logic
  - [x] Added `cleanupOldSessions(maxAge)` for future scheduler use
  - [x] Sessions tracked by timestamp for expiration
- [x] Run all tests: `go test ./...` (all must pass)
- [x] Run linter: `make lint` (0 issues)

### Success Criteria:
- ✅ Multiple DKG/reshare sessions can be tracked independently
- ✅ Messages correctly routed to their session
- ✅ Transport layer properly abstracted with clear method names
- ✅ All existing tests still pass
- ✅ Ready for automatic scheduling in Milestone 3

---

## Milestone 3: Automatic Protocol Scheduling

**Goal**: Move DKG/reshare scheduling into the Node with automatic 10-minute reshare cycles.

**Why Third**: Now that we have session management, we can safely add automatic scheduling.

### Tasks:
- [x] Add chain-specific reshare intervals to config:
  - [x] Add `ReshareInterval` constants by ChainId to `pkg/config/config.go`
    - [x] Mainnet: 10 minutes
    - [x] Sepolia: 2 minutes
    - [x] Anvil/Devnet: 1 minute
  - [x] Add `GetReshareIntervalForChain(chainId)` function
- [x] Update node.Config:
  - [x] Add `ChainID config.ChainId` parameter
  - [x] Update all node creation to include ChainID
  - [x] Add `DKGAt *time.Time` (optional coordinated DKG time)
  - [x] Derive `ReshareInterval` from ChainID at runtime
  - [x] Automatic resharing always enabled (no flag needed)
- [x] Implement `startScheduler()` method in Node:
  - [x] Create 500ms ticker
  - [x] Run in goroutine
  - [x] Call `checkScheduledOperations()` on each tick
  - [x] Handle graceful shutdown via schedulerStop channel
  - [x] Always start scheduler for all nodes
- [x] Implement `checkScheduledOperations()`:
  - [x] Check if `DKGAt` is set and time has passed:
    - [x] Run DKG once (in goroutine)
    - [x] Set dkgTriggered flag to prevent duplicates
  - [x] Check if at reshare boundary (chain-specific intervals):
    - [x] Track lastReshareTime to calculate when to trigger
    - [x] Run reshare (in goroutine)
    - [x] Update lastReshareTime to avoid duplicates
- [x] Update `RunDKG()` to use session timestamps:
  - [x] Create session with `time.Now().Unix()`
  - [x] Sessions created and cleaned up via defer
- [x] Update `RunReshare()` to use session timestamps:
  - [x] Create session with timestamp
  - [x] Session-based message routing
- [x] Remove scheduling logic from `cmd/kmsServer/main.go`:
  - [x] Deleted scheduleDKG and runDKGAsync functions
  - [x] Node scheduler handles all protocol triggers
  - [x] Removed manual DKG execution code
- [x] Update kmsServer CLI:
  - [x] Convert DKGAt from int64 to *time.Time when passing to Node
  - [x] Support immediate execution (DKGAt=0)
- [x] Run all tests: `go test ./...` (all must pass)
- [x] Run linter: `make lint` (0 issues)

### Success Criteria:
- ✅ DKG automatically triggers at specified time
- ✅ Reshare automatically runs at chain-specific intervals (10min/2min/1min)
- ✅ No manual scheduling needed in main.go
- ✅ Scheduler properly integrated into Node lifecycle
- ✅ All tests pass, 0 linter issues

---
## Milestone 4: Unified Interval-Based Protocol Execution

**Goal**: Implement interval-based protocol execution that handles genesis DKG, automatic resharing, and new operator joining in a unified flow.

**Why Fourth**: The scheduler ticks at intervals - we need to implement the decision logic for what to execute at each boundary.

**Key Insight**: DKG is a group effort where `master_secret = Σ f_i(0)`. Nodes don't need perfect start-time coordination - they just need to use the same session timestamp (rounded to interval boundary). The master secret is the aggregate of all contributions regardless of when each node starts.

### The Unified Execution Flow:

```
Every 500ms scheduler tick:
  │
  ├─ [Step 1] Calculate rounded interval boundary
  │   intervalSeconds = reshareInterval.Seconds()
  │   roundedTime = (now.Unix() / intervalSeconds) * intervalSeconds
  │
  ├─ [Step 2] Check if already processed this boundary
  │   if roundedTime == lastProcessedBoundary:
  │       return  // Skip - already handled this interval
  │   lastProcessedBoundary = roundedTime
  │
  ├─ [Step 3] Determine if I'm a new or existing operator
  │   hasShares = (keyStore.GetActiveVersion() != nil)
  │
  ├─ [Step 4] Execute appropriate protocol with rounded timestamp
  │   if !hasShares:  // I'm a new operator
  │       ├─ Query /pubkey from all operators in set
  │       ├─ Does anyone have master public key commitments?
  │       │   ├─ NO → Genesis DKG needed
  │       │   │   └─ RunDKG(roundedTime)
  │       │   └─ YES → Existing cluster, join via reshare
  │       │       └─ RunReshareAsNewOperator(roundedTime)
  │   else:  // I'm an existing operator
  │       └─ RunReshareAsExistingOperator(roundedTime)
```

### Tasks:

**Phase 1: Rounded Timestamp Coordination**
- [x] Update Node struct scheduling fields:
  - [x] Add `lastProcessedBoundary int64` field
  - [x] Remove `lastReshareTime time.Time` (replaced by boundary tracking)
  - [x] Remove `dkgAt *time.Time` (no longer needed)
  - [x] Remove `dkgTriggered bool` (no longer needed)
  - [x] Initialize `lastProcessedBoundary` to 0 in NewNode
- [ ] Remove DKGAt from node.Config:
  - [x] Remove `DKGAt *time.Time` field
  - [x] Remove from all node creation sites
- [ ] Update `checkScheduledOperations()` to use rounded timestamps:
  - [x] Calculate `intervalSeconds = int64(n.reshareInterval.Seconds())`
  - [x] Calculate `roundedTime = (now.Unix() / intervalSeconds) * intervalSeconds`
  - [x] Skip if `roundedTime == n.lastProcessedBoundary`
  - [x] Update `n.lastProcessedBoundary = roundedTime` before triggering protocol
  - [x] Log rounded timestamp for debugging

**Phase 2: Cluster State Detection**
- [ ] Implement `hasExistingShares()` method:
  - [x] Return `n.keyStore.GetActiveVersion() != nil`
  - [x] Simple check - no locks needed (keyStore is thread-safe)
- [ ] Implement `detectClusterState()` method:
  - [x] Fetch current operators from peering system
  - [x] Query `/pubkey` from each operator via HTTP GET
  - [x] Check if response contains valid commitments (len > 0)
  - [x] Return "genesis" if NO operator has commitments
  - [x] Return "existing" if ANY operator has commitments
  - [x] Handle HTTP errors (operator down = skip, don't fail)
  - [x] Log detection result with operator count

**Phase 3: Protocol Method Refactoring**
- [ ] Refactor `RunDKG()` to accept session timestamp:
  - [x] Change signature: `func (n *Node) RunDKG(sessionTimestamp int64) error`
  - [x] Use `sessionTimestamp` when calling `createSession()`
  - [x] Remove `session := n.createSession()` - accept timestamp parameter
  - [x] Update `createSession()` to accept timestamp: `createSession(sessionType, operators, timestamp)`
- [ ] Implement `RunReshareAsExistingOperator(sessionTimestamp int64)`:
  - [x] Essentially current `RunReshare()` with session timestamp parameter
  - [x] Get current share: `currentShare, err := n.keyStore.GetActivePrivateShare()`
  - [x] Generate new shares: `shares, commitments := n.resharer.GenerateNewShares(currentShare, threshold)`
  - [x] Broadcast to ALL operators in set
  - [x] Wait for threshold responses
  - [x] Finalize and store new key version
- [ ] Implement `RunReshareAsNewOperator(sessionTimestamp int64)`:
  - [x] Create session with timestamp
  - [x] DON'T call `GenerateNewShares()` (no current share to use)
  - [x] ONLY wait for shares from existing operators
  - [x] Wait for shares: `waitForSharesWithRetry(len(operators), timeout)`
  - [x] Wait for commitments: `waitForCommitmentsWithRetry(len(operators), timeout)`
  - [x] Compute final share via Lagrange: `resharer.ComputeNewKeyShare(participantIDs, receivedShares, allCommitments)`
  - [x] Store as first `KeyShareVersion`
  - [x] Log successful join

**Phase 4: Updated Interval Handler**
- [ ] Rewrite `checkScheduledOperations()` with unified flow:
  - [x] Step 1: Calculate `roundedTime` as interval boundary
  - [x] Step 2: Check if `roundedTime == lastProcessedBoundary`, skip if true
  - [x] Step 3: Update `lastProcessedBoundary = roundedTime`
  - [x] Step 4: Call `hasExistingShares()` to determine state
  - [x] Step 5a: New operator path:
    - [x] Call `detectClusterState()`
    - [x] If "genesis" → `go RunDKG(roundedTime)`
    - [x] If "existing" → `go RunReshareAsNewOperator(roundedTime)`
  - [x] Step 5b: Existing operator path:
    - [x] `go RunReshareAsExistingOperator(roundedTime)`
  - [x] Proper error logging for all paths

**Phase 5: Session Creation Update**
- [ ] Update `createSession()` signature:
  - [x] Add `sessionTimestamp int64` parameter
  - [x] Use provided timestamp instead of `time.Now().Unix()`
  - [x] Ensures caller controls session timestamp
- [ ] Update all `createSession()` calls:
  - [x] Pass `sessionTimestamp` from protocol methods
  - [x] Remove any `time.Now()` calls in protocol code

**Phase 6: Testing**
- [ ] Update existing tests to use new signatures:
  - [x] Update `testutil` if it calls RunDKG directly
  - [x] Ensure tests still pass with session timestamp parameter
- [ ] Add new tests for interval-based execution:
  - [x] Test rounded timestamp calculation with various times
  - [x] Test `lastProcessedBoundary` prevents duplicates
  - [x] Test `detectClusterState()` with empty cluster (genesis)
  - [x] Test `detectClusterState()` with existing cluster
  - [x] Test new operator joining at interval
- [ ] Run all tests: `go test ./...` (all must pass)
- [ ] Run linter: `make lint` (0 issues)

### Success Criteria:
- ✅ All nodes calculate same rounded timestamp for interval boundaries
- ✅ `lastProcessedBoundary` prevents duplicate protocol executions
- ✅ Genesis DKG happens automatically at first interval when no master pubkey exists
- ✅ New operators automatically join via reshare at next interval
- ✅ Existing operators automatically reshare at intervals
- ✅ No coordination required - nodes self-organize via interval boundaries
- ✅ All tests pass, 0 linter issues

### Why This Works:

**Rounded Timestamps Solve Coordination:**
```go
// Node A ticks at 17:00:00.157 → roundedTime = 17:00:00
// Node B ticks at 17:00:00.623 → roundedTime = 17:00:00
// Node C ticks at 17:00:01.091 → roundedTime = 17:00:00
// All use sessionTimestamp = 17:00:00 → messages route correctly
```

**Genesis DKG Works Without Perfect Sync:**
- Each node independently generates random polynomial
- Master secret = aggregate of all polynomials
- Doesn't matter if Node A starts at :00.1 and Node B at :00.8
- Final key is `f_A(0) + f_B(0) + f_C(0)` regardless of timing

**New Operators Join Seamlessly:**
- At interval boundary, existing operators detect new member in operator set
- Existing operators reshare (include new operator in distribution)
- New operator waits for shares, computes via Lagrange
- All use same roundedTime for session coordination


---

## Milestone 5: Threshold Governance & Operational Flexibility

**Goal**: Add support for threshold adjustments to handle planned operator rotations safely.

**Why Last**: This is an operational enhancement that builds on all previous functionality.

### Tasks:
- [ ] Add threshold override to config:
  - [x] Add `ThresholdOverride *int` to node.Config
  - [x] Add `--threshold-override` flag to kmsServer CLI
  - [x] Document governance process for setting threshold
- [ ] Update threshold calculation:
  - [x] Modify `calculateThreshold()` to check override first
  - [x] Fall back to 2n/3	 if no override
  - [x] Log when override is used
- [ ] Add threshold validation:
  - [x] Ensure threshold d number of operators
  - [x] Ensure threshold e 1
  - [x] Warn if threshold < 2n/3	 (reduced security)
- [ ] Update reshare to use explicit threshold:
  - [x] Pass threshold to `GenerateNewShares()` explicitly
  - [x] Don't always recalculate from operator count
- [ ] Add tests for threshold scenarios:
  - [x] Test threshold override
  - [x] Test planned operator rotation with threshold reduction
  - [x] Test your scenario (add 3, remove original 3)
  - [x] Test threshold validation
- [ ] Update documentation:
  - [x] Document threshold governance in CLAUDE.md
  - [x] Add operator rotation playbook
  - [x] Document safe threshold adjustment procedures
- [ ] Run all tests: `go test ./...` (all must pass)
- [ ] Run linter: `make lint` (0 issues)

### Success Criteria:
- Threshold can be safely adjusted via governance
- Planned operator rotations work correctly
- System remains secure during threshold changes
- All scenarios documented

---

## General Guidelines:

1. **Complete Each Milestone Fully**: Do not move to the next milestone until:
   - All tasks are completed
   - All tests pass (`go test ./...`)
   - Linter shows 0 issues (`make lint`)
   - Integration tests verify the milestone's functionality

2. **Test-Driven Approach**:
   - Write/update tests first where possible
   - Ensure tests fail before implementation
   - Verify tests pass after implementation

3. **No Regressions**:
   - Existing tests must continue to pass
   - No new linter errors introduced
   - No functionality removed without replacement

4. **Documentation**:
   - Update CLAUDE.md for significant architectural changes
   - Update command READMEs for CLI changes
   - Add inline comments for complex logic

---

## Current Status:

 **Completed**:
- Authenticated messaging system with BN254 signatures
- Address-based operator identification
- Complete DKG protocol with acknowledgements
- Complete reshare protocol implementation
- kmsClient CLI with on-chain operator discovery
- kmsServer with blockchain integration
- Code cleanup (removed unused methods and fields)

L **Not Started**:
- Automatic scheduling in Node (Milestone 1-3)
- Session management (Milestone 2)
- Bootstrap detection (Milestone 4)
- New operator support (Milestone 4)
- Threshold governance (Milestone 5)

**✅ Milestone 1 Complete!**

- Fixed `testutil.NewTestCluster()` to execute real coordinated DKG
- Fixed authentication bug (`VerifySolidityCompatible` vs `Verify`)
- Restored all comprehensive integration tests
- All tests passing with real cryptographic verification
- 0 linter issues

**✅ Milestone 1 Complete!**

---

## Milestone 2: Session Management - ✅ COMPLETE

**Completed Tasks:**
- Session tracking infrastructure with `ProtocolSession` struct
- All message types include `SessionTimestamp`
- Message handlers route by session with validation
- Transport layer refactored with clear method names
- Endpoints handled internally (no caller-specified paths)
- Proper error handling throughout
- Session cleanup with `cleanupOldSessions()` ready for scheduler
- All tests passing, 0 linter issues

**✅ Milestone 2 Complete!**

---

## Milestone 3: Automatic Protocol Scheduling - ✅ COMPLETE

**Completed:**
- Chain-specific reshare intervals (10min/2min/1min)
- Automatic scheduler with 500ms ticker
- All scheduling moved into Node
- DKGAt removed (interval-based execution only)

---

## Milestone 4: Unified Interval-Based Protocol Execution - ✅ COMPLETE

**Completed:**
- Rounded timestamp coordination for session alignment
- `hasExistingShares()` and `detectClusterState()` methods
- `RunDKG(sessionTimestamp)` with provided timestamp
- `RunReshareAsExistingOperator(sessionTimestamp)` for nodes with shares
- `RunReshareAsNewOperator(sessionTimestamp)` for new operators joining
- Unified `checkScheduledOperations()` flow
- All tests passing, 0 linter issues

**Ready to begin Milestone 5.**
