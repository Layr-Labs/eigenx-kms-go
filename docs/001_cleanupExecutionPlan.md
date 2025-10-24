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
- [ ] Add session tracking to Node struct
  - [ ] Add `activeSessions map[int64]*ProtocolSession`
  - [ ] Add `sessionMutex sync.RWMutex`
  - [ ] Define `ProtocolSession` struct with type, timestamp, phase, state
- [ ] Update all message types with `SessionTimestamp int64`:
  - [ ] `ShareMessage`
  - [ ] `CommitmentMessage`
  - [ ] `AcknowledgementMessage`
  - [ ] `CompletionMessage`
- [ ] Update message handlers to route by session:
  - [ ] `handleDKGShare` - find/create session, store share in session context
  - [ ] `handleDKGCommitment` - route to session
  - [ ] `handleDKGAck` - route to session
  - [ ] `handleReshareShare` - route to session
  - [ ] `handleReshareCommitment` - route to session
- [ ] Update `RunDKG()` to use sessions:
  - [ ] Create session at start with timestamp
  - [ ] Include session timestamp in all outgoing messages
  - [ ] Wait for session completion
  - [ ] Clean up session on completion/failure
- [ ] Update `RunReshare()` to use sessions:
  - [ ] Create session at start
  - [ ] Include session timestamp in messages
  - [ ] Clean up on completion
- [ ] Add session timeout and cleanup logic
  - [ ] Expire sessions after reasonable timeout (5 minutes)
  - [ ] Clean up old session data
- [ ] Update all tests to handle session-aware messaging
- [ ] Run all tests: `go test ./...` (all must pass)
- [ ] Run linter: `make lint` (0 issues)

### Success Criteria:
- Multiple DKG/reshare sessions can be tracked independently
- Messages correctly routed to their session
- No message confusion between concurrent operations
- All existing tests still pass

---

## Milestone 3: Automatic Protocol Scheduling

**Goal**: Move DKG/reshare scheduling into the Node with automatic 10-minute reshare cycles.

**Why Third**: Now that we have session management, we can safely add automatic scheduling.

### Tasks:
- [ ] Update node.Config:
  - [ ] Add `DKGAt *time.Time` (optional coordinated DKG time)
  - [ ] Add `EnableAutoReshare bool` (enable 10-minute cycles)
  - [ ] Add `ReshareInterval time.Duration` (default 10 minutes)
- [ ] Implement `startScheduler()` method in Node:
  - [ ] Create 500ms ticker
  - [ ] Run in goroutine
  - [ ] Call `checkScheduledOperations()` on each tick
  - [ ] Handle graceful shutdown
- [ ] Implement `checkScheduledOperations()`:
  - [ ] Check if `DKGAt` is set and time has passed:
    - [ ] Run DKG once (in goroutine)
    - [ ] Clear `DKGAt` after triggering
  - [ ] Check if at reshare boundary (10-minute intervals):
    - [ ] Calculate boundary: `now.Unix() % (10*60) < 1`
    - [ ] Run reshare (in goroutine)
    - [ ] Track last reshare time to avoid duplicates
- [ ] Update `RunDKG()` to use session timestamps:
  - [ ] Create session with `time.Now().Unix()`
  - [ ] Log session start/completion
- [ ] Update `RunReshare()` to use session timestamps:
  - [ ] Create session with rounded 10-minute boundary timestamp
  - [ ] All operators use same session timestamp
- [ ] Remove scheduling logic from `cmd/kmsServer/main.go`:
  - [ ] Delete manual DKG scheduling code
  - [ ] Let Node handle scheduling internally
- [ ] Add tests for automatic scheduling:
  - [ ] Test DKGAt trigger fires correctly
  - [ ] Test 10-minute boundary detection
  - [ ] Test no duplicate triggers
- [ ] Run all tests: `go test ./...` (all must pass)
- [ ] Run linter: `make lint` (0 issues)

### Success Criteria:
- DKG automatically triggers at specified time
- Reshare automatically runs every 10 minutes
- No manual scheduling needed in main.go
- All tests pass including new scheduling tests

---

## Milestone 4: Bootstrap Detection & New Operator Support

**Goal**: Enable nodes to detect if they're joining an existing cluster vs starting fresh, and support new operators joining via reshare.

**Why Fourth**: With scheduling and sessions working, we can now handle the complexities of new operators joining.

### Tasks:
- [ ] Implement bootstrap detection:
  - [ ] Add `detectClusterState()` method
  - [ ] Query operators via `/pubkey` for existing commitments
  - [ ] Return "genesis" if no operators have keys, "existing" otherwise
- [ ] Update Node startup logic:
  - [ ] On start, call `detectClusterState()`
  - [ ] If genesis + DKGAt set � schedule DKG
  - [ ] If existing cluster � wait for next reshare cycle
- [ ] Implement new operator reshare flow:
  - [ ] Add `isNewOperator()` method - checks if node has active key share
  - [ ] Split `RunReshare()` into two paths:
    - [ ] `runReshareAsExistingOperator()` - generates new shares from current share
    - [ ] `runReshareAsNewOperator()` - only receives shares from existing operators
- [ ] Update `runReshareAsExistingOperator()`:
  - [ ] Use current share as `f'_i(0)`
  - [ ] Generate and send shares to ALL operators (including new)
  - [ ] Participate in finalization
- [ ] Implement `runReshareAsNewOperator()`:
  - [ ] Don't generate shares (no current share)
  - [ ] Only receive shares from existing operators
  - [ ] Compute final share via Lagrange: `x'_j = � �_i s'_ij`
  - [ ] Store first key version
- [ ] Update operator set change detection:
  - [ ] Compare current vs previous operator set
  - [ ] Log added/removed operators
  - [ ] Trigger reshare when set changes (don't wait for 10-minute boundary)
- [ ] Add tests for new operator joining:
  - [ ] Test genesis DKG with all operators
  - [ ] Test new operator joining existing cluster
  - [ ] Test operator removal scenarios
  - [ ] Test complete operator turnover (your scenario)
- [ ] Run all tests: `go test ./...` (all must pass)
- [ ] Run linter: `make lint` (0 issues)

### Success Criteria:
- Nodes correctly detect genesis vs existing cluster
- New operators successfully join via reshare
- Existing operators handle new members correctly
- All bootstrap scenarios tested

---

## Milestone 5: Threshold Governance & Operational Flexibility

**Goal**: Add support for threshold adjustments to handle planned operator rotations safely.

**Why Last**: This is an operational enhancement that builds on all previous functionality.

### Tasks:
- [ ] Add threshold override to config:
  - [ ] Add `ThresholdOverride *int` to node.Config
  - [ ] Add `--threshold-override` flag to kmsServer CLI
  - [ ] Document governance process for setting threshold
- [ ] Update threshold calculation:
  - [ ] Modify `calculateThreshold()` to check override first
  - [ ] Fall back to 2n/3	 if no override
  - [ ] Log when override is used
- [ ] Add threshold validation:
  - [ ] Ensure threshold d number of operators
  - [ ] Ensure threshold e 1
  - [ ] Warn if threshold < 2n/3	 (reduced security)
- [ ] Update reshare to use explicit threshold:
  - [ ] Pass threshold to `GenerateNewShares()` explicitly
  - [ ] Don't always recalculate from operator count
- [ ] Add tests for threshold scenarios:
  - [ ] Test threshold override
  - [ ] Test planned operator rotation with threshold reduction
  - [ ] Test your scenario (add 3, remove original 3)
  - [ ] Test threshold validation
- [ ] Update documentation:
  - [ ] Document threshold governance in CLAUDE.md
  - [ ] Add operator rotation playbook
  - [ ] Document safe threshold adjustment procedures
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

**Ready to begin Milestone 2.**
