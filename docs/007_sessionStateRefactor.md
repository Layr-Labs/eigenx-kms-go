# Session State Refactor Plan

## Problem Statement

Currently, protocol state (`receivedShares`, `receivedCommitments`, `receivedAcks`) is stored globally on the Node struct, causing:
1. **Race conditions** between concurrent DKG/Reshare sessions
2. **No completion tracking** - code takes whatever data is available without knowing if all messages received
3. **Data corruption** - multiple sessions overwrite each other's data
4. **Silent failures** - `>=` checks instead of `==` mask bugs

## Solution

Move all protocol state to be session-scoped and use channels for completion signaling.

---

## Phase 1: Data Structure Changes

### 1.1 Update ProtocolSession (DONE)

```go
type ProtocolSession struct {
    // ... existing fields ...

    // State maps (now actually used, not just declared)
    shares      map[int]*fr.Element
    commitments map[int][]types.G2Point
    acks        map[int]map[int]*types.Acknowledgement

    // Completion channels (buffered, size 1)
    sharesCompleteChan      chan bool
    commitmentsCompleteChan chan bool
    acksCompleteChan        chan bool

    // ... rest ...
}
```

### 1.2 Remove Global State from Node (DONE)

Remove these fields:
- ~~`receivedShares map[int]*fr.Element`~~
- ~~`receivedCommitments map[int][]types.G2Point`~~
- ~~`receivedAcks map[int]map[int]*types.Acknowledgement`~~
- ~~`reshareComplete map[int]*types.CompletionSignature`~~

### 1.3 Update createSession (DONE)

Initialize all channels and maps properly.

---

## Phase 2: Handler Updates

### 2.1 handleDKGShare

**Current (wrong):**
```go
n.mu.Lock()
n.receivedShares[fromID] = share  // Global state!
n.mu.Unlock()
```

**New (correct):**
```go
session.mu.Lock()

// Reject duplicates
if _, exists := session.shares[fromNodeID]; exists {
    session.mu.Unlock()
    http.Error(w, "duplicate share", http.StatusBadRequest)
    return
}

session.shares[fromNodeID] = share

// Signal completion when EXACTLY all shares received
if len(session.shares) == len(session.Operators) {
    select {
    case session.sharesCompleteChan <- true:
    default: // Already signaled
    }
}
session.mu.Unlock()
```

**Files to update:**
- `pkg/node/handlers.go` - handleDKGShare (lines ~200-250)
- `pkg/node/handlers.go` - handleReshareShare (similar pattern)

### 2.2 handleDKGCommitment

**New implementation:**
```go
session.mu.Lock()

// Reject duplicates
if _, exists := session.commitments[fromNodeID]; exists {
    session.mu.Unlock()
    http.Error(w, "duplicate commitment", http.StatusBadRequest)
    return
}

session.commitments[fromNodeID] = commitments

// Signal when EXACTLY all commitments received
if len(session.commitments) == len(session.Operators) {
    select {
    case session.commitmentsCompleteChan <- true:
    default:
    }
}
session.mu.Unlock()
```

**Files to update:**
- `pkg/node/handlers.go` - handleDKGCommitment
- `pkg/node/handlers.go` - handleReshareCommitment

### 2.3 handleDKGAck

**New implementation:**
```go
session.mu.Lock()

// Reject duplicates
if _, exists := session.acks[dealerID][playerID]; exists {
    session.mu.Unlock()
    http.Error(w, "duplicate ack", http.StatusBadRequest)
    return
}

if session.acks[dealerID] == nil {
    session.acks[dealerID] = make(map[int]*types.Acknowledgement)
}
session.acks[dealerID][playerID] = ack

// If I'm the dealer, check if I received all expected acks
myNodeID := addressToNodeID(s.node.OperatorAddress)
if dealerID == myNodeID {
    expectedAcks := len(session.Operators) - 1
    if len(session.acks[myNodeID]) == expectedAcks {  // == not >=
        select {
        case session.acksCompleteChan <- true:
        default:
        }
    }
}
session.mu.Unlock()
```

**Files to update:**
- `pkg/node/handlers.go` - handleDKGAck
- `pkg/node/handlers.go` - handleReshareAck

---

## Phase 3: Wait Function Refactor

### 3.1 Replace waitForSharesWithRetry

**Current (polling):**
```go
func (n *Node) waitForSharesWithRetry(expectedCount int, timeout time.Duration) error {
    for time.Now().Before(deadline) {
        n.mu.RLock()
        received := len(n.receivedShares)  // Global!
        n.mu.RUnlock()
        // ...
    }
}
```

**New (channel-based):**
```go
func waitForShares(session *ProtocolSession, timeout time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    select {
    case <-session.sharesCompleteChan:
        return nil

    case <-ctx.Done():
        session.mu.RLock()
        received := len(session.shares)
        expected := len(session.Operators)
        session.mu.RUnlock()
        return fmt.Errorf("timeout: got %d/%d shares", received, expected)
    }
}
```

### 3.2 Replace waitForCommitmentsWithRetry

Same pattern as shares.

### 3.3 Replace waitForAcknowledgements

```go
func waitForAcks(session *ProtocolSession, dealerNodeID int, timeout time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    select {
    case <-session.acksCompleteChan:
        return nil

    case <-ctx.Done():
        session.mu.RLock()
        ackMap := session.acks[dealerNodeID]
        received := 0
        if ackMap != nil {
            received = len(ackMap)
        }
        expected := len(session.Operators) - 1
        session.mu.RUnlock()
        return fmt.Errorf("timeout: got %d/%d acks", received, expected)
    }
}
```

---

## Phase 4: RunDKG Refactor

### 4.1 Update to Use Session State

**Old (lines 561-564):**
```go
if opNodeID == thisNodeID {
    n.mu.Lock()
    n.receivedShares[thisNodeID] = shares[thisNodeID]  // Global!
    n.receivedCommitments[thisNodeID] = commitments
    n.mu.Unlock()
    continue
}
```

**New:**
```go
if opNodeID == thisNodeID {
    session.mu.Lock()
    session.shares[thisNodeID] = shares[thisNodeID]  // Session-scoped!
    session.commitments[thisNodeID] = commitments

    // Check if this completes the set
    if len(session.shares) == len(session.Operators) {
        select {
        case session.sharesCompleteChan <- true:
        default:
        }
    }
    if len(session.commitments) == len(session.Operators) {
        select {
        case session.commitmentsCompleteChan <- true:
        default:
        }
    }
    session.mu.Unlock()
    continue
}
```

### 4.2 Update Waiting

**Old (lines 578-583):**
```go
if err := n.waitForSharesWithRetry(len(operators), protocolTimeout); err != nil {
    return err
}
if err := n.waitForCommitmentsWithRetry(len(operators), protocolTimeout); err != nil {
    return err
}
```

**New:**
```go
if err := waitForShares(session, protocolTimeout); err != nil {
    return err
}
if err := waitForCommitments(session, protocolTimeout); err != nil {
    return err
}
```

### 4.3 Update Data Access

**Old (lines 588-597):**
```go
n.mu.RLock()
receivedShares := make(map[int]*fr.Element)
for k, v := range n.receivedShares {  // Global!
    receivedShares[k] = v
}
receivedCommitments := make(map[int][]types.G2Point)
for k, v := range n.receivedCommitments {
    receivedCommitments[k] = v
}
n.mu.RUnlock()
```

**New:**
```go
session.mu.RLock()
// Now we KNOW we have all data (channel signaled)
receivedShares := session.shares
receivedCommitments := session.commitments
session.mu.RUnlock()
```

---

## Phase 5: Similar Updates for Reshare

Apply same patterns to:
- `RunReshareAsExistingOperator`
- `RunReshareAsNewOperator`
- Reshare handlers

---

## Phase 6: Testing

### Unit Tests to Add

```go
func TestProtocolSession_CompletionChannels(t *testing.T) {
    session := &ProtocolSession{
        shares: make(map[int]*fr.Element),
        Operators: makeTestOperators(3),
        sharesCompleteChan: make(chan bool, 1),
    }

    // Add shares one by one
    session.shares[1] = &fr.Element{}
    // Channel should NOT signal (1 != 3)

    session.shares[2] = &fr.Element{}
    // Channel should NOT signal (2 != 3)

    session.shares[3] = &fr.Element{}
    // NOW signal (3 == 3)
    select {
    case session.sharesCompleteChan <- true:
    default:
    }

    // Verify we can read from channel
    select {
    case <-session.sharesCompleteChan:
        // Success
    case <-time.After(1 * time.Second):
        t.Fatal("should have received completion signal")
    }
}
```

---

## Implementation Order

1. ✅ Update ProtocolSession struct
2. ✅ Remove global state from Node
3. ✅ Update createSession
4. ⏳ Update handlers (share, commitment, ack) - **NEXT**
5. ⏳ Create new wait functions
6. ⏳ Update RunDKG
7. ⏳ Update Reshare functions
8. ⏳ Run tests and fix issues

---

## Files to Modify

- `pkg/node/node.go` - Node struct, createSession, RunDKG, Reshare functions, wait functions
- `pkg/node/handlers.go` - All DKG/Reshare message handlers
- Tests should continue to pass (internal changes only)

---

## Breaking Changes

**None** - This is an internal refactor. External API unchanged.

---

## Risks

1. **Large change** - touches core protocol logic
2. **Hard to review** - state management changes are subtle
3. **Testing critical** - must verify no regressions

**Mitigation:** Implement incrementally, run tests after each phase.
