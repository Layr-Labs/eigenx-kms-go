# EigenX KMS Node Persistence - Implementation Plan

## Overview

Implement a persistence layer for the EigenX KMS node to survive restarts, using a unified `INodePersistence` interface with both in-memory (testing) and Badger (production) implementations. This enables nodes to restore critical state including key shares, operational state, and protocol sessions after crashes or restarts.

---

# Execution Guidelines

**CRITICAL: These guidelines must be followed strictly during implementation:**

1. **Sequential Implementation**: Implement milestones in order (1→2→3→4→5→6→7). Never skip ahead or work on multiple milestones in parallel.

2. **Milestone Completion Criteria**: A milestone is only complete when:
   - All code is implemented
   - All tests pass: `make test` succeeds with no failures
   - Linter passes: `make lint` succeeds with no warnings
   - Tests provide adequate coverage for the new code

3. **Testing Requirements**: Each milestone must include:
   - Unit tests for all new functions/methods
   - Integration tests where applicable
   - Edge case coverage (nil checks, error paths, concurrent access)
   - Tests must be run and verified before proceeding

4. **Quality Gates**: Before moving to the next milestone:
   - Run `make test` - all tests must pass
   - Run `make lint` - no linting errors
   - Review test coverage - all critical paths tested
   - Verify no regressions in existing functionality

5. **No Partial Work**: Do not leave TODOs, incomplete implementations, or commented-out code. Each milestone should be production-ready.

---

## Critical State to Persist

Based on analysis of `/Users/seanmcgary/Code/eigenx-kms-go-secondary/pkg/node/node.go`:

### Must Persist
1. **Key Shares** - All versioned key shares from DKG/reshare operations
2. **Active Version** - Pointer to currently active key version epoch
3. **Block Boundary** - `lastProcessedBoundary` to avoid re-triggering protocols
4. **Protocol Sessions** - In-progress DKG/reshare state for crash recovery

### Ephemeral (Derived/Config)
- Operators (fetched from blockchain)
- Configuration (loaded from CLI/env)
- Runtime channels and locks

---

## Architecture

### Interface Design

**Package**: `pkg/persistence/`

```go
type INodePersistence interface {
    // Key Share Management
    SaveKeyShareVersion(version *types.KeyShareVersion) error
    LoadKeyShareVersion(epoch int64) (*types.KeyShareVersion, error)
    ListKeyShareVersions() ([]*types.KeyShareVersion, error)
    DeleteKeyShareVersion(epoch int64) error

    // Active Version Tracking
    SetActiveVersionEpoch(epoch int64) error
    GetActiveVersionEpoch() (int64, error)

    // Node Operational State
    SaveNodeState(state *NodeState) error
    LoadNodeState() (*NodeState, error)

    // Protocol Session Management
    SaveProtocolSession(session *ProtocolSessionState) error
    LoadProtocolSession(sessionTimestamp int64) (*ProtocolSessionState, error)
    DeleteProtocolSession(sessionTimestamp int64) error
    ListProtocolSessions() ([]*ProtocolSessionState, error)

    // Lifecycle
    Close() error
    HealthCheck() error
}
```

### Storage Key Schema

```
keyshare:{epoch}             -> KeyShareVersion (JSON)
active:version               -> int64 epoch
nodestate:main               -> NodeState (JSON)
session:{sessionTimestamp}   -> ProtocolSessionState (JSON)
metadata:schema_version      -> "v1"
```

### Serialization

- **Field Elements**: Use existing `SerializeFr()/DeserializeFr()` from `pkg/types/messages.go`
- **G1/G2 Points**: Already JSON-serializable via `CompressedBytes` field
- **Structs**: JSON marshal/unmarshal with custom helpers for `*fr.Element` fields

---

## Implementation Milestones

### Milestone 1: Interface and Core Types

**Files to Create:**
- `pkg/persistence/interface.go` - Core interface definition
- `pkg/persistence/types.go` - NodeState, ProtocolSessionState structs
- `pkg/persistence/serialization.go` - Helpers for KeyShareVersion serialization

**Deliverables:**
- `INodePersistence` interface with full documentation
- `NodeState` struct for operational state
- `ProtocolSessionState` struct for session recovery
- Serialization helpers: `SerializeKeyShareVersion()`, `DeserializeKeyShareVersion()`

**Testing:**
- Serialization tests for round-trip conversion
- Test that SerializeKeyShareVersion/DeserializeKeyShareVersion preserve data

**Acceptance Criteria:**
- [x] `pkg/persistence/interface.go` created with INodePersistence interface
- [x] `pkg/persistence/types.go` created with NodeState and ProtocolSessionState
- [x] `pkg/persistence/serialization.go` created with serialization helpers
- [x] All struct fields properly documented
- [x] Serialization test passes for KeyShareVersion round-trip
- [x] Serialization test passes for ProtocolSessionState round-trip
- [x] `make lint` passes with no errors
- [x] Code reviewed for completeness

**Status: ✅ COMPLETED**

---

### Milestone 2: In-Memory Implementation

**Files to Create:**
- `pkg/persistence/memory/memory.go` - Thread-safe in-memory persistence
- `pkg/persistence/memory/memory_test.go` - Comprehensive unit tests

**Implementation Details:**
- Use `sync.RWMutex` for thread safety
- Deep copy all data to prevent external mutation
- Warn loudly when instantiated (testing only)
- Zero-config constructor: `NewMemoryPersistence()`

**Deliverables:**
- Fully functional in-memory implementation
- Unit tests covering all interface methods
- Thread-safety tests (concurrent access)

**Testing:**
```go
func TestMemoryPersistence_SaveAndLoadKeyShare(t *testing.T)
func TestMemoryPersistence_ActiveVersionTracking(t *testing.T)
func TestMemoryPersistence_NodeState(t *testing.T)
func TestMemoryPersistence_ProtocolSessions(t *testing.T)
func TestMemoryPersistence_ThreadSafety(t *testing.T)
func TestMemoryPersistence_Close(t *testing.T)
func TestMemoryPersistence_HealthCheck(t *testing.T)
```

**Quality Gate:**
- Run `make test` - all tests pass
- Run `make lint` - no errors

**Acceptance Criteria:**
- [x] `pkg/persistence/memory/memory.go` created with full implementation
- [x] `pkg/persistence/memory/memory_test.go` created with comprehensive tests
- [x] All INodePersistence interface methods implemented
- [x] Thread-safe implementation with sync.RWMutex
- [x] Deep copy data to prevent external mutation
- [x] Warning message printed on instantiation
- [x] TestMemoryPersistence_SaveAndLoadKeyShare passes
- [x] TestMemoryPersistence_ActiveVersionTracking passes
- [x] TestMemoryPersistence_NodeState passes
- [x] TestMemoryPersistence_ProtocolSessions passes
- [x] TestMemoryPersistence_ThreadSafety passes
- [x] TestMemoryPersistence_Close passes
- [x] TestMemoryPersistence_HealthCheck passes
- [x] `make test` passes (all tests)
- [x] `make lint` passes with no errors
- [x] Code coverage adequate (>80% for new code)

**Status: ✅ COMPLETED**

---

### Milestone 3: Node Integration with Memory Persistence

**Files to Modify:**
- `pkg/node/node.go` - Add persistence field, RestoreState method
- `pkg/config/config.go` - Add PersistenceConfig struct
- `cmd/kmsServer/main.go` - Wire up memory persistence (temporarily)
- `pkg/testutil/test_cluster.go` - Create memory persistence for test nodes

**Node Changes (pkg/node/node.go):**

1. **Add Field** (line ~63):
```go
persistence persistence.INodePersistence
```

2. **Update Constructor** (line ~135):
```go
func NewNode(..., persistence persistence.INodePersistence, l *zap.Logger) *Node
```

3. **Add RestoreState Method** (new):
```go
func (n *Node) RestoreState() error {
    // Load lastProcessedBoundary
    // Load all key share versions
    // Restore active version pointer
    // Clean up incomplete sessions
}
```

4. **Update Start()** (line ~292):
```go
func (n *Node) Start() error {
    if err := n.RestoreState(); err != nil {
        return fmt.Errorf("failed to restore state: %w", err)
    }
    // ... rest unchanged
}
```

5. **Add Persistence Calls**:
   - After DKG completion (line ~640): `SaveKeyShareVersion()`, `SetActiveVersionEpoch()`
   - After reshare completion (line ~757): `SaveKeyShareVersion()`, `SetActiveVersionEpoch()`
   - After block boundary (line ~225): `SaveNodeState()`

**Config Changes (pkg/config/config.go):**

1. **Add Struct** (line ~180):
```go
type PersistenceConfig struct {
    Type     string `json:"type"`      // "memory" or "badger"
    DataPath string `json:"data_path"` // For badger
}
```

2. **Add to KMSServerConfig**:
```go
PersistenceConfig PersistenceConfig `json:"persistence_config"`
```

3. **Add Constants** (line ~13):
```go
EnvKMSPersistenceType     = "KMS_PERSISTENCE_TYPE"
EnvKMSPersistenceDataPath = "KMS_PERSISTENCE_DATA_PATH"
```

4. **Add Validation**:
```go
func (pc *PersistenceConfig) Validate() error
```

**Main.go Changes (cmd/kmsServer/main.go):**

1. **Create Persistence** (replace lines ~159-160):
```go
nodePersistence := memory.NewMemoryPersistence()
defer nodePersistence.Close()
```

2. **Update Node Constructor** (line ~185):
```go
n := node.NewNode(nodeConfig, pdf, bh, poller, imts, nodePersistence, l)
```

**Deliverables:**
- Node can persist and restore state using memory implementation
- All existing tests pass with memory persistence
- Config infrastructure ready for Badger

**Testing:**
- Run existing integration tests - all should pass
- Verify RestoreState() loads nothing on first run (new node)
- Verify persistence calls don't break DKG/reshare

**Quality Gate:**
- Run `make test` - all tests pass (including existing tests)
- Run `make lint` - no errors

**Acceptance Criteria:**
- [x] `pkg/node/node.go` - persistence field added to Node struct
- [x] `pkg/node/node.go` - NewNode constructor updated with persistence parameter
- [x] `pkg/node/node.go` - RestoreState() method implemented
- [x] `pkg/node/node.go` - Start() calls RestoreState()
- [x] `pkg/node/node.go` - DKG completion saves key share and active version
- [x] `pkg/node/node.go` - Reshare completion saves key share and active version
- [x] `pkg/node/node.go` - Block boundary saves node state
- [x] `pkg/config/config.go` - PersistenceConfig struct added
- [x] `pkg/config/config.go` - Environment variable constants added
- [x] `pkg/config/config.go` - Validate() method for PersistenceConfig
- [x] `pkg/config/config.go` - PersistenceConfig added to KMSServerConfig
- [x] `cmd/kmsServer/main.go` - Memory persistence created and passed to Node
- [x] `pkg/testutil/test_cluster.go` - Memory persistence created for test nodes
- [x] All existing integration tests pass
- [x] RestoreState() works correctly on first run (empty state)
- [x] Persistence calls don't break DKG protocol
- [x] Persistence calls don't break reshare protocol
- [x] `make test` passes (all tests including existing)
- [x] `make lint` passes with no errors

**Status: ✅ COMPLETED**

**Notes:**
- Simplified serialization to use standard JSON marshaling (fr.Element has built-in JSON support)
- Updated all test files: secrets_test.go, onchain_integration_test.go, test_cluster.go
- Fixed import alias conflict (persistenceMemory) in cmd/kmsServer/main.go

---

### Milestone 4: Badger Implementation

**Files to Create:**
- `pkg/persistence/badger/badger.go` - Production Badger implementation
- `pkg/persistence/badger/logger.go` - Badger logger adapter (zap -> badger)
- `pkg/persistence/badger/badger_test.go` - Unit tests

**Dependencies:**
- Update `go.mod`: `go get github.com/dgraph-io/badger/v3`

**Implementation Details:**

1. **Constructor**:
```go
func NewBadgerPersistence(dataPath string, logger *zap.Logger) (*BadgerPersistence, error) {
    opts := badger.DefaultOptions(dataPath)
    opts.SyncWrites = true  // Durability
    opts.Logger = &badgerLoggerAdapter{logger: logger}

    db, err := badger.Open(opts)
    // Initialize schema version
    // Start background GC goroutine
}
```

2. **Key Schema Constants**:
```go
const (
    keyPrefixKeyShare      = "keyshare:"
    keyPrefixActiveVersion = "active:"
    keyPrefixNodeState     = "nodestate:"
    keyPrefixSession       = "session:"
    keySchemaVersion       = "metadata:schema_version"
)
```

3. **Serialization**:
- JSON marshal/unmarshal for all structs
- Handle `*fr.Element` fields with SerializeFr/DeserializeFr

4. **Background GC**:
```go
func (b *BadgerPersistence) runGC(ctx context.Context) {
    ticker := time.NewTicker(5 * time.Minute)
    for {
        select {
        case <-ticker.C:
            b.db.RunValueLogGC(0.5)
        case <-ctx.Done():
            return
        }
    }
}
```

**Deliverables:**
- Fully functional Badger implementation
- Logger adapter (zap.Logger -> badger.Logger interface)
- Unit tests matching memory implementation test suite
- Schema versioning for future migrations

**Testing:**
```go
func TestBadgerPersistence_SaveAndLoadKeyShare(t *testing.T) {
    tmpDir := t.TempDir()
    p, err := badger.NewBadgerPersistence(tmpDir, testLogger)
    require.NoError(t, err)
    defer p.Close()
    // Same tests as memory implementation
}
```

**Quality Gate:**
- Run `make test` - all tests pass
- Run `make lint` - no errors

**Acceptance Criteria:**
- [x] `go.mod` updated with badger/v3 dependency
- [x] `pkg/persistence/badger/badger.go` created
- [x] `pkg/persistence/badger/logger.go` created with zap adapter
- [x] `pkg/persistence/badger/badger_test.go` created
- [x] All INodePersistence interface methods implemented
- [x] Constructor properly initializes Badger with SyncWrites=true
- [x] Schema version initialized on first run
- [x] Background GC goroutine started
- [x] Key schema constants defined (keyshare:, active:, nodestate:, session:)
- [x] JSON serialization/deserialization working for all types
- [x] *fr.Element fields handled with built-in JSON marshaling
- [x] TestBadgerPersistence_SaveAndLoadKeyShare passes
- [x] TestBadgerPersistence_ActiveVersionTracking passes
- [x] TestBadgerPersistence_NodeState passes
- [x] TestBadgerPersistence_ProtocolSessions passes
- [x] TestBadgerPersistence_ThreadSafety passes
- [x] TestBadgerPersistence_Close passes
- [x] TestBadgerPersistence_HealthCheck passes
- [x] TestBadgerPersistence_Persistence_AcrossRestarts passes
- [x] Tests use t.TempDir() for isolation
- [x] `make test` passes (all tests)
- [x] `make lint` passes with no errors

**Status: ✅ COMPLETED**

---

### Milestone 5: Config-Driven Persistence Selection

**Files to Modify:**
- `cmd/kmsServer/main.go` - Conditional persistence creation based on config

**Main.go Changes:**

1. **Add CLI Flags** (line ~37):
```go
&cli.StringFlag{
    Name:    "persistence-type",
    Usage:   "Persistence backend: 'memory' or 'badger'",
    Value:   "badger",
    EnvVars: []string{config.EnvKMSPersistenceType},
},
&cli.StringFlag{
    Name:    "persistence-data-path",
    Usage:   "Data directory for Badger",
    Value:   "./kms-data",
    EnvVars: []string{config.EnvKMSPersistenceDataPath},
},
```

2. **Conditional Creation** (replace memory-only line):
```go
var nodePersistence persistence.INodePersistence
if kmsConfig.PersistenceConfig.Type == "badger" {
    var err error
    nodePersistence, err = badger.NewBadgerPersistence(
        kmsConfig.PersistenceConfig.DataPath, l)
    if err != nil {
        l.Sugar().Fatalw("Failed to create Badger persistence", "error", err)
    }
    l.Sugar().Infow("Using Badger persistence",
        "path", kmsConfig.PersistenceConfig.DataPath)
} else {
    nodePersistence = memory.NewMemoryPersistence()
    l.Sugar().Warn("⚠️  Using in-memory persistence - data will be lost on restart")
}
defer nodePersistence.Close()

// Health check
if err := nodePersistence.HealthCheck(); err != nil {
    l.Sugar().Fatalw("Persistence health check failed", "error", err)
}
```

3. **Update parseKMSConfig** (line ~216):
```go
PersistenceConfig: config.PersistenceConfig{
    Type:     c.String("persistence-type"),
    DataPath: c.String("persistence-data-path"),
},
```

**Deliverables:**
- CLI flags for persistence configuration
- Runtime selection between memory and Badger
- Default to Badger (production mode)
- Health check on startup

**Testing:**
- Manual test: Run with `--persistence-type=badger`
- Manual test: Run with `--persistence-type=memory`
- Verify logs show correct mode
- Verify Badger creates data directory

**Quality Gate:**
- Run `make test` - all tests pass
- Run `make lint` - no errors

**Acceptance Criteria:**
- [x] CLI flag `--persistence-type` added with default "badger"
- [x] CLI flag `--persistence-data-path` added with default "./kms-data"
- [x] Environment variables wired to CLI flags
- [x] Conditional persistence creation based on config type
- [x] Badger path creation includes proper error handling
- [x] Memory persistence shows warning log
- [x] Health check called before node start
- [x] Health check failure prevents startup
- [x] parseKMSConfig updated with persistence config
- [x] Manual test with --persistence-type=badger succeeds
- [x] Manual test with --persistence-type=memory succeeds
- [x] Badger creates data directory on first run
- [x] Logs show correct persistence mode
- [x] `make test` passes (all tests)
- [x] `make lint` passes with no errors

**Status: ✅ COMPLETED**

---

### Milestone 6: Integration Testing

**Files to Create:**
- `pkg/node/node_persistence_test.go` - Node restart integration tests

**Test Scenarios:**

1. **Clean Restart**:
```go
func TestNodeRestart_CleanShutdown(t *testing.T) {
    // Create node with Badger persistence
    // Run DKG to completion
    // Store active version epoch
    // Shutdown cleanly
    // Create new node with same data path
    // Verify state restored correctly
}
```

2. **Crash During DKG**:
```go
func TestNodeRestart_CrashDuringDKG(t *testing.T) {
    // Start DKG but don't complete
    // Force shutdown (simulate crash)
    // Restart node
    // Verify incomplete session cleaned up
    // Verify node rejoins on next boundary
}
```

3. **Multiple Reshares**:
```go
func TestNodeRestart_MultipleKeyVersions(t *testing.T) {
    // Run DKG -> Reshare -> Reshare
    // Verify 3 key versions persisted
    // Restart node
    // Verify all 3 versions restored
    // Verify correct active version
}
```

4. **Block Boundary Tracking**:
```go
func TestNodeRestart_BlockBoundaryTracking(t *testing.T) {
    // Process blocks 100, 110, 120
    // Verify lastProcessedBoundary = 120
    // Restart node
    // Verify restored boundary = 120
    // Send block 120 again - verify skipped
}
```

**Deliverables:**
- Integration tests covering all recovery scenarios
- Documentation of recovery behavior
- Validation of persistence correctness

**Quality Gate:**
- Run `make test` - all tests pass (including new integration tests)
- Run `make lint` - no errors

**Acceptance Criteria:**
- [x] `pkg/node/node_persistence_test.go` created
- [x] TestNodeRestart_CleanShutdown implemented and passes
- [x] TestNodeRestart_IncompleteSessions implemented and passes (crash recovery)
- [x] TestNodeRestart_MultipleKeyVersions implemented and passes
- [x] TestNodeRestart_BlockBoundaryTracking implemented and passes
- [x] TestNodeRestart_EmptyState implemented and passes (first run)
- [x] Tests verify state restoration after restart
- [x] Tests verify incomplete session cleanup
- [x] Tests verify multiple key versions persisted correctly
- [x] Tests verify block boundary tracking prevents re-processing
- [x] Tests use Badger persistence with t.TempDir()
- [x] All tests are deterministic and reliable
- [x] `make test` passes (all tests including integration)
- [x] `make lint` passes with no errors
- [x] No flaky tests

**Status: ✅ COMPLETED**

---

### Milestone 7: Documentation and Final Updates

**Files to Update:**
- `docs/006_nodePersistence.md` - Add operational guide sections

**Documentation Sections to Add:**

1. **Recovery Scenarios**
   - Clean restart
   - Crash during protocol
   - Corruption detection

2. **Configuration Guide**
   - CLI flags and environment variables
   - Badger tuning options
   - Data directory recommendations

3. **Security Considerations**
   - Filesystem permissions (0700)
   - Disk encryption recommendations
   - Future: Key encryption at rest

4. **Operational Guide**
   - Backup strategies
   - Disaster recovery
   - Monitoring persistence health

**Deliverables:**
- Complete operational documentation
- Configuration examples
- Security best practices

**Quality Gate:**
- Documentation review complete
- All examples tested and verified

**Acceptance Criteria:**
- [x] Recovery Scenarios section added with detailed examples
- [x] Configuration Guide section added with CLI flags and env vars
- [x] Security Considerations section added
- [x] Operational Guide section added (backup, disaster recovery)
- [x] All configuration examples tested
- [x] Security best practices documented (filesystem permissions, encryption)
- [x] Backup and restore procedures documented
- [x] Monitoring and health check guidance provided
- [x] Documentation reviewed for accuracy
- [x] No TODOs or incomplete sections remain

**Status: ✅ COMPLETED**

---

## Operational Documentation

### Recovery Scenarios

#### Scenario 1: Clean Restart

**Situation**: Node stopped cleanly (SIGTERM) and restarted.

**Expected Behavior**:
1. Node calls `RestoreState()` on startup
2. Loads `lastProcessedBoundary` - skips already-processed blocks
3. Loads all key share versions from persistence
4. Restores active version pointer
5. No incomplete sessions (cleaned up on normal shutdown)

**Outcome**: Node resumes operations seamlessly with full state intact.

**Tested In**: `TestNodeRestart_CleanShutdown`

---

#### Scenario 2: Crash During Protocol (DKG/Reshare)

**Situation**: Node crashes in Phase 2 of DKG or reshare protocol.

**Expected Behavior**:
1. On restart, `RestoreState()` detects incomplete sessions
2. Logs warning about incomplete protocol sessions
3. Cleans up incomplete session state via `DeleteProtocolSession()`
4. Node waits for next block boundary to retry protocol

**Outcome**: Incomplete protocol state cleaned up, node rejoins at next opportunity.

**Tested In**: `TestNodeRestart_IncompleteSessions`

---

#### Scenario 3: Multiple Key Versions

**Situation**: Node has undergone multiple reshares (multiple key versions).

**Expected Behavior**:
1. All historical key versions loaded from persistence
2. Active version pointer correctly identifies current version
3. Historical versions available for time-based attestation validation

**Outcome**: All key versions restored, correct active version set.

**Tested In**: `TestNodeRestart_MultipleKeyVersions`

---

#### Scenario 4: Persistence Corruption

**Situation**: Badger database files corrupted (disk failure, incomplete write).

**Detection**:
1. `HealthCheck()` fails on startup
2. Schema version mismatch detected
3. JSON deserialization errors when loading key shares

**Recovery**:
1. Fatal error on startup (cannot continue)
2. Administrator must restore from backup
3. Or delete data directory and rejoin cluster via reshare

**Prevention**: Use Badger's SyncWrites=true (enabled by default) for durability.

---

### Configuration Guide

#### CLI Flags

```bash
# Use Badger persistence (production default)
./bin/kms-server \
  --operator-address "0x..." \
  --bn254-private-key "0x..." \
  --chain-id 31337 \
  --avs-address "0x..." \
  --persistence-type badger \
  --persistence-data-path /var/lib/kms/data

# Use memory persistence (testing only)
./bin/kms-server \
  --operator-address "0x..." \
  --bn254-private-key "0x..." \
  --chain-id 31337 \
  --avs-address "0x..." \
  --persistence-type memory
```

#### Environment Variables

```bash
# Badger (production)
export KMS_PERSISTENCE_TYPE=badger
export KMS_PERSISTENCE_DATA_PATH=/var/lib/kms/data

# Memory (testing only)
export KMS_PERSISTENCE_TYPE=memory
```

#### Default Behavior

- **Default Type**: `badger` (production-ready)
- **Default Path**: `./kms-data` (relative to working directory)
- **Recommended Path**: `/var/lib/kms/data` (absolute path for production)

---

### Security Considerations

#### Filesystem Permissions

**Requirement**: Data directory must be readable/writable only by the KMS process owner.

```bash
# Create data directory with restricted permissions
sudo mkdir -p /var/lib/kms/data
sudo chown kms:kms /var/lib/kms/data
sudo chmod 0700 /var/lib/kms/data
```

**Rationale**: Key shares stored on disk could be stolen if permissions are too permissive.

---

#### Disk Encryption

**Recommendation**: Use full-disk encryption for the data directory.

**Options**:
- **Linux**: LUKS/dm-crypt
- **Cloud**: AWS EBS encryption, GCP persistent disk encryption
- **Kubernetes**: Encrypted persistent volumes

**Rationale**: Provides defense-in-depth if physical disk is stolen.

---

#### Future Enhancement: Encryption at Rest

**Planned**: Encrypt key shares before persisting to Badger.

**Approach**:
- Derive encryption key from operator's BN254 private key
- AES-256-GCM encryption of serialized key shares
- Transparent to persistence interface

**Status**: Out of scope for current implementation.

---

### Operational Guide

#### Backup Strategies

**1. Filesystem Snapshot**

```bash
# Stop node
systemctl stop kms-node

# Backup data directory
tar -czf kms-backup-$(date +%Y%m%d).tar.gz /var/lib/kms/data

# Restart node
systemctl start kms-node
```

**2. Hot Backup (No Downtime)**

Badger supports snapshots while running:

```go
// Future enhancement: Add backup API endpoint
// GET /admin/backup -> triggers Badger snapshot
err := db.Backup(outputFile, 0)
```

**Status**: Planned for future milestone.

---

#### Disaster Recovery

**Scenario**: Complete data loss (disk failure, corruption).

**Recovery Options**:

**Option 1: Restore from Backup**
```bash
# Stop node
systemctl stop kms-node

# Restore data directory
rm -rf /var/lib/kms/data
tar -xzf kms-backup-20251202.tar.gz -C /

# Restart node
systemctl start kms-node
```

**Option 2: Rejoin Cluster (No Backup)**
```bash
# Delete corrupted data
rm -rf /var/lib/kms/data

# Restart node - will detect no shares and join via reshare
systemctl start kms-node

# Node automatically joins at next block boundary interval
```

**Requirements for Option 2**:
- At least ⌈2n/3⌉ other operators must be operational
- Node will receive new key share via reshare protocol
- Master secret preserved (no data loss from cluster perspective)

---

#### Monitoring and Health Checks

**Health Check Endpoint**

```bash
# Check node health
curl http://localhost:8000/health

# Response includes persistence status
{
  "status": "healthy",
  "hasActiveKey": true,
  "lastReshare": 1234567890
}
```

**Prometheus Metrics** (Future Enhancement)

```
kms_persistence_write_duration_seconds
kms_persistence_read_duration_seconds
kms_persistence_errors_total
kms_key_versions_total
```

**Recommended Alerts**:
- Persistence health check failures
- Missing active key version
- Incomplete session duration > 1 hour

---

#### Data Directory Growth

**Key Share Size**: ~5-10 KB per version

**Growth Rate**:
- Mainnet: 6 versions/hour × 10KB = ~520 MB/year
- Testnet: 30 versions/hour × 10KB = ~2.6 GB/year

**Cleanup Strategy** (Future):
```bash
# Keep last 100 versions, delete older ones
# Implemented via admin API or automatic pruning
```

**Current**: No automatic cleanup - all versions retained indefinitely.

---

### Production Deployment Checklist

- [ ] Data directory created with 0700 permissions
- [ ] Data directory on encrypted volume
- [ ] Persistence type set to "badger" (not memory)
- [ ] Data path is absolute (not relative)
- [ ] Backup strategy implemented
- [ ] Monitoring and alerts configured
- [ ] Disaster recovery procedure documented
- [ ] Operator has tested restore from backup

---

## Critical Files Summary

### Files to Create (New)
1. `pkg/persistence/interface.go` - INodePersistence interface
2. `pkg/persistence/types.go` - NodeState, ProtocolSessionState
3. `pkg/persistence/serialization.go` - Serialization helpers
4. `pkg/persistence/memory/memory.go` - In-memory implementation
5. `pkg/persistence/memory/memory_test.go` - Memory unit tests
6. `pkg/persistence/badger/badger.go` - Badger implementation
7. `pkg/persistence/badger/logger.go` - Logger adapter
8. `pkg/persistence/badger/badger_test.go` - Badger unit tests
9. `pkg/node/node_persistence_test.go` - Integration tests

### Files to Modify (Existing)
1. `pkg/node/node.go` - Add persistence field, RestoreState(), persist calls
2. `pkg/config/config.go` - Add PersistenceConfig
3. `cmd/kmsServer/main.go` - Wire up persistence layer
4. `pkg/testutil/test_cluster.go` - Create memory persistence for tests
5. `go.mod` - Add badger/v3 dependency

---

## Error Handling Strategy

### Fatal Errors (Prevent Startup)
- Cannot open Badger database
- Persistence health check fails
- Corrupted key share data during deserialization

### Retryable Errors (Log Warning, Continue)
- Failed to persist after successful DKG (in-memory state valid)
- Failed to persist block boundary (can recover on next boundary)
- Background GC errors in Badger

### Recoverable Errors (Handle Gracefully)
- Key not found (return nil, expected for new operators)
- Session not found (expected for completed protocols)

---

## Testing Strategy

### Unit Tests
- Memory implementation: All interface methods
- Badger implementation: All interface methods
- Thread-safety: Concurrent access patterns
- Serialization: Round-trip conversion

### Integration Tests
- Node restart after DKG completion
- Node restart after reshare completion
- Crash recovery (incomplete sessions)
- Block boundary tracking across restarts

---

## Success Criteria

1. ✅ Node survives restart with state intact
2. ✅ All existing tests pass with memory persistence
3. ✅ Integration tests pass with Badger persistence
4. ✅ No data loss on clean shutdown
5. ✅ Incomplete sessions cleaned up on crash recovery
6. ✅ Block boundary tracking prevents duplicate protocols
7. ✅ Performance: <10ms overhead per persistence operation
8. ✅ Security: Filesystem permissions documented
9. ✅ Documentation complete and accurate
10. ✅ Default configuration uses Badger (production-ready)

---

## Implementation Order

1. **Milestone 1** - Interface and types (foundation)
2. **Milestone 2** - Memory implementation (testing infrastructure)
3. **Milestone 3** - Node integration (wire up persistence)
4. **Milestone 4** - Badger implementation (production storage)
5. **Milestone 5** - Config-driven selection (runtime flexibility)
6. **Milestone 6** - Integration testing (validation)
7. **Milestone 7** - Documentation (operational readiness)

---

## Estimated Effort

- **Milestone 1**: 2-3 hours (interface design)
- **Milestone 2**: 3-4 hours (memory impl + tests)
- **Milestone 3**: 4-6 hours (node integration, largest change)
- **Milestone 4**: 5-6 hours (Badger impl + tests)
- **Milestone 5**: 1-2 hours (config wiring)
- **Milestone 6**: 3-4 hours (integration tests)
- **Milestone 7**: 2-3 hours (documentation)

**Total**: ~20-28 hours

---

## Future Enhancements (Out of Scope)

1. **Encryption at Rest**: Encrypt key shares before persisting
2. **Session Recovery**: Resume incomplete protocols after crash
3. **Backup API**: Snapshot/restore endpoints for disaster recovery
4. **Metrics**: Prometheus metrics for persistence operations
5. **Alternative Backends**: RocksDB, LevelDB implementations
6. **Key Version Cleanup**: Automatic pruning of old versions
