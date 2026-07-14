# Reshare Auto-Heal + Deterministic Dealer-Set — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the reshare dealer set deterministic across nodes (so a degraded round can never persist divergent shares), and add auto-heal so an already-poisoned cluster recovers by rolling back to the last-good source version — all without changing the master public key (MPK preserved, no re-DKG).

**Architecture:** Two parts. **Part 1 (prevention):** replace the wall-clock, local-head dealer-set cutoff in `deriveAgreedDealerSet` with a block-derived one — an L1 deadline block `N + interval − buffer` (L1 as a shared clock, not a finality oracle), mapped to the first L2 block with `timestamp ≥ T`, and the registry read pinned at that height with retry-until-readable and abort-the-whole-round on persistent failure. **Part 2 (auto-heal):** a persisted counter of consecutive MPK-validation aborts on the same active source version, majority-gated so early rollers don't over-walk; on reaching N=3 the node demotes the poisoned version and rolls the active pointer back to the last-known-good (agreed `srcVersion`) or the next-lower persisted version, excluding poisoned versions from all keystore accessors.

**Tech Stack:** Go, BLS12-381 (gnark-crypto), go-ethereum ethclient, Redis/Badger/in-memory persistence, mockery (vektra) for mocks, testify for assertions.

## Global Constraints

- **Test runner:** always use `./scripts/goTest.sh <pkg-or-args>` (forwards to `go test -count=1 -timeout 10m`), never `go test` directly. It spins up the required web3signer Docker containers.
- **No co-authored-by trailers** in commits.
- **MPK is invariant** across key versions — never introduce a code path that changes it; a rollback re-points the active pointer only.
- **Determinism rule:** every value that decides the dealer set `D` must derive from shared inputs (agreed block *number*, on-chain registry, persisted version numbers), never from a per-node wall clock or an unsynced chain-head read.
- **Reference spec:** `docs/superpowers/specs/2026-07-13-reshare-autoheal-design.md`. Every task's requirements implicitly include this section.
- **Threshold math:** `dkg.CalculateThreshold(n) = ⌈2n/3⌉`; reshare source polynomial degree = `newThreshold − 1`.

---

## File Structure

**Part 1 — deterministic dealer set:**
- `pkg/config/config.go` — add `ReshareCutoffBuffer_*` per-chain constants + `GetReshareCutoffBufferForChain`.
- `pkg/contractCaller/contractCaller.go` — add `HeaderTimestampAt` / `FirstBlockAtOrAfterTimestamp` methods to `IContractCaller`.
- `pkg/contractCaller/caller/blockLookup.go` (new) — implement those methods on `ContractCaller` using the wrapped ethclient.
- `pkg/contractCaller/mock_IContractCaller.go` — regenerated mock (via `mockery`).
- `pkg/contractCaller/testhelpers.go` — add stub methods + `...Func` hooks.
- `pkg/node/node.go` — `deriveAgreedDealerSet`: block-gate + pinned read + retry/abort; thread `triggerBlock` into `RunReshareAsNewOperator`; new-op call site passes `blockNumber`.

**Part 2 — auto-heal:**
- `pkg/persistence/types.go` — add `TrackedSourceVersion`, `ConsecutiveMPKAborts`, `LastKnownGoodSourceVersion` to `NodeState`.
- `pkg/persistence/interface.go` — add poisoned-version-set methods.
- `pkg/persistence/{redis,memory,badger}/*.go` — implement the poisoned-version-set methods.
- `pkg/persistence/mock_INodePersistence.go` (if present) or the stub — regenerate/extend.
- `pkg/keystore/keystore.go` — poisoned-version set + exclusion in `GetActiveVersion`/`GetKeyVersionAtTime`/`GetPrivateShareForVersion`.
- `pkg/node/node.go` — abort-counter increment (majority-gated) + demotion + rollback + LKG record on success + RestoreState wiring + floor halt/alert + observability logs.

**Task ordering:** Part 1 first (Tasks 1–6), Part 2 second (Tasks 7–13). Each task ends with an independently testable deliverable.

---

## PART 1 — Deterministic Dealer Set

### Task 1: Per-chain cutoff buffer config

**Files:**
- Modify: `pkg/config/config.go` (near `ReshareBlockInterval_*` at lines 158-162 and `GetReshareBlockIntervalForChain` at 180-190)
- Test: `pkg/config/config_test.go` (create if absent)

**Interfaces:**
- Produces: `config.GetReshareCutoffBufferForChain(chainId ChainId) int64` — L1 blocks before the round's final boundary at which the dealer set is cut off.

- [ ] **Step 1: Write the failing test**

Create/append to `pkg/config/config_test.go`:

```go
package config

import "testing"

func TestGetReshareCutoffBufferForChain(t *testing.T) {
	cases := []struct {
		chain ChainId
		want  int64
	}{
		{ChainId_EthereumMainnet, 2},
		{ChainId_EthereumSepolia, 2},
		{ChainId_EthereumAnvil, 2},
		{ChainId(999999), 2}, // default
	}
	for _, c := range cases {
		if got := GetReshareCutoffBufferForChain(c.chain); got != c.want {
			t.Fatalf("chain %v: got buffer %d, want %d", c.chain, got, c.want)
		}
	}
}

func TestCutoffBufferStrictlyInsideInterval(t *testing.T) {
	// The cutoff (interval - buffer) must leave >=1 block of room and be > interval/2
	// so dealers have time to submit before it.
	for _, chain := range []ChainId{ChainId_EthereumMainnet, ChainId_EthereumSepolia, ChainId_EthereumAnvil} {
		interval := GetReshareBlockIntervalForChain(chain)
		buffer := GetReshareCutoffBufferForChain(chain)
		if buffer <= 0 || buffer >= interval {
			t.Fatalf("chain %v: buffer %d not strictly inside interval %d", chain, buffer, interval)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./pkg/config -run 'TestGetReshareCutoffBufferForChain|TestCutoffBufferStrictlyInsideInterval' -v`
Expected: FAIL — `undefined: GetReshareCutoffBufferForChain`.

- [ ] **Step 3: Implement the config**

In `pkg/config/config.go`, after the `ReshareBlockInterval_*` const block (line ~162) add:

```go
// Reshare dealer-set cutoff buffer, in L1 blocks before the round's final
// boundary (N + interval). At block N + interval - buffer the dealer set is
// snapshotted. The buffer leaves room after the cutoff to read the pinned
// registry and finalize before the next boundary. Tunable per chain if a
// chain's Base RPC latency needs a wider read window.
const (
	ReshareCutoffBuffer_Mainnet = 2
	ReshareCutoffBuffer_Sepolia = 2
	ReshareCutoffBuffer_Anvil   = 2
)

// GetReshareCutoffBufferForChain returns the dealer-set cutoff buffer (in L1
// blocks) for a given chain.
func GetReshareCutoffBufferForChain(chainId ChainId) int64 {
	switch chainId {
	case ChainId_EthereumMainnet:
		return ReshareCutoffBuffer_Mainnet
	case ChainId_EthereumSepolia:
		return ReshareCutoffBuffer_Sepolia
	case ChainId_EthereumAnvil:
		return ReshareCutoffBuffer_Anvil
	default:
		return ReshareCutoffBuffer_Mainnet
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./scripts/goTest.sh ./pkg/config -run 'TestGetReshareCutoffBufferForChain|TestCutoffBufferStrictlyInsideInterval' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/config/config.go pkg/config/config_test.go
git commit -m "feat(config): add per-chain reshare cutoff buffer"
```

---

### Task 2: L2 block-by-timestamp lookup on the contract caller

**Files:**
- Modify: `pkg/contractCaller/contractCaller.go` (add two methods to `IContractCaller`, after `GetCommitmentAt` at line 97)
- Create: `pkg/contractCaller/caller/blockLookup.go`
- Test: `pkg/contractCaller/caller/blockLookup_test.go`

**Interfaces:**
- Consumes: the wrapped `ethclient *ethclient.Client` field on `ContractCaller` (`caller.go:29`); `HeaderByNumber(ctx, *big.Int) (*types.Header, error)` (used already at `eigenCompute.go:289`).
- Produces (both added to `IContractCaller`):
  - `HeaderTimestampAt(ctx context.Context, blockNumber uint64) (uint64, error)` — the Unix timestamp of a block by number (0 ⇒ latest head).
  - `FirstBlockAtOrAfterTimestamp(ctx context.Context, targetTimestamp uint64) (uint64, error)` — the lowest block number whose `timestamp ≥ targetTimestamp`, via binary search over `[1, head]`; returns an error if the head's timestamp is still `< targetTimestamp` (caller must wait/retry).

- [ ] **Step 1: Write the failing test**

Create `pkg/contractCaller/caller/blockLookup_test.go`. This tests the pure binary-search helper against a fake header-timestamp source, so it needs no live chain:

```go
package caller

import (
	"context"
	"fmt"
	"testing"
)

// fakeChain maps block number -> timestamp; head is the max block.
type fakeChain struct {
	ts   map[uint64]uint64
	head uint64
}

func (f *fakeChain) tsAt(ctx context.Context, n uint64) (uint64, error) {
	if n == 0 {
		n = f.head
	}
	v, ok := f.ts[n]
	if !ok {
		return 0, fmt.Errorf("missing trie node for block %d", n)
	}
	return v, nil
}

func TestFirstBlockAtOrAfterTimestamp(t *testing.T) {
	// blocks 1..10, 2s apart starting at t=1000
	fc := &fakeChain{ts: map[uint64]uint64{}, head: 10}
	for n := uint64(1); n <= 10; n++ {
		fc.ts[n] = 1000 + (n-1)*2 // 1000,1002,...,1018
	}

	cases := []struct {
		target uint64
		want   uint64
	}{
		{1000, 1}, // exact first
		{1001, 2}, // between 1 and 2 -> 2
		{1002, 2}, // exact
		{1017, 9}, // between 8(1014) and 9(1016)? 1016<1017 -> 10
		{1016, 9}, // exact block 9
		{1018, 10},
	}
	for _, c := range cases {
		got, err := firstBlockAtOrAfterTimestamp(context.Background(), c.target, fc.head, fc.tsAt)
		if err != nil {
			t.Fatalf("target %d: unexpected error %v", c.target, err)
		}
		if got != c.want {
			t.Fatalf("target %d: got block %d, want %d", c.target, got, c.want)
		}
	}
}

func TestFirstBlockAtOrAfterTimestamp_HeadNotReached(t *testing.T) {
	fc := &fakeChain{ts: map[uint64]uint64{1: 1000, 2: 1002}, head: 2}
	_, err := firstBlockAtOrAfterTimestamp(context.Background(), 5000, fc.head, fc.tsAt)
	if err == nil {
		t.Fatal("expected error when head timestamp < target, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./pkg/contractCaller/caller -run TestFirstBlockAtOrAfterTimestamp -v`
Expected: FAIL — `undefined: firstBlockAtOrAfterTimestamp`.

- [ ] **Step 3: Implement `blockLookup.go`**

Create `pkg/contractCaller/caller/blockLookup.go`:

```go
package caller

import (
	"context"
	"fmt"
	"math/big"
)

// HeaderTimestampAt returns the Unix timestamp of the block at blockNumber.
// blockNumber == 0 reads the latest head.
func (cc *ContractCaller) HeaderTimestampAt(ctx context.Context, blockNumber uint64) (uint64, error) {
	var num *big.Int
	if blockNumber != 0 {
		num = new(big.Int).SetUint64(blockNumber)
	}
	header, err := cc.ethclient.HeaderByNumber(ctx, num)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch header for block %d: %w", blockNumber, err)
	}
	return header.Time, nil
}

// FirstBlockAtOrAfterTimestamp returns the lowest block number whose timestamp
// is >= targetTimestamp. It errors if the current head's timestamp is still
// below the target (the caller must wait for the chain to advance and retry).
func (cc *ContractCaller) FirstBlockAtOrAfterTimestamp(ctx context.Context, targetTimestamp uint64) (uint64, error) {
	headNum, err := cc.ethclient.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch head header: %w", err)
	}
	head := headNum.Number.Uint64()
	return firstBlockAtOrAfterTimestamp(ctx, targetTimestamp, head, cc.HeaderTimestampAt)
}

// firstBlockAtOrAfterTimestamp is the pure binary search, injectable for tests.
// tsAt(ctx, n) returns block n's timestamp (n==0 => head).
func firstBlockAtOrAfterTimestamp(
	ctx context.Context,
	target uint64,
	head uint64,
	tsAt func(context.Context, uint64) (uint64, error),
) (uint64, error) {
	headTs, err := tsAt(ctx, head)
	if err != nil {
		return 0, err
	}
	if headTs < target {
		return 0, fmt.Errorf("head block %d timestamp %d is below target %d; chain not advanced yet", head, headTs, target)
	}
	// Binary search for the lowest n in [1, head] with tsAt(n) >= target.
	lo, hi := uint64(1), head
	for lo < hi {
		mid := lo + (hi-lo)/2
		ts, err := tsAt(ctx, mid)
		if err != nil {
			return 0, err
		}
		if ts >= target {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo, nil
}
```

- [ ] **Step 4: Add the methods to the interface**

In `pkg/contractCaller/contractCaller.go`, after the `GetCommitmentAt` block (line 97), add:

```go
	// HeaderTimestampAt returns the Unix timestamp of the block at blockNumber
	// (0 => latest head). Used to map an L1 deadline block to an L2 read height.
	HeaderTimestampAt(ctx context.Context, blockNumber uint64) (uint64, error)

	// FirstBlockAtOrAfterTimestamp returns the lowest block number whose timestamp
	// is >= targetTimestamp, or an error if the head has not reached that timestamp.
	FirstBlockAtOrAfterTimestamp(ctx context.Context, targetTimestamp uint64) (uint64, error)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./scripts/goTest.sh ./pkg/contractCaller/caller -run TestFirstBlockAtOrAfterTimestamp -v`
Expected: PASS.

- [ ] **Step 6: Verify the caller package still compiles against the interface**

Run: `./scripts/goTest.sh ./pkg/contractCaller/... 2>&1 | tail -20`
Expected: build errors ONLY about `MockIContractCaller`/stub not implementing the two new methods (fixed in Task 3). If the `caller` package itself fails to compile, fix before proceeding.

- [ ] **Step 7: Commit**

```bash
git add pkg/contractCaller/contractCaller.go pkg/contractCaller/caller/blockLookup.go pkg/contractCaller/caller/blockLookup_test.go
git commit -m "feat(contractCaller): add block-by-timestamp lookup for L2 cutoff resolution"
```

---

### Task 3: Regenerate mock + extend the test stub

**Files:**
- Modify: `pkg/contractCaller/mock_IContractCaller.go` (regenerate via `mockery`)
- Modify: `pkg/contractCaller/testhelpers.go` (add stub methods + `...Func` fields)
- Test: none new (compilation is the test; existing suites must pass)

**Interfaces:**
- Consumes: the two new `IContractCaller` methods from Task 2.
- Produces: `MockContractCallerStub.HeaderTimestampAtFunc` and `.FirstBlockAtOrAfterTimestampFunc` hooks for later tests.

- [ ] **Step 1: Regenerate the mock**

Run from repo root:
```bash
mockery
```
Expected: `pkg/contractCaller/mock_IContractCaller.go` now contains `HeaderTimestampAt` and `FirstBlockAtOrAfterTimestamp` mock method blocks (same shape as the `GetCommitmentAt` block at lines 704-802). If `mockery` is not installed, run `make deps` first (installs it per the repo's dependency setup).

- [ ] **Step 2: Extend the stub**

In `pkg/contractCaller/testhelpers.go`, add fields to `MockContractCallerStub` (after `GetCommitmentAtFunc`, line 24):

```go
	HeaderTimestampAtFunc            func(ctx context.Context, blockNumber uint64) (uint64, error)
	FirstBlockAtOrAfterTimestampFunc func(ctx context.Context, targetTimestamp uint64) (uint64, error)
```

And add the stub methods (mirror the `GetCommitmentAt` stub at lines 83-88):

```go
func (m *MockContractCallerStub) HeaderTimestampAt(ctx context.Context, blockNumber uint64) (uint64, error) {
	if m.HeaderTimestampAtFunc != nil {
		return m.HeaderTimestampAtFunc(ctx, blockNumber)
	}
	return 0, nil
}

func (m *MockContractCallerStub) FirstBlockAtOrAfterTimestamp(ctx context.Context, targetTimestamp uint64) (uint64, error) {
	if m.FirstBlockAtOrAfterTimestampFunc != nil {
		return m.FirstBlockAtOrAfterTimestampFunc(ctx, targetTimestamp)
	}
	return 0, nil
}
```

- [ ] **Step 3: Verify everything compiles**

Run: `./scripts/goTest.sh ./pkg/contractCaller/... -v 2>&1 | tail -20`
Expected: PASS (mock + stub now satisfy the interface).

- [ ] **Step 4: Verify dependent packages compile**

Run: `./scripts/goTest.sh ./pkg/node/... 2>&1 | tail -20`
Expected: PASS or failures unrelated to the interface (node code doesn't call the new methods yet).

- [ ] **Step 5: Commit**

```bash
git add pkg/contractCaller/mock_IContractCaller.go pkg/contractCaller/testhelpers.go
git commit -m "test(contractCaller): regenerate mock and extend stub for block lookup"
```

---

### Task 4: Compute the deterministic L2 cutoff height in `deriveAgreedDealerSet`

**Files:**
- Modify: `pkg/node/node.go` — `deriveAgreedDealerSet` (1156-1215) and its two call sites (2282, 2648)
- Test: `pkg/node/dealer_cutoff_test.go` (create)

**Interfaces:**
- Consumes: `config.GetReshareCutoffBufferForChain`, `config.GetReshareBlockIntervalForChain`, `IContractCaller.HeaderTimestampAt`, `IContractCaller.FirstBlockAtOrAfterTimestamp`.
- Produces: a new unexported helper `func (n *Node) resolveCutoffL2(ctx context.Context, triggerBlock int64) (uint64, error)` that returns the pinned L2 read height (or an error if not yet resolvable). Adds a `triggerBlock int64` parameter to `deriveAgreedDealerSet`.

- [ ] **Step 1: Write the failing test**

Create `pkg/node/dealer_cutoff_test.go`:

```go
package node

import (
	"context"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"go.uber.org/zap"
)

func TestResolveCutoffL2_MapsL1DeadlineToL2Height(t *testing.T) {
	l, _ := zap.NewDevelopment()

	// L1 interval=10, buffer=2 (Anvil) => deadline = triggerBlock + (10-2) = trigger+8.
	// Stub: L1 deadline block's timestamp is 1_700_000_096; the first L2 block at/after
	// that timestamp is 5000.
	const triggerBlock = int64(100)
	interval := config.GetReshareBlockIntervalForChain(config.ChainId_EthereumAnvil)
	buffer := config.GetReshareCutoffBufferForChain(config.ChainId_EthereumAnvil)
	wantDeadline := uint64(triggerBlock) + uint64(interval-buffer)

	var gotDeadlineArg uint64
	stub := &contractCaller.MockContractCallerStub{
		HeaderTimestampAtFunc: func(ctx context.Context, blockNumber uint64) (uint64, error) {
			gotDeadlineArg = blockNumber
			return 1_700_000_096, nil
		},
		FirstBlockAtOrAfterTimestampFunc: func(ctx context.Context, ts uint64) (uint64, error) {
			if ts != 1_700_000_096 {
				t.Fatalf("expected target ts 1700000096, got %d", ts)
			}
			return 5000, nil
		},
	}

	n := &Node{
		logger:             l,
		ChainID:            config.ChainId_EthereumAnvil,
		platformConfigCaller: stub, // L1-bound caller (see Step 3 for selection)
		baseContractCaller: stub,
	}

	got, err := n.resolveCutoffL2(context.Background(), triggerBlock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotDeadlineArg != wantDeadline {
		t.Fatalf("expected L1 timestamp lookup at deadline block %d, got %d", wantDeadline, gotDeadlineArg)
	}
	if got != 5000 {
		t.Fatalf("expected cutoffL2 = 5000, got %d", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./pkg/node -run TestResolveCutoffL2 -v`
Expected: FAIL — `n.resolveCutoffL2 undefined`.

- [ ] **Step 3: Implement `resolveCutoffL2`**

Add to `pkg/node/node.go` (near `deriveAgreedDealerSet`). The L1 timestamp read uses `platformConfigCaller` (L1-bound; falls back to `baseContractCaller` when nil, matching the existing seed pattern at node.go:599); the L2 resolution uses `baseContractCaller`:

```go
// resolveCutoffL2 maps the L1 deadline block (triggerBlock + interval - buffer)
// to the deterministic L2 registry read height: the first L2 block whose
// timestamp is >= the L1 deadline block's timestamp. All honest nodes compute
// the same value from the agreed triggerBlock number. Returns an error (retry)
// if the L1 deadline block does not exist yet or the L2 head has not reached
// the target timestamp.
func (n *Node) resolveCutoffL2(ctx context.Context, triggerBlock int64) (uint64, error) {
	interval := config.GetReshareBlockIntervalForChain(n.ChainID)
	buffer := config.GetReshareCutoffBufferForChain(n.ChainID)
	deadlineL1 := uint64(triggerBlock + interval - buffer)

	l1 := n.platformConfigCaller
	if l1 == nil {
		l1 = n.baseContractCaller
	}
	deadlineTs, err := l1.HeaderTimestampAt(ctx, deadlineL1)
	if err != nil {
		return 0, fmt.Errorf("L1 deadline block %d not readable yet: %w", deadlineL1, err)
	}
	cutoffL2, err := n.baseContractCaller.FirstBlockAtOrAfterTimestamp(ctx, deadlineTs)
	if err != nil {
		return 0, fmt.Errorf("L2 cutoff not resolvable for ts %d: %w", deadlineTs, err)
	}
	return cutoffL2, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./scripts/goTest.sh ./pkg/node -run TestResolveCutoffL2 -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/node/node.go pkg/node/dealer_cutoff_test.go
git commit -m "feat(node): resolve deterministic L2 cutoff height from L1 deadline block"
```

---

### Task 5: Wire the cutoff into `deriveAgreedDealerSet` (block-gate + pinned read + retry/abort)

**Files:**
- Modify: `pkg/node/node.go` — `deriveAgreedDealerSet` (1156-1215): add `triggerBlock int64` param; replace the wall-clock loop with resolve-cutoff → wait-until-resolvable → pinned per-dealer read → abort-on-persistent-failure.
- Modify: both call sites: existing-op `node.go:2282`, new-op `node.go:2648`.
- Test: `pkg/node/dealer_cutoff_test.go` (extend)

**Interfaces:**
- Consumes: `resolveCutoffL2` (Task 4); `GetProtocolTimeoutForChain` (still the outer bound); `baseContractCaller.GetCommitmentAt(ctx, registry, epoch, dealer, cutoffL2)`.
- Produces: `deriveAgreedDealerSet(ctx, operators, epoch, triggerBlock int64) ([]common.Address, map[common.Address][32]byte, error)` — signature changes from `(ctx, operators, epoch, pinnedBlock int64, expectedDealers []common.Address)` to include `triggerBlock` and drop the unused `pinnedBlock`/`expectedDealers` (verify no other caller passes `expectedDealers` non-nil first; if one does, keep it).

- [ ] **Step 1: Write the failing test**

Append to `pkg/node/dealer_cutoff_test.go`. Assert: (a) a `missing trie node` read is retried then succeeds; (b) a dealer read that fails persistently aborts the whole round (no partial D); (c) all reads happen pinned at `cutoffL2`.

```go
func TestDeriveAgreedDealerSet_RetriesThenReadsAtPinnedHeight(t *testing.T) {
	l, _ := zap.NewDevelopment()
	dealers := makeAddrs(3) // helper: []common.Address of len 3 (add if absent)

	var readsAtCutoff int
	callsPerDealer := map[common.Address]int{}
	stub := &contractCaller.MockContractCallerStub{
		HeaderTimestampAtFunc: func(ctx context.Context, b uint64) (uint64, error) { return 1000, nil },
		FirstBlockAtOrAfterTimestampFunc: func(ctx context.Context, ts uint64) (uint64, error) { return 5000, nil },
		GetCommitmentAtFunc: func(ctx context.Context, reg common.Address, epoch int64, op common.Address, blk uint64) ([32]byte, [32]byte, uint64, error) {
			if blk != 5000 {
				t.Fatalf("expected read pinned at cutoffL2=5000, got %d", blk)
			}
			readsAtCutoff++
			callsPerDealer[op]++
			// First dealer's first read simulates not-yet-synced, then succeeds.
			if op == dealers[0] && callsPerDealer[op] == 1 {
				return [32]byte{}, [32]byte{}, 0, fmt.Errorf("missing trie node")
			}
			var h [32]byte
			h[0] = 1 // non-zero => submitted
			return h, [32]byte{}, 0, nil
		},
	}
	n := nodeWithDealers(t, l, stub, dealers) // helper: builds *Node with these expected dealers + stub callers

	got, _, err := n.deriveAgreedDealerSet(context.Background(), n.testOperators, 12345, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected all 3 dealers, got %d", len(got))
	}
}

func TestDeriveAgreedDealerSet_AbortsWholeRoundOnPersistentReadFailure(t *testing.T) {
	l, _ := zap.NewDevelopment()
	dealers := makeAddrs(3)
	stub := &contractCaller.MockContractCallerStub{
		HeaderTimestampAtFunc: func(ctx context.Context, b uint64) (uint64, error) { return 1000, nil },
		FirstBlockAtOrAfterTimestampFunc: func(ctx context.Context, ts uint64) (uint64, error) { return 5000, nil },
		GetCommitmentAtFunc: func(ctx context.Context, reg common.Address, epoch int64, op common.Address, blk uint64) ([32]byte, [32]byte, uint64, error) {
			if op == dealers[2] {
				return [32]byte{}, [32]byte{}, 0, fmt.Errorf("missing trie node") // never recovers
			}
			var h [32]byte
			h[0] = 1
			return h, [32]byte{}, 0, nil
		},
	}
	n := nodeWithDealers(t, l, stub, dealers)
	// Use a short protocol timeout for the test via n.ChainID = Anvil (30s) or inject a ctx deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err := n.deriveAgreedDealerSet(ctx, n.testOperators, 12345, 100)
	if err == nil {
		t.Fatal("expected whole-round abort when a dealer read never succeeds, got nil error")
	}
}
```

Add helpers at the bottom of the test file if not already present (`makeAddrs`, `nodeWithDealers`, and a `testOperators` field). Keep them minimal — mirror `pkg/node/reshare_validation_test.go`'s `makeNodeForValidation`. If adding a field to `Node` for tests is undesirable, have `nodeWithDealers` return `(*Node, []*peering.OperatorSetPeer)` and pass operators explicitly.

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./pkg/node -run TestDeriveAgreedDealerSet -v`
Expected: FAIL — signature mismatch (`deriveAgreedDealerSet` doesn't take `triggerBlock`) / behavior missing.

- [ ] **Step 3: Rewrite `deriveAgreedDealerSet`**

Replace the body of `deriveAgreedDealerSet` (node.go:1156-1215). New signature and logic:

```go
func (n *Node) deriveAgreedDealerSet(
	ctx context.Context,
	operators []*peering.OperatorSetPeer,
	epoch int64,
	triggerBlock int64,
) ([]common.Address, map[common.Address][32]byte, error) {
	expected := n.expectedReshareDealers(operators)
	if len(expected) == 0 {
		return nil, nil, fmt.Errorf("no expected dealers for reshare")
	}

	deadline := time.Now().Add(config.GetProtocolTimeoutForChain(n.ChainID))
	pollInterval := 1 * time.Second

	// Resolve the deterministic L2 cutoff height, retrying until the chain has
	// advanced far enough (bounded by the protocol-timeout deadline).
	var cutoffL2 uint64
	for {
		h, err := n.resolveCutoffL2(ctx, triggerBlock)
		if err == nil {
			cutoffL2 = h
			break
		}
		if time.Now().After(deadline) {
			return nil, nil, fmt.Errorf("reshare aborted: L2 cutoff not resolvable before deadline: %w; will retry next interval", err)
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}

	// Read every expected dealer's commitment pinned at cutoffL2. A transient
	// read failure (e.g. this node's L2 view not yet synced to cutoffL2) is
	// RETRIED, never skipped: skipping would drop a dealer on one node only and
	// re-introduce the cross-node dealer-set split. If any dealer still cannot
	// be read by the deadline, ABORT the whole round so all nodes fail together.
	submitted := make([]common.Address, 0, len(expected))
	onChainHashes := make(map[common.Address][32]byte, len(expected))
	for _, dealer := range expected {
		var lastErr error
		for {
			commitmentHash, _, _, err := n.baseContractCaller.GetCommitmentAt(
				ctx, n.commitmentRegistryAddress, epoch, dealer, cutoffL2,
			)
			if err == nil {
				if commitmentHash != ([32]byte{}) {
					submitted = append(submitted, dealer)
					onChainHashes[dealer] = commitmentHash
				}
				break
			}
			lastErr = err
			if time.Now().After(deadline) {
				return nil, nil, fmt.Errorf("reshare aborted: dealer %s not readable at cutoff L2 block %d before deadline: %w; will retry next interval",
					dealer.Hex(), cutoffL2, lastErr)
			}
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(pollInterval):
			}
		}
	}

	n.logger.Sugar().Infow("Derived agreed dealer set at pinned L2 cutoff",
		"operator_address", n.OperatorAddress.Hex(),
		"cutoff_l2_block", cutoffL2, "submitted", len(submitted), "expected", len(expected))
	return submitted, onChainHashes, nil
}
```

- [ ] **Step 4: Update both call sites**

At `node.go:2282` (existing-operator path):
```go
	agreedDealers, onChainHashes, err := n.deriveAgreedDealerSet(ctx, operators, session.SessionTimestamp, triggerBlock)
```
(`triggerBlock` is the `RunReshareAsExistingOperator` parameter — already in scope.)

At `node.go:2648` (new-operator path): temporarily pass `0`; Task 6 threads the real trigger block:
```go
	agreedDealers, onChainHashes, err := n.deriveAgreedDealerSet(ctx, operators, session.SessionTimestamp, 0)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `./scripts/goTest.sh ./pkg/node -run 'TestDeriveAgreedDealerSet|TestResolveCutoffL2' -v`
Expected: PASS.

- [ ] **Step 6: Run the full node + integration reshare suites (regression)**

Run: `./scripts/goTest.sh ./pkg/node/... -run Reshare -v 2>&1 | tail -30`
Run: `./scripts/goTest.sh ./internal/tests/integration -run Reshare -v 2>&1 | tail -30`
Expected: PASS, including `Test_Reshare_SucceedsWithExactlyThresholdAcks`. If the integration cluster's mock poller doesn't advance L2 headers, the stub callers used by the cluster must return sane `HeaderTimestampAt`/`FirstBlockAtOrAfterTimestamp` values — see Task 6 note and adjust `testutil` cluster caller wiring so `resolveCutoffL2` returns the current session's height (map `triggerBlock` → a cutoff the cluster's registry stub honors).

- [ ] **Step 7: Commit**

```bash
git add pkg/node/node.go pkg/node/dealer_cutoff_test.go
git commit -m "feat(node): derive dealer set at deterministic L2 cutoff with retry/abort"
```

---

### Task 6: Thread `triggerBlock` into the new-operator join path

**Files:**
- Modify: `pkg/node/node.go` — `RunReshareAsNewOperator` (2458-2459) signature + its `deriveAgreedDealerSet` call (2648) + the scheduler call site (778-784)
- Test: `pkg/node/dealer_cutoff_test.go` (extend)

**Interfaces:**
- Produces: `RunReshareAsNewOperator(sessionTimestamp int64, triggerBlock int64) error`.

- [ ] **Step 1: Write the failing test**

Append to `pkg/node/dealer_cutoff_test.go` — assert a joining node computes the same cutoff as an existing node given the same trigger block:

```go
func TestNewOperatorPath_UsesTriggerBlockForCutoff(t *testing.T) {
	l, _ := zap.NewDevelopment()
	var seenDeadlineBlock uint64
	stub := &contractCaller.MockContractCallerStub{
		HeaderTimestampAtFunc: func(ctx context.Context, b uint64) (uint64, error) {
			seenDeadlineBlock = b
			return 1000, nil
		},
		FirstBlockAtOrAfterTimestampFunc: func(ctx context.Context, ts uint64) (uint64, error) { return 5000, nil },
	}
	n := &Node{logger: l, ChainID: config.ChainId_EthereumAnvil, baseContractCaller: stub, platformConfigCaller: stub}

	got, err := n.resolveCutoffL2(context.Background(), 200)
	require.NoError(t, err)
	require.Equal(t, uint64(5000), got)
	interval := config.GetReshareBlockIntervalForChain(config.ChainId_EthereumAnvil)
	buffer := config.GetReshareCutoffBufferForChain(config.ChainId_EthereumAnvil)
	require.Equal(t, uint64(200+interval-buffer), seenDeadlineBlock)
}
```

(This exercises the shared `resolveCutoffL2`; the join path uses the identical helper, so parity is structural. The signature change is verified by compilation in Step 3–4.)

- [ ] **Step 2: Run test to verify it fails/compiles**

Run: `./scripts/goTest.sh ./pkg/node -run TestNewOperatorPath -v`
Expected: PASS for the helper assertion (it already works); proceed to make the signature change so the join path actually passes a real trigger block.

- [ ] **Step 3: Change the signature and call**

In `pkg/node/node.go`:
- Line 2459: `func (n *Node) RunReshareAsNewOperator(sessionTimestamp int64, triggerBlock int64) error {`
- Line 2648: `agreedDealers, onChainHashes, err := n.deriveAgreedDealerSet(ctx, operators, session.SessionTimestamp, triggerBlock)`

- [ ] **Step 4: Update the scheduler call site**

At `node.go:778-784`:
```go
	go func() {
		if err := n.RunReshareAsNewOperator(blockTimestamp, blockNumber); err != nil {
			n.logger.Sugar().Errorw("Failed to join cluster via reshare",
				"operator_address", n.OperatorAddress.Hex(),
				"error", err)
		}
	}()
```

- [ ] **Step 5: Run tests + build**

Run: `./scripts/goTest.sh ./pkg/node/... -run 'Reshare|Cutoff' -v 2>&1 | tail -30`
Expected: PASS. Fix any other `RunReshareAsNewOperator(...)` call sites the compiler flags (search: `grep -rn "RunReshareAsNewOperator(" --include=*.go`).

- [ ] **Step 6: Commit**

```bash
git add pkg/node/node.go pkg/node/dealer_cutoff_test.go
git commit -m "feat(node): thread trigger block into new-operator reshare for cutoff parity"
```

---

## PART 2 — Auto-Heal

### Task 7: Persist abort counter + LKG marker in NodeState

**Files:**
- Modify: `pkg/persistence/types.go` — add fields to `NodeState`
- Test: `pkg/persistence/serialization_test.go` (extend) or a new `pkg/persistence/nodestate_test.go`

**Interfaces:**
- Produces: three new JSON-serialized `NodeState` fields:
  - `TrackedSourceVersion int64` — the active source version the abort counter is counting against.
  - `ConsecutiveMPKAborts int` — count of consecutive MPK-validation aborts on that version.
  - `LastKnownGoodSourceVersion int64` — the agreed `srcVersion` of the last MPK-validated persist (0 = none).

- [ ] **Step 1: Write the failing test**

Create `pkg/persistence/nodestate_test.go`:

```go
package persistence

import (
	"encoding/json"
	"testing"
)

func TestNodeState_AutoHealFieldsRoundTrip(t *testing.T) {
	in := &NodeState{
		LastProcessedBoundary:      100,
		OperatorAddress:            "0xabc",
		TrackedSourceVersion:       1783944564,
		ConsecutiveMPKAborts:       3,
		LastKnownGoodSourceVersion: 1783944444,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out NodeState
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.TrackedSourceVersion != 1783944564 || out.ConsecutiveMPKAborts != 3 || out.LastKnownGoodSourceVersion != 1783944444 {
		t.Fatalf("auto-heal fields did not round-trip: %+v", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./pkg/persistence -run TestNodeState_AutoHealFieldsRoundTrip -v`
Expected: FAIL — unknown fields.

- [ ] **Step 3: Add the fields**

In `pkg/persistence/types.go`, inside `NodeState`:

```go
	// TrackedSourceVersion is the active source version the MPK-abort counter is
	// currently counting against. The counter is only trusted after restart when
	// this equals the current active source version.
	TrackedSourceVersion int64 `json:"trackedSourceVersion"`

	// ConsecutiveMPKAborts counts consecutive Layer-1 MPK-validation aborts on
	// TrackedSourceVersion. Reaching the demotion threshold marks that version poisoned.
	ConsecutiveMPKAborts int `json:"consecutiveMpkAborts"`

	// LastKnownGoodSourceVersion is the agreed majority source version (srcVersion)
	// of the most recent reshare round that passed MPK validation and persisted.
	// 0 means none recorded yet. Used as the preferred auto-heal rollback target.
	LastKnownGoodSourceVersion int64 `json:"lastKnownGoodSourceVersion"`
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./scripts/goTest.sh ./pkg/persistence -run TestNodeState_AutoHealFieldsRoundTrip -v`
Expected: PASS.

- [ ] **Step 5: Verify memory/redis/badger NodeState copies carry the new fields**

Check `pkg/persistence/memory/memory.go:182-190` and `206-210` — the memory backend copies `NodeState` field-by-field; add the three new fields to both the save-copy and load-copy structs. (Redis/Badger marshal the whole struct as JSON, so they need no change.) Run:
`./scripts/goTest.sh ./pkg/persistence/... -v 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/persistence/types.go pkg/persistence/memory/memory.go pkg/persistence/nodestate_test.go
git commit -m "feat(persistence): persist reshare abort counter + LKG marker in NodeState"
```

---

### Task 8: Poisoned-version set persistence surface

**Files:**
- Modify: `pkg/persistence/interface.go` — add three methods
- Modify: `pkg/persistence/redis/redis.go`, `pkg/persistence/memory/memory.go`, `pkg/persistence/badger/badger.go`
- Modify: mock (`pkg/persistence/mock_INodePersistence.go` if it exists — regenerate via `mockery`)
- Test: `pkg/persistence/poisoned_test.go` (create) + per-backend tests mirroring existing ones

**Interfaces:**
- Produces (added to `INodePersistence`):
  - `AddPoisonedVersion(version int64) error`
  - `ListPoisonedVersions() ([]int64, error)`
  - (No delete needed — poisoned is permanent for the deployment; YAGNI.)

- [ ] **Step 1: Write the failing test**

Create `pkg/persistence/poisoned_test.go` — a table that runs against each backend (mirror how existing backend tests construct each store; use the in-memory store here and add redis/badger cases in their own `_test.go` files if the repo separates them):

```go
package persistence_test

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/memory"
	"github.com/stretchr/testify/require"
)

func TestPoisonedVersions_Memory(t *testing.T) {
	var p persistence.INodePersistence = memory.NewMemoryPersistence()
	require.NoError(t, p.AddPoisonedVersion(1783944564))
	require.NoError(t, p.AddPoisonedVersion(1783944564)) // idempotent
	require.NoError(t, p.AddPoisonedVersion(1783944800))
	got, err := p.ListPoisonedVersions()
	require.NoError(t, err)
	require.ElementsMatch(t, []int64{1783944564, 1783944800}, got)
}
```

(Confirm the memory constructor name via `grep -n "func NewMemoryPersistence" pkg/persistence/memory/memory.go`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./pkg/persistence/... -run TestPoisonedVersions -v`
Expected: FAIL — methods undefined / interface not satisfied.

- [ ] **Step 3: Add interface methods**

In `pkg/persistence/interface.go` (in the Key Share Management section):

```go
	// AddPoisonedVersion records a key-share version as poisoned (its shares are
	// cross-node-inconsistent and must never be dealt from, activated, or served).
	// Idempotent. Returns error only on storage failure.
	AddPoisonedVersion(version int64) error

	// ListPoisonedVersions returns all recorded poisoned versions (unordered).
	// Returns empty slice if none. Returns error only on storage failure.
	ListPoisonedVersions() ([]int64, error)
```

- [ ] **Step 4: Implement in memory backend**

In `pkg/persistence/memory/memory.go`: add a `poisoned map[int64]struct{}` field (init in `NewMemoryPersistence`), guarded by the existing mutex:

```go
func (m *MemoryPersistence) AddPoisonedVersion(version int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.poisoned == nil {
		m.poisoned = map[int64]struct{}{}
	}
	m.poisoned[version] = struct{}{}
	return nil
}

func (m *MemoryPersistence) ListPoisonedVersions() ([]int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]int64, 0, len(m.poisoned))
	for v := range m.poisoned {
		out = append(out, v)
	}
	return out, nil
}
```

- [ ] **Step 5: Implement in redis backend**

In `pkg/persistence/redis/redis.go`: add a key prefix const `keyPrefixPoisoned = "kms:poisoned"` (a Redis SET). Mirror the SADD/SMEMBERS pattern used by the key-share index set:

```go
func (r *RedisPersistence) AddPoisonedVersion(version int64) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return fmt.Errorf("persistence layer is closed")
	}
	return r.client.SAdd(context.Background(), r.prefixKey(keyPrefixPoisoned), version).Err()
}

func (r *RedisPersistence) ListPoisonedVersions() ([]int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, fmt.Errorf("persistence layer is closed")
	}
	vals, err := r.client.SMembers(context.Background(), r.prefixKey(keyPrefixPoisoned)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list poisoned versions: %w", err)
	}
	out := make([]int64, 0, len(vals))
	for _, s := range vals {
		v, perr := strconv.ParseInt(s, 10, 64)
		if perr != nil {
			r.logger.Sugar().Warnw("skipping non-integer poisoned version", "value", s)
			continue
		}
		out = append(out, v)
	}
	return out, nil
}
```

(Add `"strconv"` to imports if missing.)

- [ ] **Step 6: Implement in badger backend**

In `pkg/persistence/badger/badger.go`: store each poisoned version as its own key `poisoned:<version>` and list via prefix iteration (mirror how the badger backend iterates key-share keys). Example:

```go
const keyPrefixPoisoned = "poisoned:"

func (b *BadgerPersistence) AddPoisonedVersion(version int64) error {
	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(fmt.Sprintf("%s%d", keyPrefixPoisoned, version)), []byte{1})
	})
}

func (b *BadgerPersistence) ListPoisonedVersions() ([]int64, error) {
	var out []int64
	err := b.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(keyPrefixPoisoned)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			key := string(it.Item().Key())
			v, perr := strconv.ParseInt(key[len(keyPrefixPoisoned):], 10, 64)
			if perr != nil {
				continue
			}
			out = append(out, v)
		}
		return nil
	})
	return out, err
}
```

(Confirm the badger import alias and `b.db` field name by reading the top of `badger.go`; adjust `strconv` import.)

- [ ] **Step 7: Regenerate the persistence mock (if one exists)**

Run: `grep -rn "mock_INodePersistence\|MockINodePersistence" pkg/persistence` — if a generated mock exists (or `INodePersistence` is in `.mockery.yaml`), run `mockery` from repo root and stage the regenerated file. If only a hand-written stub is used in tests, add the two methods to it.

- [ ] **Step 8: Run tests to verify they pass**

Run: `./scripts/goTest.sh ./pkg/persistence/... -run 'TestPoisoned' -v`
Expected: PASS.
Run: `./scripts/goTest.sh ./pkg/persistence/... 2>&1 | tail -20`
Expected: PASS (all backends satisfy the interface).

- [ ] **Step 9: Commit**

```bash
git add pkg/persistence/
git commit -m "feat(persistence): add poisoned-version set (interface + redis/memory/badger + mock)"
```

---

### Task 9: Keystore poisoned-version exclusion

**Files:**
- Modify: `pkg/keystore/keystore.go` — add poisoned set + exclude in `GetActiveVersion`, `GetKeyVersionAtTime`, `GetPrivateShareForVersion`
- Test: `pkg/keystore/keystore_test.go` (extend)

**Interfaces:**
- Produces:
  - `KeyStore.MarkPoisoned(version int64)` — records a version poisoned in-keystore (mirrors the persisted set; loaded at startup).
  - `KeyStore.IsPoisoned(version int64) bool`
  - Modified readers: `GetKeyVersionAtTime` skips poisoned versions; `GetPrivateShareForVersion` errors on a poisoned version; `GetActiveVersion` returns the active version unchanged (rollback guarantees active is never poisoned — see Task 11), but add a guard test.

- [ ] **Step 1: Write the failing test**

Append to `pkg/keystore/keystore_test.go`:

```go
func TestKeyStore_ExcludesPoisonedVersion(t *testing.T) {
	ks := NewKeyStore()
	good := &types.KeyShareVersion{Version: 100, PrivateShare: fr.NewElement(1)}
	poison := &types.KeyShareVersion{Version: 200, PrivateShare: fr.NewElement(2)}
	ks.AddVersion(good)
	ks.AddVersion(poison)
	ks.MarkPoisoned(200)

	// GetKeyVersionAtTime(250) must skip 200 and return 100.
	if got := ks.GetKeyVersionAtTime(250); got == nil || got.Version != 100 {
		t.Fatalf("expected version 100 (skipping poisoned 200), got %+v", got)
	}
	// GetPrivateShareForVersion(200) must error.
	if _, err := ks.GetPrivateShareForVersion(200); err == nil {
		t.Fatal("expected error fetching share for poisoned version 200")
	}
	// IsPoisoned reflects state.
	if !ks.IsPoisoned(200) || ks.IsPoisoned(100) {
		t.Fatal("IsPoisoned wrong")
	}
}
```

(Confirm `fr.NewElement` construction matches existing keystore tests; if they use `new(fr.Element).SetUint64(1)`, use that form instead.)

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./pkg/keystore -run TestKeyStore_ExcludesPoisonedVersion -v`
Expected: FAIL — `MarkPoisoned` / `IsPoisoned` undefined; poisoned version still returned.

- [ ] **Step 3: Implement exclusion**

In `pkg/keystore/keystore.go`, add a field to `KeyStore` (line 12-18):

```go
	poisoned map[int64]struct{}
```

Add methods:

```go
// MarkPoisoned records a version as poisoned; poisoned versions are excluded
// from all version-resolution accessors.
func (ks *KeyStore) MarkPoisoned(version int64) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.poisoned == nil {
		ks.poisoned = map[int64]struct{}{}
	}
	ks.poisoned[version] = struct{}{}
}

// IsPoisoned reports whether a version has been marked poisoned.
func (ks *KeyStore) IsPoisoned(version int64) bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	_, ok := ks.poisoned[version]
	return ok
}
```

In `GetKeyVersionAtTime` (line 145 loop), skip poisoned:

```go
	for _, version := range ks.keyVersions {
		if _, bad := ks.poisoned[version.Version]; bad {
			continue
		}
		if version.Version <= timestamp {
			if best == nil || version.Version > best.Version {
				best = version
			}
		}
	}
```

In `GetPrivateShareForVersion` (line 127 loop), reject poisoned before returning:

```go
	if _, bad := ks.poisoned[version]; bad {
		return nil, fmt.Errorf("key version %d is poisoned and must not be used", version)
	}
	for _, v := range ks.keyVersions {
		...
	}
```

(Both hold `ks.mu.RLock()` already; reading `ks.poisoned` under the same lock is safe.)

- [ ] **Step 4: Run test to verify it passes**

Run: `./scripts/goTest.sh ./pkg/keystore -run TestKeyStore_ExcludesPoisonedVersion -v`
Expected: PASS.

- [ ] **Step 5: Run full keystore suite (regression)**

Run: `./scripts/goTest.sh ./pkg/keystore -v 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/keystore/keystore.go pkg/keystore/keystore_test.go
git commit -m "feat(keystore): exclude poisoned versions from version-resolution accessors"
```

---

### Task 10: Auto-heal state manager (pure logic)

**Files:**
- Create: `pkg/node/autoheal.go`
- Test: `pkg/node/autoheal_test.go`

**Interfaces:**
- Produces a pure, testable decision unit (no I/O), so the increment/gating/demotion logic is unit-tested independent of the node's chain wiring:
  - `type abortTracker struct { TrackedSourceVersion int64; ConsecutiveAborts int }`
  - `func (t *abortTracker) recordMPKAbort(activeSourceVersion, majoritySrcVersion int64, threshold int) (demote bool)` — implements the majority-gated increment: increments only when `majoritySrcVersion == activeSourceVersion`; resets and re-tracks when `activeSourceVersion` changed; returns `demote=true` when the count reaches `demotionThreshold`.
  - `func (t *abortTracker) recordSuccess()` — resets the counter (called on a persisted round).
  - `const demotionThreshold = 3`
  - `func rollbackTarget(lkg int64, poisonedVersion int64, persistedVersions []int64, isPoisoned func(int64) bool) (int64, bool)` — returns the LKG if usable (`>0 && < poisonedVersion && !isPoisoned(lkg)`), else the highest persisted version `< poisonedVersion` that is not poisoned; `ok=false` if none (floor).

- [ ] **Step 1: Write the failing test**

Create `pkg/node/autoheal_test.go`:

```go
package node

import "testing"

func TestAbortTracker_MajorityGatedIncrement(t *testing.T) {
	tr := &abortTracker{}

	// Majority attempting our active version V=100 -> increments.
	for i := 1; i <= 2; i++ {
		if demote := tr.recordMPKAbort(100, 100, 2); demote {
			t.Fatalf("premature demote at count %d", i)
		}
	}
	// Third consecutive on same version -> demote.
	if demote := tr.recordMPKAbort(100, 100, 2); !demote {
		t.Fatal("expected demote at 3 consecutive aborts")
	}
}

func TestAbortTracker_DoesNotCountWhenMajorityOnDifferentVersion(t *testing.T) {
	tr := &abortTracker{}
	// We rolled back to 90, but the majority is still attempting 100.
	// Our active (90) != majority (100) -> do NOT count (don't blame good 90).
	for i := 0; i < 10; i++ {
		if demote := tr.recordMPKAbort(90, 100, 2); demote {
			t.Fatal("must not demote our version when majority is on a different version")
		}
	}
	if tr.ConsecutiveAborts != 0 {
		t.Fatalf("expected 0 aborts counted, got %d", tr.ConsecutiveAborts)
	}
}

func TestAbortTracker_ResetsOnActiveVersionChange(t *testing.T) {
	tr := &abortTracker{}
	tr.recordMPKAbort(100, 100, 2) // count=1 on v100
	tr.recordMPKAbort(90, 90, 2)   // active changed -> reset, count=1 on v90
	if tr.TrackedSourceVersion != 90 || tr.ConsecutiveAborts != 1 {
		t.Fatalf("expected tracked=90 count=1, got tracked=%d count=%d", tr.TrackedSourceVersion, tr.ConsecutiveAborts)
	}
}

func TestAbortTracker_ResetOnSuccess(t *testing.T) {
	tr := &abortTracker{}
	tr.recordMPKAbort(100, 100, 2)
	tr.recordSuccess()
	if tr.ConsecutiveAborts != 0 {
		t.Fatalf("expected reset, got %d", tr.ConsecutiveAborts)
	}
}

func TestRollbackTarget(t *testing.T) {
	never := func(int64) bool { return false }
	// Prefer LKG when usable.
	if got, ok := rollbackTarget(90, 100, []int64{80, 90, 100}, never); !ok || got != 90 {
		t.Fatalf("expected LKG 90, got %d ok=%v", got, ok)
	}
	// No LKG -> highest persisted below poison.
	if got, ok := rollbackTarget(0, 100, []int64{70, 80, 100}, never); !ok || got != 80 {
		t.Fatalf("expected walk-back 80, got %d ok=%v", got, ok)
	}
	// Skip a poisoned candidate.
	poisoned := map[int64]bool{80: true}
	if got, ok := rollbackTarget(0, 100, []int64{70, 80, 100}, func(v int64) bool { return poisoned[v] }); !ok || got != 70 {
		t.Fatalf("expected 70 (skip poisoned 80), got %d ok=%v", got, ok)
	}
	// Floor: nothing below poison.
	if _, ok := rollbackTarget(0, 100, []int64{100, 110}, never); ok {
		t.Fatal("expected floor (no target)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./pkg/node -run 'TestAbortTracker|TestRollbackTarget' -v`
Expected: FAIL — undefined types/functions.

- [ ] **Step 3: Implement `autoheal.go`**

Create `pkg/node/autoheal.go`:

```go
package node

import "sort"

// demotionThreshold is the number of consecutive MPK-validation aborts on the
// same active source version after which that version is declared poisoned.
const demotionThreshold = 3

// abortTracker counts consecutive Layer-1 MPK-validation aborts on the same
// active source version, majority-gated so an early roller does not over-walk.
type abortTracker struct {
	TrackedSourceVersion int64
	ConsecutiveAborts    int
}

// recordMPKAbort applies the majority-gated increment. It returns demote=true
// when the counter reaches demotionThreshold on the active source version.
//
//   - If the active source version changed since we last tracked, reset and
//     start counting the new version (preserves "resets on active-version change").
//   - Only increment when the round's agreed majority source version equals our
//     active source version — i.e. the cluster is actually attempting OUR version.
//     A node that has already rolled back to a lower version does not count aborts
//     that the majority incurs on the still-poisoned higher version.
func (t *abortTracker) recordMPKAbort(activeSourceVersion, majoritySrcVersion int64, threshold int) bool {
	if t.TrackedSourceVersion != activeSourceVersion {
		t.TrackedSourceVersion = activeSourceVersion
		t.ConsecutiveAborts = 0
	}
	if majoritySrcVersion != activeSourceVersion {
		return false
	}
	t.ConsecutiveAborts++
	return t.ConsecutiveAborts >= demotionThreshold
}

// recordSuccess resets the counter after a round that passed MPK validation.
func (t *abortTracker) recordSuccess() {
	t.ConsecutiveAborts = 0
}

// rollbackTarget picks the demotion rollback target. Prefers the last-known-good
// source version when it is usable (present, below the poisoned version, not
// itself poisoned); otherwise the highest persisted version strictly below the
// poisoned one that is not poisoned. Returns ok=false when none exists (floor).
func rollbackTarget(lkg int64, poisonedVersion int64, persistedVersions []int64, isPoisoned func(int64) bool) (int64, bool) {
	if lkg > 0 && lkg < poisonedVersion && !isPoisoned(lkg) {
		return lkg, true
	}
	sorted := append([]int64(nil), persistedVersions...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] > sorted[j] }) // descending
	for _, v := range sorted {
		if v < poisonedVersion && !isPoisoned(v) {
			return v, true
		}
	}
	return 0, false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./scripts/goTest.sh ./pkg/node -run 'TestAbortTracker|TestRollbackTarget' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/node/autoheal.go pkg/node/autoheal_test.go
git commit -m "feat(node): auto-heal decision logic (majority-gated counter + rollback target)"
```

---

### Task 11: Wire auto-heal into the reshare finalize abort path

**Files:**
- Modify: `pkg/node/node.go` — add an `abortTracker` field to `Node`; at the MPK-abort site (2423-2430) call `recordMPKAbort`, persist, and on demote perform rollback; on successful persist call `recordSuccess` + record LKG.
- Test: `pkg/node/autoheal_integration_test.go` (create) using the node-level `makeNodeWithKeyVersion` helper style from `reshare_validation_test.go`

**Interfaces:**
- Consumes: `abortTracker` (Task 10); `rollbackTarget` (Task 10); persistence fields (Task 7/8); keystore `MarkPoisoned`/`SetActiveVersion` (Task 9); `srcVersion` from `SelectMajoritySourceVersion` (node.go:2319).
- Produces: `Node.abortTracker *abortTracker` field; unexported `func (n *Node) onMPKValidationAbort(activeSourceVersion, majoritySrcVersion int64, threshold int)` and `func (n *Node) performRollback(poisonedVersion int64)`.

- [ ] **Step 1: Write the failing test**

Create `pkg/node/autoheal_integration_test.go`. Build a node with several persisted versions, drive three MPK-abort signals on the same active version with `majority==active`, and assert: the poisoned version is marked, the active version is rolled back to LKG, and NodeState persisted the demotion. Mirror `makeNodeWithKeyVersion` from `reshare_validation_test.go`:

```go
package node

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/keystore"
	"go.uber.org/zap"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/memory"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

func TestAutoHeal_DemotesAndRollsBackToLKG(t *testing.T) {
	l, _ := zap.NewDevelopment()
	ks := keystore.NewKeyStore()
	good := &types.KeyShareVersion{Version: 1783944444, PrivateShare: new(fr.Element).SetUint64(1), MasterPublicKey: nil}
	poison := &types.KeyShareVersion{Version: 1783944564, PrivateShare: new(fr.Element).SetUint64(2)}
	ks.AddVersion(good)
	ks.AddVersion(poison)
	ks.SetActiveVersion(poison)

	p := memory.NewMemoryPersistence()
	n := &Node{
		logger:       l,
		keyStore:     ks,
		persistence:  p,
		abortTracker: &abortTracker{},
	}
	// LKG points at the good version (as recorded by the last successful round).
	_ = n.persistence.SaveNodeState(&persistenceNodeStateWithLKG(1783944444)) // helper or inline struct

	const active = int64(1783944564)
	const majority = int64(1783944564)
	for i := 0; i < demotionThreshold; i++ {
		n.onMPKValidationAbort(active, majority, 2)
	}

	require.True(t, ks.IsPoisoned(1783944564), "poisoned version must be marked")
	require.Equal(t, int64(1783944444), ks.GetActiveVersion().Version, "active must roll back to LKG")
	poisoned, _ := p.ListPoisonedVersions()
	require.Contains(t, poisoned, int64(1783944564))
}
```

(Replace `persistenceNodeStateWithLKG` with an inline `persistence.NodeState{LastKnownGoodSourceVersion: 1783944444, OperatorAddress: n.OperatorAddress.Hex()}` — adjust to the real constructor. If `Node` requires more fields to be non-nil for these methods, set them minimally as `reshare_validation_test.go` does.)

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./pkg/node -run TestAutoHeal_DemotesAndRollsBackToLKG -v`
Expected: FAIL — `onMPKValidationAbort` undefined / `abortTracker` field missing.

- [ ] **Step 3: Add the field and methods**

In `pkg/node/node.go`, add to `Node` struct (near `persistence`, line 68):
```go
	abortTracker *abortTracker
```
Initialize in the constructor (near line 510-513): `abortTracker: &abortTracker{},`.

Add the methods:

```go
// onMPKValidationAbort records a Layer-1 MPK-validation abort against the active
// source version (majority-gated) and, on reaching the demotion threshold,
// demotes the active version and rolls back. Persists the counter each call.
func (n *Node) onMPKValidationAbort(activeSourceVersion, majoritySrcVersion int64, threshold int) {
	demote := n.abortTracker.recordMPKAbort(activeSourceVersion, majoritySrcVersion, threshold)
	n.persistAbortTracker()
	if !demote {
		return
	}
	n.logger.Sugar().Warnw("Auto-heal: demoting poisoned source version after consecutive MPK aborts",
		"operator_address", n.OperatorAddress.Hex(),
		"poisoned_version", activeSourceVersion, "consecutive_aborts", n.abortTracker.ConsecutiveAborts)
	n.performRollback(activeSourceVersion)
}

// performRollback marks poisonedVersion poisoned (keystore + persistence) and
// re-points the active version to the rollback target (LKG or walk-back). If no
// target exists, halts rotation with a loud alert (never auto-re-DKG).
func (n *Node) performRollback(poisonedVersion int64) {
	n.keyStore.MarkPoisoned(poisonedVersion)
	if err := n.persistence.AddPoisonedVersion(poisonedVersion); err != nil {
		n.logger.Sugar().Errorw("Auto-heal: failed to persist poisoned version", "version", poisonedVersion, "error", err)
	}

	lkg := int64(0)
	if st, err := n.persistence.LoadNodeState(); err == nil && st != nil {
		lkg = st.LastKnownGoodSourceVersion
	}
	versions, _ := n.persistence.ListKeyShareVersions()
	nums := make([]int64, 0, len(versions))
	for _, v := range versions {
		nums = append(nums, v.Version)
	}
	target, ok := rollbackTarget(lkg, poisonedVersion, nums, n.keyStore.IsPoisoned)
	if !ok {
		n.logger.Sugar().Errorw("AUTO-HEAL FLOOR: no non-poisoned version below the poisoned one; rotation halted, decrypt still served. MANUAL INTERVENTION REQUIRED (no auto re-DKG).",
			"operator_address", n.OperatorAddress.Hex(), "poisoned_version", poisonedVersion)
		return
	}
	for _, v := range versions {
		if v.Version == target {
			n.keyStore.SetActiveVersion(v)
			if err := n.persistence.SetActiveVersionTimestamp(target); err != nil {
				n.logger.Sugar().Errorw("Auto-heal: failed to persist rolled-back active version", "target", target, "error", err)
			}
			// Reset the tracker to the new active version.
			n.abortTracker.TrackedSourceVersion = target
			n.abortTracker.ConsecutiveAborts = 0
			n.persistAbortTracker()
			n.logger.Sugar().Infow("Auto-heal: rolled active version back to recover rotation",
				"operator_address", n.OperatorAddress.Hex(), "from", poisonedVersion, "to", target)
			return
		}
	}
}

// persistAbortTracker writes the current tracker into NodeState (merging with
// the existing persisted state so other fields are preserved).
func (n *Node) persistAbortTracker() {
	st, err := n.persistence.LoadNodeState()
	if err != nil || st == nil {
		st = &persistence.NodeState{OperatorAddress: n.OperatorAddress.Hex()}
	}
	st.TrackedSourceVersion = n.abortTracker.TrackedSourceVersion
	st.ConsecutiveMPKAborts = n.abortTracker.ConsecutiveAborts
	if err := n.persistence.SaveNodeState(st); err != nil {
		n.logger.Sugar().Errorw("Auto-heal: failed to persist abort tracker", "error", err)
	}
}

// recordSuccessfulReshare resets the abort counter and records the agreed source
// version as last-known-good after a round that passed MPK validation.
func (n *Node) recordSuccessfulReshare(agreedSrcVersion int64) {
	n.abortTracker.recordSuccess()
	st, err := n.persistence.LoadNodeState()
	if err != nil || st == nil {
		st = &persistence.NodeState{OperatorAddress: n.OperatorAddress.Hex()}
	}
	st.ConsecutiveMPKAborts = 0
	if agreedSrcVersion > 0 {
		st.LastKnownGoodSourceVersion = agreedSrcVersion
	}
	if err := n.persistence.SaveNodeState(st); err != nil {
		n.logger.Sugar().Errorw("Auto-heal: failed to persist LKG marker", "error", err)
	}
}
```

- [ ] **Step 4: Hook the calls into the finalize path**

At the MPK-abort site (`node.go:2423-2430`), inside the `if verr != nil` block, after the existing `Errorw` log and before `return`, add:
```go
			n.onMPKValidationAbort(srcVersion, srcVersion, newThreshold)
```
(Here the node's active source version == `srcVersion` for this path — the round dealt from the agreed majority version. `srcVersion` and `newThreshold` are in scope from lines 2319/1890.)

At the successful-persist site (after `SaveKeyShareVersion` succeeds and `SetActiveVersionTimestamp` is set, around `node.go:2435-2443`), add:
```go
			n.recordSuccessfulReshare(srcVersion)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `./scripts/goTest.sh ./pkg/node -run TestAutoHeal_DemotesAndRollsBackToLKG -v`
Expected: PASS. Adjust the inline NodeState construction in the test to match the real `persistence.NodeState` fields if the compiler complains.

- [ ] **Step 6: Add the staggered-rollback / floor tests**

Append to `pkg/node/autoheal_integration_test.go`:

```go
func TestAutoHeal_MinorityDoesNotOverWalk(t *testing.T) {
	// A node already on V-1 while majority is on poisoned V must not demote V-1.
	l, _ := zap.NewDevelopment()
	ks := keystore.NewKeyStore()
	vMinus1 := &types.KeyShareVersion{Version: 1783944444, PrivateShare: new(fr.Element).SetUint64(1)}
	ks.AddVersion(vMinus1)
	ks.SetActiveVersion(vMinus1)
	n := &Node{logger: l, keyStore: ks, persistence: memory.NewMemoryPersistence(), abortTracker: &abortTracker{}}

	for i := 0; i < 10; i++ {
		n.onMPKValidationAbort(1783944444, 1783944564, 2) // active=V-1, majority=V
	}
	require.False(t, ks.IsPoisoned(1783944444), "must not poison the good version we already rolled to")
	require.Equal(t, int64(1783944444), ks.GetActiveVersion().Version)
}

func TestAutoHeal_FloorHaltsWithoutReDKG(t *testing.T) {
	l, _ := zap.NewDevelopment()
	ks := keystore.NewKeyStore()
	only := &types.KeyShareVersion{Version: 100, PrivateShare: new(fr.Element).SetUint64(1)}
	ks.AddVersion(only)
	ks.SetActiveVersion(only)
	n := &Node{logger: l, keyStore: ks, persistence: memory.NewMemoryPersistence(), abortTracker: &abortTracker{}}
	for i := 0; i < demotionThreshold; i++ {
		n.onMPKValidationAbort(100, 100, 2)
	}
	// Poisoned, no lower version -> floor: active stays (still poisoned), no panic, no new version.
	require.True(t, ks.IsPoisoned(100))
}
```

Run: `./scripts/goTest.sh ./pkg/node -run TestAutoHeal -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/node/node.go pkg/node/autoheal_integration_test.go
git commit -m "feat(node): wire auto-heal demotion/rollback into reshare finalize abort path"
```

---

### Task 12: Restore auto-heal state on startup

**Files:**
- Modify: `pkg/node/node.go` — `RestoreState` (854-919): load poisoned set into keystore and load the persisted abort tracker with the version-match guard.
- Test: `pkg/node/autoheal_integration_test.go` (extend)

**Interfaces:**
- Consumes: `persistence.ListPoisonedVersions`, `keystore.MarkPoisoned`, `NodeState.{TrackedSourceVersion,ConsecutiveMPKAborts}`, `abortTracker`.

- [ ] **Step 1: Write the failing test**

Append to `pkg/node/autoheal_integration_test.go`:

```go
func TestRestoreState_HonorsAbortCounterOnlyIfVersionMatches(t *testing.T) {
	l, _ := zap.NewDevelopment()
	p := memory.NewMemoryPersistence()
	// Persist a tracker on version 500 with 2 aborts, and mark 999 poisoned.
	require.NoError(t, p.SaveNodeState(&persistence.NodeState{
		OperatorAddress:      "0x0",
		TrackedSourceVersion: 500,
		ConsecutiveMPKAborts: 2,
	}))
	require.NoError(t, p.AddPoisonedVersion(999))

	// Case A: active version matches tracked (500) -> counter honored.
	ksA := keystore.NewKeyStore()
	vA := &types.KeyShareVersion{Version: 500, PrivateShare: new(fr.Element).SetUint64(1)}
	ksA.AddVersion(vA)
	nA := newTestNodeForRestore(t, l, ksA, p, 500) // helper sets GetActiveVersionTimestamp=500
	require.NoError(t, nA.RestoreState())
	require.Equal(t, 2, nA.abortTracker.ConsecutiveAborts)
	require.True(t, ksA.IsPoisoned(999))

	// Case B: active version differs (600) -> counter reset to 0.
	// (Rebuild persistence view or use a fresh store with active=600.)
	// ... assert nB.abortTracker.ConsecutiveAborts == 0
}
```

(Implement `newTestNodeForRestore` to set the memory store's active-version timestamp — use `p.SetActiveVersionTimestamp(500)` and add the version to the keystore/persistence so `RestoreState` finds it. Keep Case B minimal.)

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./pkg/node -run TestRestoreState_HonorsAbortCounter -v`
Expected: FAIL — RestoreState doesn't load poisoned set / tracker yet.

- [ ] **Step 3: Extend `RestoreState`**

In `pkg/node/node.go`, after step 3 (active-version restore, ~line 919) add:

```go
	// 3b. Restore poisoned-version set into the keystore.
	if poisoned, perr := n.persistence.ListPoisonedVersions(); perr == nil {
		for _, v := range poisoned {
			n.keyStore.MarkPoisoned(v)
		}
		if len(poisoned) > 0 {
			n.logger.Sugar().Infow("Restored poisoned key versions",
				"operator_address", n.OperatorAddress.Hex(), "count", len(poisoned))
		}
	} else {
		n.logger.Sugar().Errorw("Failed to load poisoned versions", "error", perr)
	}

	// 3c. Restore the MPK-abort tracker, but only trust the count if it still
	// refers to the current active source version (else reset — the version
	// changed while we were down, so a stale count must not carry over).
	if nodeState != nil && n.abortTracker != nil {
		active := n.keyStore.GetActiveVersion()
		if active != nil && nodeState.TrackedSourceVersion == active.Version {
			n.abortTracker.TrackedSourceVersion = nodeState.TrackedSourceVersion
			n.abortTracker.ConsecutiveAborts = nodeState.ConsecutiveMPKAborts
		} else {
			n.abortTracker.TrackedSourceVersion = 0
			n.abortTracker.ConsecutiveAborts = 0
		}
	}
```

(If `n.abortTracker` is nil in some construction paths, guard by initializing it at the top of `RestoreState`: `if n.abortTracker == nil { n.abortTracker = &abortTracker{} }`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `./scripts/goTest.sh ./pkg/node -run TestRestoreState_HonorsAbortCounter -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/node/node.go pkg/node/autoheal_integration_test.go
git commit -m "feat(node): restore poisoned set + abort counter on startup with version guard"
```

---

### Task 13: Full regression + observability sweep

**Files:**
- Modify: `pkg/node/node.go` — confirm observability log lines exist at each auto-heal transition (demote / rollback-target / heal / floor) — most added in Task 11; add any missing.
- Test: run the entire suite.

- [ ] **Step 1: Confirm observability lines**

Grep for the four transition logs and confirm each is present and greppable:
```bash
grep -n "Auto-heal: demoting\|Auto-heal: rolled active\|AUTO-HEAL FLOOR\|Derived agreed dealer set at pinned" pkg/node/node.go
```
Expected: all four present. Add a "heal confirmed" info log in the successful-persist path if not already distinct: in `recordSuccessfulReshare`, when the prior state had `ConsecutiveMPKAborts > 0`, log `"Auto-heal: rotation resumed (reshare validated after prior aborts)"`.

- [ ] **Step 2: Run the entire test suite**

Run: `./scripts/goTest.sh ./... 2>&1 | tail -40`
Expected: PASS. Pay special attention to:
- `./pkg/reshare/...` (source-version + validation tests unchanged)
- `./pkg/node/...` (new auto-heal + cutoff tests)
- `./internal/tests/integration -run Reshare` (cluster still reshares; `Test_Reshare_SucceedsWithExactlyThresholdAcks` still passes)

- [ ] **Step 3: Fix any regressions**

If the integration cluster fails because its mock callers don't implement `HeaderTimestampAt`/`FirstBlockAtOrAfterTimestamp` sensibly, wire the `testutil` cluster's contract-caller stub to return a deterministic cutoff (e.g. `FirstBlockAtOrAfterTimestampFunc` returns a fixed height and `GetCommitmentAt` ignores the height in the cluster's in-memory registry). Locate: `grep -rn "MockContractCallerStub\|NewTestCluster" pkg/testutil internal/tests`.

- [ ] **Step 4: Run lint + fmt**

Run: `make fmt && make lint 2>&1 | tail -30`
Expected: clean (or only pre-existing warnings unrelated to these files).

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "test(node): full regression + auto-heal observability sweep"
```

---

## Self-Review Notes (coverage map)

- Spec Part 1 "L1 deadline block / block-gate / cutoff mapping" → Tasks 1, 2, 4, 5.
- Spec Part 1 "retry-until-readable, abort-whole-round, never per-dealer continue" → Task 5.
- Spec Part 1 "new-operator parity (trigger block)" → Task 6.
- Spec Part 2 "persisted abort counter {trackedSourceVersion, consecutiveAborts}" → Tasks 7, 11, 12.
- Spec Part 2 "majority-gated increment" → Task 10 (`recordMPKAbort`), Task 11 (wiring).
- Spec Part 2 "LKG = agreed srcVersion" → Tasks 7, 11 (`recordSuccessfulReshare`).
- Spec Part 2 "rollback: LKG then walk-back, skip poisoned, floor" → Task 10 (`rollbackTarget`), Task 11 (`performRollback`).
- Spec Part 2 "poisoned exclusion across GetActiveVersion/GetKeyVersionAtTime/GetPrivateShareForVersion" → Task 9.
- Spec Part 2 "persist poisoned set across restart" → Tasks 8, 12.
- Spec Part 2 "floor halt + alert, no auto-re-DKG" → Task 11 (`performRollback` floor branch), Task 13 (log).
- Spec "observability" → Task 13.

**Deferred (explicitly out of this plan, per spec non-goals):** on-chain agreement of the rollback target (walk-back relies on matching persisted histories); subset-liveness when an operator is genuinely down.
