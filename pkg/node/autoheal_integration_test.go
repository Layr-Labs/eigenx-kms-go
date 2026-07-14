package node

import (
	"errors"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/keystore"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/memory"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// listErrPersistence wraps the in-memory backend but forces ListKeyShareVersions
// to fail, so tests can exercise performRollback's list-error handling with a
// real error (not just by inspection). All other calls delegate to the embedded
// MemoryPersistence.
type listErrPersistence struct {
	*memory.MemoryPersistence
	listErr error
}

func (p *listErrPersistence) ListKeyShareVersions() ([]*types.KeyShareVersion, error) {
	return nil, p.listErr
}

func TestAutoHeal_DemotesAndRollsBackToLKG(t *testing.T) {
	l, _ := zap.NewDevelopment()
	ks := keystore.NewKeyStore()
	good := &types.KeyShareVersion{Version: 1783944444, PrivateShare: new(fr.Element).SetInt64(1), MasterPublicKey: nil}
	poison := &types.KeyShareVersion{Version: 1783944564, PrivateShare: new(fr.Element).SetInt64(2)}
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
	// performRollback re-points the active version to a *KeyShareVersion object it
	// finds via ListKeyShareVersions, so the rollback target must be persisted.
	require.NoError(t, p.SaveKeyShareVersion(good))
	require.NoError(t, p.SaveKeyShareVersion(poison))
	// LKG points at the good version (as recorded by the last successful round).
	require.NoError(t, p.SaveNodeState(&persistence.NodeState{
		LastKnownGoodSourceVersion: 1783944444,
		OperatorAddress:            n.OperatorAddress.Hex(),
	}))

	const active = int64(1783944564)
	const majority = int64(1783944564)
	for i := 0; i < demotionThreshold; i++ {
		n.onMPKValidationAbort(active, majority)
	}

	require.True(t, ks.IsPoisoned(1783944564), "poisoned version must be marked")
	require.Equal(t, int64(1783944444), ks.GetActiveVersion().Version, "active must roll back to LKG")
	poisoned, _ := p.ListPoisonedVersions()
	require.Contains(t, poisoned, int64(1783944564))
}

func TestAutoHeal_MinorityDoesNotOverWalk(t *testing.T) {
	// A node already on V-1 while majority is on poisoned V must not demote V-1.
	l, _ := zap.NewDevelopment()
	ks := keystore.NewKeyStore()
	vMinus1 := &types.KeyShareVersion{Version: 1783944444, PrivateShare: new(fr.Element).SetInt64(1)}
	ks.AddVersion(vMinus1)
	ks.SetActiveVersion(vMinus1)
	n := &Node{logger: l, keyStore: ks, persistence: memory.NewMemoryPersistence(), abortTracker: &abortTracker{}}

	for i := 0; i < 10; i++ {
		n.onMPKValidationAbort(1783944444, 1783944564) // active=V-1, majority=V
	}
	require.False(t, ks.IsPoisoned(1783944444), "must not poison the good version we already rolled to")
	require.Equal(t, int64(1783944444), ks.GetActiveVersion().Version)
}

func TestAutoHeal_FloorHaltsWithoutReDKG(t *testing.T) {
	l, _ := zap.NewDevelopment()
	ks := keystore.NewKeyStore()
	only := &types.KeyShareVersion{Version: 100, PrivateShare: new(fr.Element).SetInt64(1)}
	ks.AddVersion(only)
	ks.SetActiveVersion(only)
	n := &Node{logger: l, keyStore: ks, persistence: memory.NewMemoryPersistence(), abortTracker: &abortTracker{}}
	for i := 0; i < demotionThreshold; i++ {
		n.onMPKValidationAbort(100, 100)
	}
	// Poisoned, no lower version -> floor: active stays (still poisoned), no panic, no new version.
	require.True(t, ks.IsPoisoned(100))
	// Halt is guaranteed, not just structural: the active version is unchanged
	// (no rollback target existed) and no new version was created (no re-DKG).
	require.Equal(t, int64(100), ks.GetActiveVersion().Version, "active must not change when rotation halts at the floor")
}

func TestAutoHeal_MissingRollbackTargetHaltsLoudly(t *testing.T) {
	// Defense-in-depth: rollbackTarget picks LKG (below the poisoned version and
	// not poisoned) but that LKG version is NOT in the persisted set, so the
	// apply-loop finds no matching object. This must halt loudly, leave the
	// active version poisoned/unchanged, and not silently no-op.
	core, observed := observer.New(zap.ErrorLevel)
	l := zap.New(core)
	ks := keystore.NewKeyStore()
	poison := &types.KeyShareVersion{Version: 200, PrivateShare: new(fr.Element).SetInt64(2)}
	ks.AddVersion(poison)
	ks.SetActiveVersion(poison)

	p := memory.NewMemoryPersistence()
	n := &Node{logger: l, keyStore: ks, persistence: p, abortTracker: &abortTracker{}}
	// Persist ONLY the poisoned version; the LKG (100) is deliberately absent
	// from the persisted key-share set.
	require.NoError(t, p.SaveKeyShareVersion(poison))
	require.NoError(t, p.SaveNodeState(&persistence.NodeState{
		LastKnownGoodSourceVersion: 100,
		OperatorAddress:            n.OperatorAddress.Hex(),
	}))

	for i := 0; i < demotionThreshold; i++ {
		n.onMPKValidationAbort(200, 200)
	}

	require.True(t, ks.IsPoisoned(200), "poisoned version must be marked")
	require.Equal(t, int64(200), ks.GetActiveVersion().Version, "active must not move when the rollback target is absent")

	entries := observed.FilterMessageSnippet("AUTO-HEAL FLOOR").All()
	require.NotEmpty(t, entries, "must emit a loud AUTO-HEAL FLOOR error when the rollback target is absent")
	require.Equal(t, int64(100), entries[len(entries)-1].ContextMap()["target"], "log must name the missing target")
}

// TestAutoHeal_ListVersionsErrorLogsAndFloors is a regression test for
// performRollback mishandling a ListKeyShareVersions failure. It exercises the
// NEW combination the round-2 fix targets: a usable last-known-good version is
// recorded (LKG > 0) AND the version listing errors out. Before the fix, the
// code logged the storage error but continued with an empty slice; rollbackTarget
// then returned the LKG, the apply-loop found no matching object, and the node
// emitted the MISLEADING "chosen rollback target not present" floor log — blaming
// a missing target when the real cause was the storage error.
//
// After the fix, performRollback floors immediately on the list error with a
// single, clear storage-error floor log (naming the underlying error) and does
// NOT reach the "target not present" branch. The active version must stay put
// (rotation halted, decrypt still served, no auto re-DKG). Uses listErrPersistence
// to force a REAL error, not an assert-by-inspection.
func TestAutoHeal_ListVersionsErrorLogsAndFloors(t *testing.T) {
	core, observed := observer.New(zap.ErrorLevel)
	l := zap.New(core)
	ks := keystore.NewKeyStore()
	poison := &types.KeyShareVersion{Version: 300, PrivateShare: new(fr.Element).SetInt64(3)}
	ks.AddVersion(poison)
	ks.SetActiveVersion(poison)

	p := &listErrPersistence{
		MemoryPersistence: memory.NewMemoryPersistence(),
		listErr:           errors.New("boom: storage unavailable"),
	}
	require.NoError(t, p.SaveKeyShareVersion(poison))
	n := &Node{logger: l, keyStore: ks, persistence: p, abortTracker: &abortTracker{}}
	// A usable LKG (< poisoned, not poisoned) IS recorded. rollbackTarget would
	// happily return it — but the list error must floor us BEFORE that, otherwise
	// the misleading "target not present" branch fires instead.
	require.NoError(t, p.SaveNodeState(&persistence.NodeState{
		LastKnownGoodSourceVersion: 250,
		OperatorAddress:            n.OperatorAddress.Hex(),
	}))

	for i := 0; i < demotionThreshold; i++ {
		n.onMPKValidationAbort(300, 300)
	}

	// Poisoned and floored: active unchanged, no re-DKG.
	require.True(t, ks.IsPoisoned(300), "poisoned version must be marked")
	require.Equal(t, int64(300), ks.GetActiveVersion().Version, "active must not move when the version list is unreadable")

	// Exactly one, clear floor log: the storage-error floor, naming the underlying
	// error — NOT the misleading "target not present" floor.
	listErrFloor := observed.FilterMessageSnippet("could not list persisted versions").All()
	require.NotEmpty(t, listErrFloor, "must floor with the storage-error message when the version list is unreadable")
	require.Equal(t, "boom: storage unavailable", listErrFloor[len(listErrFloor)-1].ContextMap()["error"], "floor log must carry the underlying error")
	require.Empty(t, observed.FilterMessageSnippet("chosen rollback target not present").All(),
		"must NOT emit the misleading target-not-present floor when the real cause is the storage error")
}

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
	vA := &types.KeyShareVersion{Version: 500, PrivateShare: new(fr.Element).SetInt64(1)}
	ksA.AddVersion(vA)
	require.NoError(t, p.SetActiveVersionTimestamp(500))
	require.NoError(t, p.SaveKeyShareVersion(vA))
	nA := &Node{logger: l, keyStore: ksA, persistence: p, abortTracker: &abortTracker{}, OperatorAddress: common.HexToAddress("0x0")}
	require.NoError(t, nA.RestoreState())
	require.Equal(t, 2, nA.abortTracker.ConsecutiveAborts, "counter honored when tracked version == active")
	require.Equal(t, int64(500), nA.abortTracker.TrackedSourceVersion)
	require.True(t, ksA.IsPoisoned(999))

	// Case B: active version differs (600) from the tracked 500 -> counter reset to 0.
	p2 := memory.NewMemoryPersistence()
	require.NoError(t, p2.SaveNodeState(&persistence.NodeState{
		OperatorAddress:      "0x0",
		TrackedSourceVersion: 500, // stale: tracker was on 500...
		ConsecutiveMPKAborts: 2,
	}))
	ksB := keystore.NewKeyStore()
	vB := &types.KeyShareVersion{Version: 600, PrivateShare: new(fr.Element).SetInt64(1)} // ...but active is now 600
	ksB.AddVersion(vB)
	require.NoError(t, p2.SaveKeyShareVersion(vB))
	require.NoError(t, p2.SetActiveVersionTimestamp(600))
	nB := &Node{logger: l, keyStore: ksB, persistence: p2, abortTracker: &abortTracker{}, OperatorAddress: common.HexToAddress("0x0")}
	require.NoError(t, nB.RestoreState())
	require.Equal(t, 0, nB.abortTracker.ConsecutiveAborts, "counter reset when tracked version != active")
}

// TestBoundaryPersistPreservesAutoHealFields is a regression test for the boundary
// handler clobbering persisted auto-heal fields. checkScheduledOperations persists
// interval-boundary bookkeeping on every boundary — which fires on the same cycle a
// reshare is triggered. Before the fix it wrote a FRESH NodeState, zeroing the
// out-of-band auto-heal fields (TrackedSourceVersion / ConsecutiveMPKAborts /
// LastKnownGoodSourceVersion) and losing the abort counter across a mid-interval
// restart. persistBoundary must instead load-merge so those fields survive.
func TestBoundaryPersistPreservesAutoHealFields(t *testing.T) {
	l, _ := zap.NewDevelopment()
	p := memory.NewMemoryPersistence()
	n := &Node{
		logger:          l,
		persistence:     p,
		abortTracker:    &abortTracker{},
		OperatorAddress: common.HexToAddress("0xabc"),
	}

	// Simulate a mid-abort state persisted out-of-band by persistAbortTracker /
	// recordSuccessfulReshare: counting 2 aborts against source version X and a
	// recorded last-known-good marker.
	const trackedVersion = int64(1783944564)
	const lkg = int64(1783944444)
	// A NodeStartTime recorded at the ACTUAL node start. A boundary write must not
	// re-stamp it to the boundary's time (the round-2 drift fix).
	const startTime = int64(1_700_000_000)
	require.NoError(t, p.SaveNodeState(&persistence.NodeState{
		OperatorAddress:            n.OperatorAddress.Hex(),
		TrackedSourceVersion:       trackedVersion,
		ConsecutiveMPKAborts:       2,
		LastKnownGoodSourceVersion: lkg,
		NodeStartTime:              startTime,
	}))

	// A boundary fires and persists its bookkeeping. With the old blind fresh-struct
	// write this zeroed the auto-heal fields; the load-merge helper must preserve them.
	const boundaryBlock = int64(9_000_000)
	n.persistBoundary(boundaryBlock)

	got, err := p.LoadNodeState()
	require.NoError(t, err)
	require.NotNil(t, got)

	// Boundary bookkeeping was written.
	require.Equal(t, boundaryBlock, got.LastProcessedBoundary, "boundary block must be recorded")
	require.NotZero(t, got.NodeStartTime, "node start time must be recorded")

	// NodeStartTime is PRESERVED, not re-stamped to the boundary fire time (the
	// round-2 drift fix): a boundary write on an existing state must leave it alone.
	require.Equal(t, startTime, got.NodeStartTime, "pre-existing NodeStartTime must survive a boundary write, not drift to the boundary time")

	// Auto-heal fields SURVIVE the boundary write (the regression this guards against).
	require.Equal(t, trackedVersion, got.TrackedSourceVersion, "tracked source version must survive boundary write")
	require.Equal(t, 2, got.ConsecutiveMPKAborts, "abort counter must survive boundary write")
	require.Equal(t, lkg, got.LastKnownGoodSourceVersion, "LKG marker must survive boundary write")
}
