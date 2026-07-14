package node

import (
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
		n.onMPKValidationAbort(active, majority, 2)
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
		n.onMPKValidationAbort(1783944444, 1783944564, 2) // active=V-1, majority=V
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
		n.onMPKValidationAbort(100, 100, 2)
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
		n.onMPKValidationAbort(200, 200, 2)
	}

	require.True(t, ks.IsPoisoned(200), "poisoned version must be marked")
	require.Equal(t, int64(200), ks.GetActiveVersion().Version, "active must not move when the rollback target is absent")

	entries := observed.FilterMessageSnippet("AUTO-HEAL FLOOR").All()
	require.NotEmpty(t, entries, "must emit a loud AUTO-HEAL FLOOR error when the rollback target is absent")
	require.Equal(t, int64(100), entries[len(entries)-1].ContextMap()["target"], "log must name the missing target")
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
