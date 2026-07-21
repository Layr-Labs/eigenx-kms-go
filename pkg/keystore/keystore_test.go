package keystore

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func makeVersion(ts int64) *types.KeyShareVersion {
	share := new(fr.Element).SetInt64(ts)
	return &types.KeyShareVersion{
		Version:      ts,
		PrivateShare: share,
	}
}

func TestGetKeyVersionAtTime(t *testing.T) {
	t.Run("empty keystore returns nil", func(t *testing.T) {
		ks := NewKeyStore()
		if got := ks.GetKeyVersionAtTime(1_700_000_000); got != nil {
			t.Fatalf("expected nil, got version %d", got.Version)
		}
	})

	t.Run("timestamp before all versions returns nil", func(t *testing.T) {
		ks := NewKeyStore()
		ks.AddVersion(makeVersion(1_700_000_100))
		ks.AddVersion(makeVersion(1_700_000_200))
		if got := ks.GetKeyVersionAtTime(1_700_000_050); got != nil {
			t.Fatalf("expected nil, got version %d", got.Version)
		}
	})

	t.Run("timestamp exactly equal to a version returns that version", func(t *testing.T) {
		ks := NewKeyStore()
		v := makeVersion(1_700_000_100)
		ks.AddVersion(v)
		got := ks.GetKeyVersionAtTime(1_700_000_100)
		if got == nil || got.Version != 1_700_000_100 {
			t.Fatalf("expected version 1_700_000_100, got %v", got)
		}
	})

	t.Run("timestamp between two versions returns the earlier one", func(t *testing.T) {
		ks := NewKeyStore()
		ks.AddVersion(makeVersion(1_700_000_100))
		ks.AddVersion(makeVersion(1_700_000_300))
		got := ks.GetKeyVersionAtTime(1_700_000_200)
		if got == nil || got.Version != 1_700_000_100 {
			t.Fatalf("expected version 1_700_000_100, got %v", got)
		}
	})

	t.Run("timestamp after all versions returns the latest", func(t *testing.T) {
		ks := NewKeyStore()
		ks.AddVersion(makeVersion(1_700_000_100))
		ks.AddVersion(makeVersion(1_700_000_200))
		ks.AddVersion(makeVersion(1_700_000_300))
		got := ks.GetKeyVersionAtTime(1_900_000_000)
		if got == nil || got.Version != 1_700_000_300 {
			t.Fatalf("expected version 1_700_000_300, got %v", got)
		}
	})

	t.Run("returns most recent version not exceeding timestamp", func(t *testing.T) {
		ks := NewKeyStore()
		ks.AddVersion(makeVersion(1_700_000_000))
		ks.AddVersion(makeVersion(1_700_001_000))
		ks.AddVersion(makeVersion(1_700_002_000))
		got := ks.GetKeyVersionAtTime(1_700_001_500)
		if got == nil || got.Version != 1_700_001_000 {
			t.Fatalf("expected version 1_700_001_000, got %v", got)
		}
	})

	t.Run("out-of-order insertion returns correct version", func(t *testing.T) {
		ks := NewKeyStore()
		// Insert newer version first, then older
		ks.AddVersion(makeVersion(1_700_000_300))
		ks.AddVersion(makeVersion(1_700_000_100))
		got := ks.GetKeyVersionAtTime(1_700_000_200)
		if got == nil || got.Version != 1_700_000_100 {
			t.Fatalf("expected version 1_700_000_100, got %v", got)
		}
	})
}

// TestGetPrivateShareForVersion covers the exact-match version accessor added for
// reshare source-version agreement (docs/012). Unlike GetKeyVersionAtTime, it MUST
// return an error on absence and MUST NOT fall back to a nearest/earlier version — a
// nearest-match would let a lagging node deal from a stale share and reintroduce the
// master-secret corruption this accessor exists to prevent.
func TestGetPrivateShareForVersion(t *testing.T) {
	t.Run("returns the share for an exact version match", func(t *testing.T) {
		ks := NewKeyStore()
		ks.AddVersion(makeVersion(1_700_000_100))
		ks.AddVersion(makeVersion(1_700_000_200))

		got, err := ks.GetPrivateShareForVersion(1_700_000_200)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := new(fr.Element).SetInt64(1_700_000_200)
		if !got.Equal(want) {
			t.Fatalf("wrong share returned for version 1_700_000_200")
		}
	})

	t.Run("errors when the version is absent (no nearest-match fallback)", func(t *testing.T) {
		ks := NewKeyStore()
		ks.AddVersion(makeVersion(1_700_000_100))
		ks.AddVersion(makeVersion(1_700_000_300))

		// 1_700_000_200 does not exist. GetKeyVersionAtTime would return the
		// 1_700_000_100 version here; this accessor must NOT — it must error.
		if _, err := ks.GetPrivateShareForVersion(1_700_000_200); err == nil {
			t.Fatal("expected an error for an absent version, got nil (nearest-match fallback would reintroduce the corruption bug)")
		}
	})

	t.Run("errors on empty keystore", func(t *testing.T) {
		ks := NewKeyStore()
		if _, err := ks.GetPrivateShareForVersion(1_700_000_100); err == nil {
			t.Fatal("expected an error on empty keystore, got nil")
		}
	})

	t.Run("returns a copy, not the stored element", func(t *testing.T) {
		ks := NewKeyStore()
		ks.AddVersion(makeVersion(1_700_000_100))

		got, err := ks.GetPrivateShareForVersion(1_700_000_100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Mutating the returned element must not corrupt the stored share.
		got.SetInt64(42)
		again, err := ks.GetPrivateShareForVersion(1_700_000_100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := new(fr.Element).SetInt64(1_700_000_100)
		if !again.Equal(want) {
			t.Fatal("stored share was mutated through the returned element; accessor must return a copy")
		}
	})
}

// TestActivatePendingVersion_RejectsPoisoned guards the "active is never
// poisoned" invariant at the promotion boundary: ActivatePendingVersion must
// refuse to promote a pending version that has been MarkPoisoned'd, while a
// clean pending version still promotes normally.
func TestActivatePendingVersion_RejectsPoisoned(t *testing.T) {
	t.Run("refuses to activate a poisoned pending version", func(t *testing.T) {
		ks := NewKeyStore()
		active := &types.KeyShareVersion{Version: 100, PrivateShare: new(fr.Element).SetInt64(1)}
		ks.AddVersion(active)
		ks.SetActiveVersion(active)

		pending := &types.KeyShareVersion{Version: 200, PrivateShare: new(fr.Element).SetInt64(2)}
		ks.SetPendingVersion(pending)
		ks.MarkPoisoned(200)

		if err := ks.ActivatePendingVersion(); err == nil {
			t.Fatal("expected error activating a poisoned pending version, got nil")
		}
		// Active must not have moved to the poisoned version.
		if got := ks.GetActiveVersion(); got == nil || got.Version != 100 {
			t.Fatalf("active must stay on 100 when the pending version is poisoned, got %+v", got)
		}
	})

	t.Run("activates a clean pending version normally", func(t *testing.T) {
		ks := NewKeyStore()
		active := &types.KeyShareVersion{Version: 100, PrivateShare: new(fr.Element).SetInt64(1)}
		ks.AddVersion(active)
		ks.SetActiveVersion(active)

		pending := &types.KeyShareVersion{Version: 200, PrivateShare: new(fr.Element).SetInt64(2)}
		ks.SetPendingVersion(pending)

		if err := ks.ActivatePendingVersion(); err != nil {
			t.Fatalf("unexpected error activating a clean pending version: %v", err)
		}
		if got := ks.GetActiveVersion(); got == nil || got.Version != 200 {
			t.Fatalf("active must advance to 200, got %+v", got)
		}
	})
}

func TestKeyStore_ExcludesPoisonedVersion(t *testing.T) {
	ks := NewKeyStore()
	good := &types.KeyShareVersion{Version: 100, PrivateShare: new(fr.Element).SetInt64(1)}
	poison := &types.KeyShareVersion{Version: 200, PrivateShare: new(fr.Element).SetInt64(2)}
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
