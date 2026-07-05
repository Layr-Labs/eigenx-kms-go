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
