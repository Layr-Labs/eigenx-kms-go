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
