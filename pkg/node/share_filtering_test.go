package node

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

func TestTrustedDealerIDs(t *testing.T) {
	shareA := new(fr.Element).SetInt64(10)
	shareB := new(fr.Element).SetInt64(20)
	shareC := new(fr.Element).SetInt64(30)

	t.Run("all verified returns all", func(t *testing.T) {
		validShares := map[int64]*fr.Element{1: shareA, 2: shareB, 3: shareC}
		verified := map[int64]bool{1: true, 2: true, 3: true}

		trusted := trustedDealerIDs(validShares, verified)
		require.Len(t, trusted, 3)
		require.Equal(t, shareA, trusted[1])
		require.Equal(t, shareB, trusted[2])
		require.Equal(t, shareC, trusted[3])
	})

	t.Run("polynomial fail excludes dealer", func(t *testing.T) {
		// Dealer 3 failed polynomial verification (not in validShares)
		validShares := map[int64]*fr.Element{1: shareA, 2: shareB}
		verified := map[int64]bool{1: true, 2: true, 3: true}

		trusted := trustedDealerIDs(validShares, verified)
		require.Len(t, trusted, 2)
		require.Nil(t, trusted[3])
	})

	t.Run("merkle fail excludes dealer", func(t *testing.T) {
		// Dealer 2 failed merkle verification (not in verifiedOperators)
		validShares := map[int64]*fr.Element{1: shareA, 2: shareB, 3: shareC}
		verified := map[int64]bool{1: true, 3: true}

		trusted := trustedDealerIDs(validShares, verified)
		require.Len(t, trusted, 2)
		require.Equal(t, shareA, trusted[1])
		require.Nil(t, trusted[2])
		require.Equal(t, shareC, trusted[3])
	})

	t.Run("intersection is correct", func(t *testing.T) {
		// Only dealer 2 passes both checks
		validShares := map[int64]*fr.Element{1: shareA, 2: shareB}
		verified := map[int64]bool{2: true, 3: true}

		trusted := trustedDealerIDs(validShares, verified)
		require.Len(t, trusted, 1)
		require.Equal(t, shareB, trusted[2])
	})

	t.Run("empty validShares returns empty", func(t *testing.T) {
		validShares := map[int64]*fr.Element{}
		verified := map[int64]bool{1: true, 2: true}

		trusted := trustedDealerIDs(validShares, verified)
		require.Empty(t, trusted)
	})

	t.Run("empty verifiedOperators returns empty", func(t *testing.T) {
		validShares := map[int64]*fr.Element{1: shareA, 2: shareB}
		verified := map[int64]bool{}

		trusted := trustedDealerIDs(validShares, verified)
		require.Empty(t, trusted)
	})

	t.Run("both empty returns empty", func(t *testing.T) {
		trusted := trustedDealerIDs(map[int64]*fr.Element{}, map[int64]bool{})
		require.Empty(t, trusted)
	})
}

func TestSelfDealerAlwaysTrusted(t *testing.T) {
	// Simulate: self (nodeID=1) is in validShares but NOT in verifiedOperators
	// because nodes don't verify their own broadcasts.
	// The fix adds verifiedOps[thisNodeID] = true before calling trustedDealerIDs.
	selfNodeID := int64(1)
	selfShare := new(fr.Element).SetInt64(42)

	validShares := map[int64]*fr.Element{
		selfNodeID: selfShare,
		2:          new(fr.Element).SetInt64(10),
		3:          new(fr.Element).SetInt64(20),
	}

	// verifiedOperators does NOT include self (as in real protocol)
	verifiedOps := map[int64]bool{2: true, 3: true}

	// Without the self-inclusion fix, self would be excluded
	trustedWithoutSelf := trustedDealerIDs(validShares, verifiedOps)
	require.Nil(t, trustedWithoutSelf[selfNodeID], "self should not be trusted without explicit inclusion")

	// With the self-inclusion fix (as done in node.go), self is added
	verifiedOps[selfNodeID] = true
	trustedWithSelf := trustedDealerIDs(validShares, verifiedOps)
	require.Equal(t, selfShare, trustedWithSelf[selfNodeID], "self should be trusted after explicit inclusion")
	require.Len(t, trustedWithSelf, 3)
}

func TestSelfInVerifiedButNotInValidShares(t *testing.T) {
	// Edge case: self is in verifiedOperators but NOT in validShares.
	// In practice this can't happen (a node's own polynomial always verifies),
	// but trustedDealerIDs should still handle it correctly — the self share
	// should not appear in the result because validShares is the authoritative source.
	selfNodeID := int64(1)

	validShares := map[int64]*fr.Element{
		2: new(fr.Element).SetInt64(10),
		3: new(fr.Element).SetInt64(20),
	}

	verifiedOps := map[int64]bool{selfNodeID: true, 2: true, 3: true}

	trusted := trustedDealerIDs(validShares, verifiedOps)
	require.Len(t, trusted, 2, "self should not appear when absent from validShares")
	require.Nil(t, trusted[selfNodeID])
	require.NotNil(t, trusted[2])
	require.NotNil(t, trusted[3])
}

func TestReshareFinalizationUsesFilteredShares(t *testing.T) {
	// This test validates that the reshare delta computation only sums trusted shares.
	// It simulates the reshare finalization logic from node.go.

	t.Run("delta excludes unverified dealer shares", func(t *testing.T) {
		// Simulate 3 dealers, but dealer 3 fails merkle verification
		share1 := new(fr.Element).SetInt64(5)
		share2 := new(fr.Element).SetInt64(7)
		share3 := new(fr.Element).SetInt64(100) // malicious share

		validShares := map[int64]*fr.Element{1: share1, 2: share2, 3: share3}
		verifiedOps := map[int64]bool{1: true, 2: true} // dealer 3 failed merkle

		trustedShares := trustedDealerIDs(validShares, verifiedOps)

		// Compute delta only from trusted shares (matches node.go logic)
		delta := new(fr.Element).SetZero()
		for _, share := range trustedShares {
			if share == nil {
				continue
			}
			delta.Add(delta, share)
		}

		// Expected delta = 5 + 7 = 12 (excludes malicious share of 100)
		expected := new(fr.Element).SetInt64(12)
		require.True(t, delta.Equal(expected), "delta should only include trusted shares, got %s want %s", delta.String(), expected.String())
	})

	t.Run("delta excludes polynomial-failed dealer shares", func(t *testing.T) {
		// Dealer 2 fails polynomial verification (not in validShares)
		share1 := new(fr.Element).SetInt64(5)
		share3 := new(fr.Element).SetInt64(8)

		validShares := map[int64]*fr.Element{1: share1, 3: share3}
		verifiedOps := map[int64]bool{1: true, 2: true, 3: true}

		trustedShares := trustedDealerIDs(validShares, verifiedOps)

		delta := new(fr.Element).SetZero()
		for _, share := range trustedShares {
			if share == nil {
				continue
			}
			delta.Add(delta, share)
		}

		expected := new(fr.Element).SetInt64(13) // 5 + 8
		require.True(t, delta.Equal(expected), "delta should exclude polynomial-failed shares")
	})
}

func TestDKGFinalizationFiltersUnverifiedDealers(t *testing.T) {
	// Validates that DKG finalization builds participantIDs and allCommitments
	// only from trusted dealers (intersection of validShares and verifiedOperators).

	share1 := new(fr.Element).SetInt64(10)
	share2 := new(fr.Element).SetInt64(20)
	share3 := new(fr.Element).SetInt64(30)

	validShares := map[int64]*fr.Element{1: share1, 2: share2, 3: share3}

	// Only dealers 1 and 3 pass merkle verification. Self (nodeID=1) added explicitly.
	verifiedOps := map[int64]bool{1: true, 3: true}

	trustedShares := trustedDealerIDs(validShares, verifiedOps)

	require.Len(t, trustedShares, 2)
	require.NotNil(t, trustedShares[1])
	require.Nil(t, trustedShares[2], "dealer 2 should be excluded (failed merkle)")
	require.NotNil(t, trustedShares[3])

	// Verify that only trusted dealers' commitments would be included
	// (simulating the operator iteration loop in node.go)
	type mockOp struct{ nodeID int64 }
	operators := []mockOp{{1}, {2}, {3}}
	participantIDs := make([]int64, 0)
	for _, op := range operators {
		if _, ok := trustedShares[op.nodeID]; ok {
			participantIDs = append(participantIDs, op.nodeID)
		}
	}

	require.Equal(t, []int64{1, 3}, participantIDs)
}
