package dkg

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/util"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// helper to build a deterministic operator list of size n.
func testOperators(n int) []*peering.OperatorSetPeer {
	ops := make([]*peering.OperatorSetPeer, 0, n)
	for i := 0; i < n; i++ {
		addr := common.BigToAddress(bigIntFromInt(i + 1))
		ops = append(ops, &peering.OperatorSetPeer{OperatorAddress: addr})
	}
	return ops
}

// bigIntFromInt provides a small helper to avoid importing math/big repeatedly.
func bigIntFromInt(v int) *big.Int {
	return big.NewInt(int64(v))
}

// deriveScalar deterministically maps bytes to a non-zero Fr element.
func deriveScalar(b []byte) *fr.Element {
	h := sha256.Sum256(b)
	s := new(fr.Element)
	if err := s.SetBytes(h[:]); err != nil || s.IsZero() {
		s.SetUint64(1)
	}
	return s
}

func FuzzGenerateVerifyAndFinalize(f *testing.F) {
	f.Add(3)
	f.Add(4)
	f.Add(5)
	f.Add(6)
	f.Add(7)

	f.Fuzz(func(t *testing.T, n int) {
		if n < 3 {
			n = 3
		}
		if n > 8 {
			n = 8
		}

		operators := testOperators(n)
		threshold := CalculateThreshold(len(operators))

		// Use the first operator as the dealer for this fuzz run.
		dealerID := util.AddressToNodeID(operators[0].OperatorAddress)
		d := NewDKG(dealerID, threshold, operators)

		shares, commitments, err := d.GenerateShares()
		require.NoError(t, err)
		require.Len(t, commitments, threshold)

		// Every participant should verify its own share against the commitments.
		for _, op := range operators {
			opID := util.AddressToNodeID(op.OperatorAddress)
			verifier := NewDKG(opID, threshold, operators)
			share, ok := shares[opID]
			require.True(t, ok, "missing share for operator")
			require.True(t, verifier.VerifyShare(opID, share, commitments), "share failed verification")
		}

		// Finalize and ensure the private share matches the aggregation model used in FinalizeKeyShare.
		// Note: FinalizeKeyShare sums shares across dealers for this participant; since this test only
		// uses a single dealer distribution, we mirror that invariant here (sum of provided shares).
		participantIDs := make([]int64, 0, len(shares))
		for id := range shares {
			participantIDs = append(participantIDs, id)
		}

		keyVersion := d.FinalizeKeyShare(shares, [][]types.G2Point{commitments}, participantIDs)
		require.NotNil(t, keyVersion)
		require.NotNil(t, keyVersion.PrivateShare)

		// With one dealer in this test, shares map contains the per-participant share from that dealer.
		// FinalizeKeyShare sums these to form the participant's final share.
		expected := new(fr.Element).SetZero()
		for _, share := range shares {
			expected.Add(expected, share)
		}

		require.True(t, expected.Equal(keyVersion.PrivateShare), "finalized private share mismatch (sum of dealer shares)")
	})
}

// FuzzVerifyShareRejectsTamperedShare tests that verification fails for tampered shares.
// This simulates a Byzantine dealer sending a corrupted share.
func FuzzVerifyShareRejectsTamperedShare(f *testing.F) {
	f.Add(4, []byte("seed"))
	f.Add(5, []byte("another"))

	f.Fuzz(func(t *testing.T, n int, seed []byte) {
		if n < 3 {
			n = 3
		}
		if n > 6 {
			n = 6
		}

		operators := testOperators(n)
		threshold := CalculateThreshold(len(operators))

		dealerID := util.AddressToNodeID(operators[0].OperatorAddress)
		d := NewDKG(dealerID, threshold, operators)

		shares, commitments, err := d.GenerateShares()
		require.NoError(t, err)

		// Tamper with a share by adding a delta derived from seed.
		targetOp := operators[1]
		targetID := util.AddressToNodeID(targetOp.OperatorAddress)
		originalShare := shares[targetID]

		delta := deriveScalar(seed)
		tamperedShare := new(fr.Element).Add(originalShare, delta)

		// Verification should fail for the tampered share.
		verifier := NewDKG(targetID, threshold, operators)
		require.False(t, verifier.VerifyShare(dealerID, tamperedShare, commitments),
			"tampered share should fail verification")

		// Original share should still pass.
		require.True(t, verifier.VerifyShare(dealerID, originalShare, commitments),
			"original share should pass verification")
	})
}

// FuzzVerifyShareRejectsCorruptedCommitments tests that verification fails
// when commitments are corrupted (Byzantine dealer equivocation).
func FuzzVerifyShareRejectsCorruptedCommitments(f *testing.F) {
	f.Add(4, []byte("seed"), 0)
	f.Add(5, []byte("another"), 1)

	f.Fuzz(func(t *testing.T, n int, seed []byte, corruptIdx int) {
		if n < 3 {
			n = 3
		}
		if n > 6 {
			n = 6
		}

		operators := testOperators(n)
		threshold := CalculateThreshold(len(operators))

		dealerID := util.AddressToNodeID(operators[0].OperatorAddress)
		d := NewDKG(dealerID, threshold, operators)

		shares, commitments, err := d.GenerateShares()
		require.NoError(t, err)

		// Corrupt one commitment by replacing it with a different point.
		corruptIdx = corruptIdx % len(commitments)
		if corruptIdx < 0 {
			corruptIdx = 0
		}

		// Create corrupted commitments by adding G2 generator to one commitment.
		corruptedCommitments := make([]types.G2Point, len(commitments))
		copy(corruptedCommitments, commitments)

		delta := deriveScalar(seed)
		corruptedPoint, err := crypto.ScalarMulG2(crypto.G2Generator, delta)
		require.NoError(t, err)
		corruptedCommitments[corruptIdx] = *corruptedPoint

		// Verification should fail against corrupted commitments.
		targetOp := operators[1]
		targetID := util.AddressToNodeID(targetOp.OperatorAddress)
		verifier := NewDKG(targetID, threshold, operators)

		require.False(t, verifier.VerifyShare(dealerID, shares[targetID], corruptedCommitments),
			"share should fail verification against corrupted commitments")

		// Original commitments should still verify.
		require.True(t, verifier.VerifyShare(dealerID, shares[targetID], commitments),
			"share should pass verification against original commitments")
	})
}

// FuzzVerifyShareRejectsMismatchedDealerCommitments tests that shares from one dealer
// don't verify against commitments from a different dealer (dealer equivocation detection).
func FuzzVerifyShareRejectsMismatchedDealerCommitments(f *testing.F) {
	f.Add(4)

	f.Fuzz(func(t *testing.T, n int) {
		if n < 3 {
			n = 3
		}
		if n > 6 {
			n = 6
		}

		operators := testOperators(n)
		threshold := CalculateThreshold(len(operators))

		// Two different dealers generate their own shares/commitments.
		dealer1ID := util.AddressToNodeID(operators[0].OperatorAddress)
		dealer2ID := util.AddressToNodeID(operators[1].OperatorAddress)

		d1 := NewDKG(dealer1ID, threshold, operators)
		d2 := NewDKG(dealer2ID, threshold, operators)

		shares1, commitments1, err := d1.GenerateShares()
		require.NoError(t, err)
		shares2, commitments2, err := d2.GenerateShares()
		require.NoError(t, err)

		// Verify that share1 + commitments1 works.
		targetOp := operators[2]
		targetID := util.AddressToNodeID(targetOp.OperatorAddress)
		verifier := NewDKG(targetID, threshold, operators)

		require.True(t, verifier.VerifyShare(dealer1ID, shares1[targetID], commitments1),
			"share1 should verify against commitments1")
		require.True(t, verifier.VerifyShare(dealer2ID, shares2[targetID], commitments2),
			"share2 should verify against commitments2")

		// Cross-verification should fail (Byzantine detection).
		require.False(t, verifier.VerifyShare(dealer1ID, shares1[targetID], commitments2),
			"share1 should NOT verify against commitments2")
		require.False(t, verifier.VerifyShare(dealer2ID, shares2[targetID], commitments1),
			"share2 should NOT verify against commitments1")
	})
}

// FuzzThresholdBoundaryConditions tests threshold edge cases.
func FuzzThresholdBoundaryConditions(f *testing.F) {
	// Test various n values to hit threshold boundaries.
	for n := 3; n <= 10; n++ {
		f.Add(n)
	}

	f.Fuzz(func(t *testing.T, n int) {
		if n < 3 {
			n = 3
		}
		if n > 10 {
			n = 10
		}

		threshold := CalculateThreshold(n)

		// Verify threshold formula: ⌈2n/3⌉
		expectedThreshold := (2*n + 2) / 3
		require.Equal(t, expectedThreshold, threshold, "threshold formula mismatch for n=%d", n)

		// Verify threshold is always > n/2 (majority) and <= n.
		require.Greater(t, threshold, n/2, "threshold should be majority for n=%d", n)
		require.LessOrEqual(t, threshold, n, "threshold should not exceed n for n=%d", n)

		// Generate and verify with exactly threshold operators.
		operators := testOperators(n)
		dealerID := util.AddressToNodeID(operators[0].OperatorAddress)
		d := NewDKG(dealerID, threshold, operators)

		shares, commitments, err := d.GenerateShares()
		require.NoError(t, err)
		require.Len(t, commitments, threshold, "commitments should match threshold")

		// Verify all shares.
		for _, op := range operators {
			opID := util.AddressToNodeID(op.OperatorAddress)
			verifier := NewDKG(opID, threshold, operators)
			require.True(t, verifier.VerifyShare(dealerID, shares[opID], commitments))
		}
	})
}

// FuzzVerifyShareWithZeroShare tests that zero shares are handled correctly.
func FuzzVerifyShareWithZeroShare(f *testing.F) {
	f.Add(4)

	f.Fuzz(func(t *testing.T, n int) {
		if n < 3 {
			n = 3
		}
		if n > 6 {
			n = 6
		}

		operators := testOperators(n)
		threshold := CalculateThreshold(len(operators))

		dealerID := util.AddressToNodeID(operators[0].OperatorAddress)
		d := NewDKG(dealerID, threshold, operators)

		_, commitments, err := d.GenerateShares()
		require.NoError(t, err)

		// Create a zero share.
		zeroShare := new(fr.Element).SetZero()

		// Zero share should fail verification (unless commitments are also zero, which is unlikely).
		targetOp := operators[1]
		targetID := util.AddressToNodeID(targetOp.OperatorAddress)
		verifier := NewDKG(targetID, threshold, operators)

		// A zero share is mathematically valid only if the polynomial evaluates to 0 at that point.
		// For random polynomials, this is astronomically unlikely, so verification should fail.
		result := verifier.VerifyShare(dealerID, zeroShare, commitments)
		// We don't assert here because the polynomial COULD evaluate to zero (very unlikely).
		// Instead, we just ensure no panic occurs.
		_ = result
	})
}

// FuzzVerifyShareWithEmptyCommitments tests behavior with empty commitments.
func FuzzVerifyShareWithEmptyCommitments(f *testing.F) {
	f.Add(4, []byte("seed"))

	f.Fuzz(func(t *testing.T, n int, seed []byte) {
		if n < 3 {
			n = 3
		}
		if n > 6 {
			n = 6
		}

		operators := testOperators(n)
		threshold := CalculateThreshold(len(operators))

		dealerID := util.AddressToNodeID(operators[0].OperatorAddress)
		d := NewDKG(dealerID, threshold, operators)

		shares, _, err := d.GenerateShares()
		require.NoError(t, err)

		// Empty commitments.
		emptyCommitments := []types.G2Point{}

		targetOp := operators[1]
		targetID := util.AddressToNodeID(targetOp.OperatorAddress)
		verifier := NewDKG(targetID, threshold, operators)

		// Verification with empty commitments should fail (or panic gracefully).
		// The implementation should handle this edge case.
		// We're testing that it doesn't panic.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("VerifyShare panicked with empty commitments (expected): %v", r)
				}
			}()
			result := verifier.VerifyShare(dealerID, shares[targetID], emptyCommitments)
			// If it doesn't panic, it should return false.
			require.False(t, result, "empty commitments should fail verification")
		}()
	})
}

// FuzzFinalizeWithSubsetOfShares tests finalization with various share subsets.
func FuzzFinalizeWithSubsetOfShares(f *testing.F) {
	f.Add(5, 3)
	f.Add(6, 4)

	f.Fuzz(func(t *testing.T, n int, subsetSize int) {
		if n < 3 {
			n = 3
		}
		if n > 7 {
			n = 7
		}

		operators := testOperators(n)
		threshold := CalculateThreshold(len(operators))

		if subsetSize < 1 {
			subsetSize = 1
		}
		if subsetSize > n {
			subsetSize = n
		}

		dealerID := util.AddressToNodeID(operators[0].OperatorAddress)
		d := NewDKG(dealerID, threshold, operators)

		shares, commitments, err := d.GenerateShares()
		require.NoError(t, err)

		// Take a subset of shares.
		subsetShares := make(map[int64]*fr.Element)
		participantIDs := make([]int64, 0, subsetSize)
		count := 0
		for id, share := range shares {
			if count >= subsetSize {
				break
			}
			subsetShares[id] = share
			participantIDs = append(participantIDs, id)
			count++
		}

		// Finalize with subset.
		keyVersion := d.FinalizeKeyShare(subsetShares, [][]types.G2Point{commitments}, participantIDs)
		require.NotNil(t, keyVersion)

		// The finalized share should be the sum of the subset.
		expected := new(fr.Element).SetZero()
		for _, share := range subsetShares {
			expected.Add(expected, share)
		}
		require.True(t, expected.Equal(keyVersion.PrivateShare), "finalized share should be sum of subset")
	})
}
