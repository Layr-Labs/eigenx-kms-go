package reshare

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"math/rand"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
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

// bigIntFromInt provides a small helper to avoid repetitive imports in fuzzer body.
func bigIntFromInt(v int) *big.Int {
	return big.NewInt(int64(v))
}

// deriveScalar maps arbitrary bytes to a non-zero Fr element to avoid identity outputs.
func deriveScalar(b []byte) *fr.Element {
	h := sha256.Sum256(b)
	s := new(fr.Element)
	if err := s.SetBytes(h[:]); err != nil || s.IsZero() {
		s.SetUint64(1)
	}
	return s
}

// threshold mirrors the DKG/reshare rule ⌈2n/3⌉.
func threshold(n int) int {
	return (2*n + 2) / 3
}

func FuzzGenerateVerifyAndComputeNewKeyShare(f *testing.F) {
	f.Add(3, []byte("seed"))
	f.Add(5, []byte("another-seed"))
	f.Add(4, []byte("edge"))
	f.Add(8, []byte("max"))

	f.Fuzz(func(t *testing.T, n int, seed []byte) {
		if n < 3 {
			n = 3
		}
		if n > 8 {
			n = 8
		}

		operators := testOperators(n)
		newThreshold := threshold(len(operators))

		currentShare := deriveScalar(seed)

		// Use first operator as dealer for generating shares.
		dealerID := addressToNodeID(operators[0].OperatorAddress)
		r := NewReshare(dealerID, operators)

		shares, commitments, err := r.GenerateNewShares(currentShare, newThreshold)
		require.NoError(t, err)
		require.Len(t, commitments, newThreshold)

		// Constant term commitment should be currentShare * G2.
		expectedC0, err := crypto.ScalarMulG2(crypto.G2Generator, currentShare)
		require.NoError(t, err)
		require.True(t, expectedC0.IsEqual(&commitments[0]), "C[0] should commit to currentShare")

		// Every participant verifies its own share against the commitments.
		for _, op := range operators {
			opID := addressToNodeID(op.OperatorAddress)
			verifier := NewReshare(opID, operators)
			share, ok := shares[opID]
			require.True(t, ok, "missing share for operator")
			require.True(t, verifier.VerifyNewShare(dealerID, share, commitments), "share failed verification")
		}

		// Compute new key share using all collected shares/commitments.
		dealerIDs := make([]int, 0, len(shares))
		for id := range shares {
			dealerIDs = append(dealerIDs, id)
		}

		// Shuffle dealer IDs to test order-independence.
		seedBytes := sha256.Sum256(seed)
		rng := rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(seedBytes[:8]))))
		for i := len(dealerIDs) - 1; i > 0; i-- {
			j := rng.Intn(i + 1)
			dealerIDs[i], dealerIDs[j] = dealerIDs[j], dealerIDs[i]
		}

		keyVersion := r.ComputeNewKeyShare(dealerIDs, shares, [][]types.G2Point{commitments})
		require.NotNil(t, keyVersion)
		require.NotNil(t, keyVersion.PrivateShare)

		// Independently recompute the expected interpolated share.
		expected := new(fr.Element).SetZero()
		for _, dealerID := range dealerIDs {
			share := shares[dealerID]
			lambda := crypto.ComputeLagrangeCoefficient(dealerID, dealerIDs)
			term := new(fr.Element).Mul(lambda, share)
			expected.Add(expected, term)
		}

		require.True(t, expected.Equal(keyVersion.PrivateShare), "interpolated share mismatch")
	})
}

func FuzzVerifyShareRejectsTamperedShare(f *testing.F) {
	f.Add(4, []byte("seed"))

	f.Fuzz(func(t *testing.T, n int, seed []byte) {
		if n < 3 {
			n = 3
		}
		if n > 6 {
			n = 6
		}

		operators := testOperators(n)
		newThreshold := threshold(len(operators))
		currentShare := deriveScalar(seed)

		dealerID := addressToNodeID(operators[0].OperatorAddress)
		r := NewReshare(dealerID, operators)

		shares, commitments, err := r.GenerateNewShares(currentShare, newThreshold)
		require.NoError(t, err)

		// Tamper with one share by adding 1.
		targetOp := operators[1]
		targetID := addressToNodeID(targetOp.OperatorAddress)
		originalShare := shares[targetID]
		tamperedShare := new(fr.Element).Add(originalShare, new(fr.Element).SetUint64(1))

		// Verification should fail for the tampered share.
		verifier := NewReshare(targetID, operators)
		require.False(t, verifier.VerifyNewShare(dealerID, tamperedShare, commitments),
			"tampered share should fail verification")

		// Original share should still pass.
		require.True(t, verifier.VerifyNewShare(dealerID, originalShare, commitments),
			"original share should pass verification")
	})
}

func FuzzVerifyShareRejectsMismatchedCommitments(f *testing.F) {
	f.Add(4, []byte("seed1"), []byte("seed2"))

	f.Fuzz(func(t *testing.T, n int, seed1, seed2 []byte) {
		if n < 3 {
			n = 3
		}
		if n > 6 {
			n = 6
		}

		operators := testOperators(n)
		newThreshold := threshold(len(operators))

		// Generate two different share sets.
		share1 := deriveScalar(seed1)
		share2 := deriveScalar(seed2)

		dealerID := addressToNodeID(operators[0].OperatorAddress)
		r1 := NewReshare(dealerID, operators)
		r2 := NewReshare(dealerID, operators)

		shares1, commitments1, err := r1.GenerateNewShares(share1, newThreshold)
		require.NoError(t, err)
		_, commitments2, err := r2.GenerateNewShares(share2, newThreshold)
		require.NoError(t, err)

		// Skip if seeds produced identical shares.
		if share1.Equal(share2) {
			t.Skip("degenerate input: identical shares")
		}

		// Try to verify share from set1 against commitments from set2.
		targetOp := operators[1]
		targetID := addressToNodeID(targetOp.OperatorAddress)
		verifier := NewReshare(targetID, operators)

		// share1 + commitments1 should verify.
		require.True(t, verifier.VerifyNewShare(dealerID, shares1[targetID], commitments1),
			"share should verify against correct commitments")

		// share1 + commitments2 should NOT verify (mismatched).
		require.False(t, verifier.VerifyNewShare(dealerID, shares1[targetID], commitments2),
			"share should fail verification against mismatched commitments")
	})
}

func FuzzComputeNewKeyShareThresholdSubset(f *testing.F) {
	f.Add(5, []byte("seed"))

	f.Fuzz(func(t *testing.T, n int, seed []byte) {
		if n < 4 {
			n = 4
		}
		if n > 7 {
			n = 7
		}

		operators := testOperators(n)
		newThreshold := threshold(len(operators))
		currentShare := deriveScalar(seed)

		dealerID := addressToNodeID(operators[0].OperatorAddress)
		r := NewReshare(dealerID, operators)

		shares, commitments, err := r.GenerateNewShares(currentShare, newThreshold)
		require.NoError(t, err)

		// Use only exactly threshold shares (a subset).
		dealerIDs := make([]int, 0, len(shares))
		for id := range shares {
			dealerIDs = append(dealerIDs, id)
		}

		// Take exactly threshold dealers.
		subsetDealerIDs := dealerIDs[:newThreshold]
		subsetShares := make(map[int]*fr.Element, newThreshold)
		for _, id := range subsetDealerIDs {
			subsetShares[id] = shares[id]
		}

		keyVersion := r.ComputeNewKeyShare(subsetDealerIDs, subsetShares, [][]types.G2Point{commitments})
		require.NotNil(t, keyVersion)

		// Use all shares for comparison.
		keyVersionAll := r.ComputeNewKeyShare(dealerIDs, shares, [][]types.G2Point{commitments})

		// Both should produce the same result since Lagrange interpolation is correct.
		require.True(t, keyVersion.PrivateShare.Equal(keyVersionAll.PrivateShare),
			"threshold subset should produce same key as full set")
	})
}
