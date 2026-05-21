package reshare

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"math/rand"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
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
		newThreshold := dkg.CalculateThreshold(len(operators))

		currentShare := deriveScalar(seed)

		// Use first operator as dealer for generating shares.
		dealerAddr := operators[0].OperatorAddress
		r := NewReshare(dealerAddr, operators)

		shares, commitments, err := r.GenerateNewShares(currentShare, newThreshold)
		require.NoError(t, err)
		require.Len(t, commitments, newThreshold)

		// Constant term commitment should be currentShare * G2.
		expectedC0, err := crypto.ScalarMulG2(crypto.G2Generator, currentShare)
		require.NoError(t, err)
		require.True(t, expectedC0.IsEqual(&commitments[0]), "C[0] should commit to currentShare")

		// Every participant verifies its own share against the commitments.
		for _, op := range operators {
			opAddr := op.OperatorAddress
			verifier := NewReshare(opAddr, operators)
			share, ok := shares[opAddr]
			require.True(t, ok, "missing share for operator")
			require.True(t, verifier.VerifyNewShare(share, commitments), "share failed verification")
		}

		// Compute new key share using all collected shares/commitments.
		dealerAddrs := make([]common.Address, 0, len(shares))
		for id := range shares {
			dealerAddrs = append(dealerAddrs, id)
		}

		// Shuffle dealer IDs to test order-independence.
		seedBytes := sha256.Sum256(seed)
		rng := rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(seedBytes[:8]))))
		for i := len(dealerAddrs) - 1; i > 0; i-- {
			j := rng.Intn(i + 1)
			dealerAddrs[i], dealerAddrs[j] = dealerAddrs[j], dealerAddrs[i]
		}

		keyVersion, err := r.ComputeNewKeyShare(dealerAddrs, shares, [][]types.G2Point{commitments})
		require.NoError(t, err)
		require.NotNil(t, keyVersion)
		require.NotNil(t, keyVersion.PrivateShare)

		// Independently recompute the expected interpolated share.
		expected := new(fr.Element).SetZero()
		for _, dealerAddr := range dealerAddrs {
			share := shares[dealerAddr]
			lambda := crypto.ComputeLagrangeCoefficient(dealerAddr, dealerAddrs)
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
		newThreshold := dkg.CalculateThreshold(len(operators))
		currentShare := deriveScalar(seed)

		dealerAddr := operators[0].OperatorAddress
		r := NewReshare(dealerAddr, operators)

		shares, commitments, err := r.GenerateNewShares(currentShare, newThreshold)
		require.NoError(t, err)

		// Tamper with one share by adding 1.
		targetOp := operators[1]
		targetAddr := targetOp.OperatorAddress
		originalShare := shares[targetAddr]
		tamperedShare := new(fr.Element).Add(originalShare, new(fr.Element).SetUint64(1))

		// Verification should fail for the tampered share.
		verifier := NewReshare(targetAddr, operators)
		require.False(t, verifier.VerifyNewShare(tamperedShare, commitments),
			"tampered share should fail verification")

		// Original share should still pass.
		require.True(t, verifier.VerifyNewShare(originalShare, commitments),
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
		newThreshold := dkg.CalculateThreshold(len(operators))

		// Generate two different share sets.
		share1 := deriveScalar(seed1)
		share2 := deriveScalar(seed2)

		dealerAddr := operators[0].OperatorAddress
		r1 := NewReshare(dealerAddr, operators)
		r2 := NewReshare(dealerAddr, operators)

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
		targetAddr := targetOp.OperatorAddress
		verifier := NewReshare(targetAddr, operators)

		// share1 + commitments1 should verify.
		require.True(t, verifier.VerifyNewShare(shares1[targetAddr], commitments1),
			"share should verify against correct commitments")

		// share1 + commitments2 should NOT verify (mismatched).
		require.False(t, verifier.VerifyNewShare(shares1[targetAddr], commitments2),
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
		newThreshold := dkg.CalculateThreshold(len(operators))
		currentShare := deriveScalar(seed)

		dealerAddr := operators[0].OperatorAddress
		r := NewReshare(dealerAddr, operators)

		shares, commitments, err := r.GenerateNewShares(currentShare, newThreshold)
		require.NoError(t, err)

		// Use only exactly threshold shares (a subset).
		dealerAddrs := make([]common.Address, 0, len(shares))
		for id := range shares {
			dealerAddrs = append(dealerAddrs, id)
		}

		// Take exactly threshold dealers.
		subsetDealerIDs := dealerAddrs[:newThreshold]
		subsetShares := make(map[common.Address]*fr.Element, newThreshold)
		for _, id := range subsetDealerIDs {
			subsetShares[id] = shares[id]
		}

		keyVersion, err := r.ComputeNewKeyShare(subsetDealerIDs, subsetShares, [][]types.G2Point{commitments})
		require.NoError(t, err)
		require.NotNil(t, keyVersion)

		// Use all shares for comparison.
		keyVersionAll, err := r.ComputeNewKeyShare(dealerAddrs, shares, [][]types.G2Point{commitments})
		require.NoError(t, err)

		// Both should produce the same result since Lagrange interpolation is correct.
		require.True(t, keyVersion.PrivateShare.Equal(keyVersionAll.PrivateShare),
			"threshold subset should produce same key as full set")
	})
}

// FuzzZeroConstantDealerPolynomialsDoNotPreserveOriginalSecret captures the old
// protocol-mismatch class: if dealers all use zero-constant polynomials and
// recipients combine via Lagrange, the reconstructed secret is not the original
// non-zero cluster secret.
func FuzzZeroConstantDealerPolynomialsDoNotPreserveOriginalSecret(f *testing.F) {
	f.Add(5, []byte("seed-zero-constant"))

	f.Fuzz(func(t *testing.T, n int, seed []byte) {
		if n < 4 {
			n = 4
		}
		if n > 8 {
			n = 8
		}

		operators := testOperators(n)
		newThreshold := dkg.CalculateThreshold(len(operators))
		zero := new(fr.Element).SetZero()
		oldSecret := deriveScalar(seed)

		// Build dealer IDs from first n-1 operators.
		dealerAddrs := make([]common.Address, 0, len(operators)-1)
		for i := 0; i < len(operators)-1; i++ {
			dealerAddrs = append(dealerAddrs, operators[i].OperatorAddress)
		}

		// Each dealer generates zero-constant shares (the problematic mode).
		sharesByDealer := make(map[common.Address]map[common.Address]*fr.Element, len(dealerAddrs))
		for _, dealerAddr := range dealerAddrs {
			dealerResharer := NewReshare(dealerAddr, operators)
			perRecipientShares, _, err := dealerResharer.GenerateNewShares(zero, newThreshold)
			require.NoError(t, err)
			sharesByDealer[dealerAddr] = perRecipientShares
		}

		// Reconstruct final recipient shares via Lagrange combine.
		finalShares := make(map[common.Address]*fr.Element, len(operators))
		for _, recipient := range operators {
			recipientAddr := recipient.OperatorAddress
			received := make(map[common.Address]*fr.Element, len(dealerAddrs))
			for _, dealerAddr := range dealerAddrs {
				received[dealerAddr] = sharesByDealer[dealerAddr][recipientAddr]
			}

			recipientResharer := NewReshare(recipientAddr, operators)
			keyVersion, err := recipientResharer.ComputeNewKeyShare(dealerAddrs, received, nil)
			require.NoError(t, err)
			require.NotNil(t, keyVersion)
			require.NotNil(t, keyVersion.PrivateShare)
			finalShares[recipientAddr] = keyVersion.PrivateShare
		}

		// Recover a secret from any threshold recipients. It must not equal oldSecret.
		recoveryShares := make(map[common.Address]*fr.Element, newThreshold)
		for i := 0; i < newThreshold; i++ {
			addr := operators[i].OperatorAddress
			recoveryShares[addr] = finalShares[addr]
		}
		recovered, err := crypto.RecoverSecret(recoveryShares)
		if err == nil {
			require.False(t, recovered.Equal(oldSecret),
				"zero-constant dealer polynomials should not preserve original non-zero secret")
		}
	})
}
