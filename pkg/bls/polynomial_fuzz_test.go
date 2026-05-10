package bls

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// deriveScalarPoly deterministically maps bytes to a non-zero Fr element.
func deriveScalarPoly(b []byte) *fr.Element {
	h := sha256.Sum256(b)
	s := new(fr.Element)
	if err := s.SetBytes(h[:]); err != nil || s.IsZero() {
		s.SetUint64(1)
	}
	return s
}

// makeAddrs creates n participant addresses from 1..n
func makeAddrs(n int) []common.Address {
	addrs := make([]common.Address, 0, n)
	for i := 1; i <= n; i++ {
		addrs = append(addrs, common.BigToAddress(new(big.Int).SetInt64(int64(i))))
	}
	return addrs
}

func FuzzRecoverSecretRoundTrip(f *testing.F) {
	// Seeds: small n, large n, varying degrees (including constant-only).
	f.Add([]byte("seed"), 3, 2)
	f.Add([]byte("another-seed"), 5, 0)
	f.Add([]byte("edge-large"), 8, 1)
	f.Add([]byte("tiny"), 2, 3)

	f.Fuzz(func(t *testing.T, seed []byte, n int, degree int) {
		if n < 2 {
			n = 2
		}
		if n > 8 {
			n = 8
		}

		if degree < 0 {
			degree = 0
		}
		if degree > 4 {
			degree = 4
		}
		if degree >= n {
			// Ensure we still have enough shares (degree+1) <= n.
			degree = n - 1
		}

		secret := deriveScalarPoly(seed)
		poly, err := GeneratePolynomial(secret, degree)
		require.NoError(t, err)

		participantAddrs := makeAddrs(n)

		// Deterministically shuffle participants to ensure order independence.
		seedBytes := sha256.Sum256(seed)
		r := rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(seedBytes[:8]))))
		for i := len(participantAddrs) - 1; i > 0; i-- {
			j := r.Intn(i + 1)
			participantAddrs[i], participantAddrs[j] = participantAddrs[j], participantAddrs[i]
		}

		shares := GenerateShares(poly, participantAddrs)
		recovered, err := RecoverSecret(shares)
		require.NoError(t, err)
		require.True(t, recovered.Equal(secret), "recovered secret mismatch")
	})
}

// Negative: tampered shares should not recover the original secret.
func FuzzRecoverSecretTamperedShare(f *testing.F) {
	f.Add([]byte("tamper"), 4, 2)

	f.Fuzz(func(t *testing.T, seed []byte, n int, degree int) {
		if n < 3 {
			n = 3
		}
		if n > 8 {
			n = 8
		}
		if degree < 1 {
			degree = 1
		}
		if degree >= n {
			degree = n - 1
		}

		secret := deriveScalarPoly(seed)
		poly, err := GeneratePolynomial(secret, degree)
		require.NoError(t, err)

		participantAddrs := makeAddrs(n)
		shares := GenerateShares(poly, participantAddrs)

		// Tamper one share (middle participant) by adding 1.
		tamperedShares := make(map[common.Address]*fr.Element, len(shares))
		for addr, share := range shares {
			tamperedShares[addr] = new(fr.Element).Set(share)
		}
		tamperAddr := participantAddrs[len(participantAddrs)/2]
		tamperedShares[tamperAddr].Add(tamperedShares[tamperAddr], new(fr.Element).SetUint64(1))

		recovered, err := RecoverSecret(tamperedShares)
		if err == nil {
			require.False(t, recovered.Equal(secret), "tampered shares should not recover original secret")
		}
	})
}

// Negative: insufficient shares (fewer than degree+1) should fail or recover the wrong secret.
func FuzzRecoverSecretInsufficientShares(f *testing.F) {
	f.Add([]byte("insufficient"), 5, 3)

	f.Fuzz(func(t *testing.T, seed []byte, n int, degree int) {
		if n < 4 {
			n = 4
		}
		if n > 8 {
			n = 8
		}
		if degree < 2 {
			degree = 2
		}
		if degree >= n {
			degree = n - 1
		}

		secret := deriveScalarPoly(seed)
		poly, err := GeneratePolynomial(secret, degree)
		require.NoError(t, err)

		participantAddrs := makeAddrs(n)
		shares := GenerateShares(poly, participantAddrs)

		// Take only degree shares (insufficient; need degree+1).
		insufficient := make(map[common.Address]*fr.Element, degree)
		for i := 0; i < degree; i++ {
			addr := participantAddrs[i]
			insufficient[addr] = shares[addr]
		}

		recovered, err := RecoverSecret(insufficient)
		if err == nil {
			require.False(t, recovered.Equal(secret), "insufficient shares should not recover original secret")
		}
	})
}

// Duplicated participant IDs should not break recovery as long as unique IDs are sufficient.
func FuzzRecoverSecretDuplicateParticipants(f *testing.F) {
	f.Add([]byte("dupe"), 5, 2)

	f.Fuzz(func(t *testing.T, seed []byte, n int, degree int) {
		if n < 3 {
			n = 3
		}
		if n > 8 {
			n = 8
		}
		if degree < 1 {
			degree = 1
		}
		if degree >= n {
			degree = n - 1
		}

		secret := deriveScalarPoly(seed)
		poly, err := GeneratePolynomial(secret, degree)
		require.NoError(t, err)

		// Build participant addresses with duplicates but ensure at least degree+1 unique addrs.
		participantAddrs := makeAddrs(n)
		if len(participantAddrs) >= 2 {
			participantAddrs[1] = participantAddrs[0] // introduce a duplicate
		}

		shares := GenerateShares(poly, participantAddrs)
		recovered, err := RecoverSecret(shares)
		require.NoError(t, err)
		require.True(t, recovered.Equal(secret), "duplicates should not break recovery when enough unique IDs remain")
	})
}

// Boundary: degree 0 (constant) and degree = n-1 should still recover correctly.
func FuzzRecoverSecretBoundaryDegrees(f *testing.F) {
	f.Add([]byte("deg-zero"), 3, 0)
	f.Add([]byte("deg-max"), 5, 4)

	f.Fuzz(func(t *testing.T, seed []byte, n int, degree int) {
		if n < 2 {
			n = 2
		}
		if n > 8 {
			n = 8
		}

		// Snap degree to boundary cases.
		if degree <= 0 {
			degree = 0
		} else {
			degree = n - 1
		}

		secret := deriveScalarPoly(seed)
		poly, err := GeneratePolynomial(secret, degree)
		require.NoError(t, err)

		participantAddrs := makeAddrs(n)

		shares := GenerateShares(poly, participantAddrs)
		recovered, err := RecoverSecret(shares)
		require.NoError(t, err)
		require.True(t, recovered.Equal(secret), "boundary degree recovery mismatch")
	})
}
