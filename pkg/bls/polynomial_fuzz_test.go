package bls

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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
			// Ensure we still have enough shares (degree+1) ≤ n.
			degree = n - 1
		}

		secret := deriveScalarPoly(seed)
		poly, err := GeneratePolynomial(secret, degree)
		require.NoError(t, err)

		participantIDs := make([]int, 0, n)
		for i := 1; i <= n; i++ {
			participantIDs = append(participantIDs, i)
		}

		// Deterministically shuffle participants to ensure order independence.
		seedBytes := sha256.Sum256(seed)
		r := rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(seedBytes[:8]))))
		for i := len(participantIDs) - 1; i > 0; i-- {
			j := r.Intn(i + 1)
			participantIDs[i], participantIDs[j] = participantIDs[j], participantIDs[i]
		}

		shares := GenerateShares(poly, participantIDs)
		recovered, err := RecoverSecret(shares)
		require.NoError(t, err)
		require.True(t, recovered.Equal(secret), "recovered secret mismatch")
	})
}
