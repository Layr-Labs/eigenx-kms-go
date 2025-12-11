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

		participantIDs := make([]int, 0, n)
		for i := 1; i <= n; i++ {
			participantIDs = append(participantIDs, i)
		}
		shares := GenerateShares(poly, participantIDs)

		// Tamper one share (different participant) by adding 1.
		tamperedShares := make(map[int]*fr.Element, len(shares))
		for id, share := range shares {
			tamperedShares[id] = new(fr.Element).Set(share)
		}
		tamperID := participantIDs[len(participantIDs)/2]
		tamperedShares[tamperID].Add(tamperedShares[tamperID], new(fr.Element).SetUint64(1))

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

		participantIDs := make([]int, 0, n)
		for i := 1; i <= n; i++ {
			participantIDs = append(participantIDs, i)
		}
		shares := GenerateShares(poly, participantIDs)

		// Take only degree shares (insufficient; need degree+1).
		insufficient := make(map[int]*fr.Element, degree)
		for i := 0; i < degree; i++ {
			id := participantIDs[i]
			insufficient[id] = shares[id]
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

		// Build participant IDs with duplicates but ensure at least degree+1 unique IDs.
		participantIDs := make([]int, 0, n)
		for i := 1; i <= n; i++ {
			participantIDs = append(participantIDs, i)
		}
		if len(participantIDs) >= 2 {
			participantIDs[1] = participantIDs[0] // introduce a duplicate
		}

		shares := GenerateShares(poly, participantIDs)
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

		participantIDs := make([]int, 0, n)
		for i := 1; i <= n; i++ {
			participantIDs = append(participantIDs, i)
		}

		shares := GenerateShares(poly, participantIDs)
		recovered, err := RecoverSecret(shares)
		require.NoError(t, err)
		require.True(t, recovered.Equal(secret), "boundary degree recovery mismatch")
	})
}
