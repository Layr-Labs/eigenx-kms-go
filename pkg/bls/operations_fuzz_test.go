package bls

import (
	"crypto/sha256"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

// deriveScalarOp deterministically maps bytes to a non-zero Fr element.
func deriveScalarOp(b []byte) *fr.Element {
	h := sha256.Sum256(b)
	s := new(fr.Element)
	if err := s.SetBytes(h[:]); err != nil || s.IsZero() {
		s.SetUint64(1)
	}
	return s
}

func FuzzScalarMulAddLinearG1(f *testing.F) {
	f.Add([]byte("a"), []byte("b"))
	f.Add([]byte("same"), []byte("same")) // identical scalars: 2*a*G
	f.Add([]byte{}, []byte("b"))          // empty seed

	f.Fuzz(func(t *testing.T, aSeed, bSeed []byte) {
		a := deriveScalarOp(aSeed)
		b := deriveScalarOp(bSeed)

		pA, err := ScalarMulG1(G1Generator, a)
		require.NoError(t, err)
		pB, err := ScalarMulG1(G1Generator, b)
		require.NoError(t, err)

		sumAB := new(fr.Element).Add(a, b)
		pSum, err := ScalarMulG1(G1Generator, sumAB)
		require.NoError(t, err)

		added, err := AddG1(pA, pB)
		require.NoError(t, err)

		require.True(t, added.point.Equal(pSum.point), "linear relation broken on G1")
	})
}

func FuzzScalarMulAddLinearG2(f *testing.F) {
	f.Add([]byte("a"), []byte("b"))
	f.Add([]byte("same"), []byte("same")) // identical scalars
	f.Add([]byte{}, []byte("b"))          // empty seed

	f.Fuzz(func(t *testing.T, aSeed, bSeed []byte) {
		a := deriveScalarOp(aSeed)
		b := deriveScalarOp(bSeed)

		pA, err := ScalarMulG2(G2Generator, a)
		require.NoError(t, err)
		pB, err := ScalarMulG2(G2Generator, b)
		require.NoError(t, err)

		sumAB := new(fr.Element).Add(a, b)
		pSum, err := ScalarMulG2(G2Generator, sumAB)
		require.NoError(t, err)

		added, err := AddG2(pA, pB)
		require.NoError(t, err)

		require.True(t, added.point.Equal(pSum.point), "linear relation broken on G2")
	})
}

func FuzzSignVerifyRoundTripG1(f *testing.F) {
	f.Add([]byte("seed"), []byte("msg"))
	f.Add([]byte("seed"), []byte{})          // empty message
	f.Add([]byte("seed"), []byte{0, 1, 255}) // binary message

	f.Fuzz(func(t *testing.T, seed, msg []byte) {
		if len(msg) == 0 {
			msg = []byte("default")
		}
		sum := sha256.Sum256(seed)
		sk, err := GeneratePrivateKeyFromSeed(sum[:])
		require.NoError(t, err)

		sig, err := sk.SignG1(msg)
		require.NoError(t, err)

		pk := sk.GetPublicKeyG2()
		ok, err := VerifyG1(pk, msg, sig)
		require.NoError(t, err)
		require.True(t, ok)
	})
}

func FuzzSignVerifyRoundTripG2(f *testing.F) {
	f.Add([]byte("seed"), []byte("msg"))
	f.Add([]byte("seed"), []byte{})          // empty message
	f.Add([]byte("seed"), []byte{0, 1, 255}) // binary message

	f.Fuzz(func(t *testing.T, seed, msg []byte) {
		if len(msg) == 0 {
			msg = []byte("default")
		}
		sum := sha256.Sum256(seed)
		sk, err := GeneratePrivateKeyFromSeed(sum[:])
		require.NoError(t, err)

		sig, err := sk.SignG2(msg)
		require.NoError(t, err)

		pk := sk.GetPublicKeyG1()
		ok, err := VerifyG2(pk, msg, sig)
		require.NoError(t, err)
		require.True(t, ok)
	})
}

func FuzzSignVerifyWrongMessageG1(f *testing.F) {
	f.Add([]byte("seed"), []byte("msg1"), []byte("msg2"))

	f.Fuzz(func(t *testing.T, seed, msg, wrongMsg []byte) {
		if len(msg) == 0 {
			msg = []byte("original")
		}
		if len(wrongMsg) == 0 || string(wrongMsg) == string(msg) {
			wrongMsg = append(msg, byte('X'))
		}

		sum := sha256.Sum256(seed)
		sk, err := GeneratePrivateKeyFromSeed(sum[:])
		require.NoError(t, err)

		sig, err := sk.SignG1(msg)
		require.NoError(t, err)

		pk := sk.GetPublicKeyG2()

		// Correct message verifies.
		ok, err := VerifyG1(pk, msg, sig)
		require.NoError(t, err)
		require.True(t, ok, "signature should verify for correct message")

		// Wrong message should fail.
		okWrong, err := VerifyG1(pk, wrongMsg, sig)
		require.NoError(t, err)
		require.False(t, okWrong, "signature should NOT verify for wrong message")
	})
}

func FuzzSignVerifyWrongKeyG1(f *testing.F) {
	f.Add([]byte("seed1"), []byte("seed2"), []byte("msg"))

	f.Fuzz(func(t *testing.T, seed1, seed2, msg []byte) {
		if len(msg) == 0 {
			msg = []byte("default")
		}

		sum1 := sha256.Sum256(seed1)
		sk1, err := GeneratePrivateKeyFromSeed(sum1[:])
		require.NoError(t, err)

		sum2 := sha256.Sum256(seed2)
		sk2, err := GeneratePrivateKeyFromSeed(sum2[:])
		require.NoError(t, err)

		// Skip if seeds produce identical keys.
		if sk1.GetScalar().Equal(sk2.GetScalar()) {
			t.Skip("degenerate input: identical keys")
		}

		sig, err := sk1.SignG1(msg)
		require.NoError(t, err)

		// Verify with sk1's pubkey should pass.
		pk1 := sk1.GetPublicKeyG2()
		ok1, err := VerifyG1(pk1, msg, sig)
		require.NoError(t, err)
		require.True(t, ok1)

		// Verify with sk2's pubkey should fail.
		pk2 := sk2.GetPublicKeyG2()
		ok2, err := VerifyG1(pk2, msg, sig)
		require.NoError(t, err)
		require.False(t, ok2, "signature should NOT verify with wrong public key")
	})
}

func FuzzAggregateG1Signatures(f *testing.F) {
	f.Add([]byte("seed"), []byte("msg"), 3)

	f.Fuzz(func(t *testing.T, seed, msg []byte, n int) {
		if len(msg) == 0 {
			msg = []byte("default")
		}
		if n < 1 {
			n = 1
		}
		if n > 5 {
			n = 5
		}

		sigs := make([]*SignatureG1, 0, n)
		for i := 0; i < n; i++ {
			derivedSeed := append(seed, byte(i))
			sum := sha256.Sum256(derivedSeed)
			sk, err := GeneratePrivateKeyFromSeed(sum[:])
			require.NoError(t, err)

			sig, err := sk.SignG1(msg)
			require.NoError(t, err)
			sigs = append(sigs, sig)
		}

		aggregated := AggregateG1(sigs)
		require.NotNil(t, aggregated)
		require.NotNil(t, aggregated.point)

		// Aggregation is associative: aggregate all at once vs. incrementally.
		if n >= 2 {
			partial := AggregateG1(sigs[:n-1])
			full := AggregateG1([]*SignatureG1{partial, sigs[n-1]})
			require.True(t, full.point.Equal(aggregated.point), "aggregation should be associative")
		}
	})
}

func FuzzScalarMultiplicationConsistency(f *testing.F) {
	f.Add([]byte("scalar"))

	f.Fuzz(func(t *testing.T, seed []byte) {
		s := deriveScalarOp(seed)

		// s*G1 should be consistent.
		p1, err := ScalarMulG1(G1Generator, s)
		require.NoError(t, err)
		p1Again, err := ScalarMulG1(G1Generator, s)
		require.NoError(t, err)
		require.True(t, p1.point.Equal(p1Again.point), "scalar mul should be deterministic on G1")

		// s*G2 should be consistent.
		p2, err := ScalarMulG2(G2Generator, s)
		require.NoError(t, err)
		p2Again, err := ScalarMulG2(G2Generator, s)
		require.NoError(t, err)
		require.True(t, p2.point.Equal(p2Again.point), "scalar mul should be deterministic on G2")
	})
}

// FuzzZeroScalarMultiplication tests that multiplying by zero produces identity.
func FuzzZeroScalarMultiplication(f *testing.F) {
	f.Add([]byte("seed"))

	f.Fuzz(func(t *testing.T, seed []byte) {
		zeroScalar := new(fr.Element).SetZero()

		// 0 * G1 should produce the identity (point at infinity).
		p1, err := ScalarMulG1(G1Generator, zeroScalar)
		require.NoError(t, err)
		require.True(t, p1.IsZero(), "0 * G1 should be identity")

		// 0 * G2 should produce the identity (point at infinity).
		p2, err := ScalarMulG2(G2Generator, zeroScalar)
		require.NoError(t, err)
		require.True(t, p2.IsZero(), "0 * G2 should be identity")
	})
}

// FuzzAdditionWithIdentityG1 tests that adding identity doesn't change a point.
func FuzzAdditionWithIdentityG1(f *testing.F) {
	f.Add([]byte("seed"))

	f.Fuzz(func(t *testing.T, seed []byte) {
		s := deriveScalarOp(seed)
		p, err := ScalarMulG1(G1Generator, s)
		require.NoError(t, err)

		// Create identity point (point at infinity).
		identity := NewG1Point(new(bls12381.G1Affine).SetInfinity())

		// p + identity = p
		result, err := AddG1(p, identity)
		require.NoError(t, err)
		require.True(t, result.point.Equal(p.point), "p + identity should equal p")

		// identity + p = p
		result2, err := AddG1(identity, p)
		require.NoError(t, err)
		require.True(t, result2.point.Equal(p.point), "identity + p should equal p")
	})
}

// FuzzAdditionWithIdentityG2 tests that adding identity doesn't change a point.
func FuzzAdditionWithIdentityG2(f *testing.F) {
	f.Add([]byte("seed"))

	f.Fuzz(func(t *testing.T, seed []byte) {
		s := deriveScalarOp(seed)
		p, err := ScalarMulG2(G2Generator, s)
		require.NoError(t, err)

		// Create identity point (point at infinity).
		identity := NewG2Point(new(bls12381.G2Affine).SetInfinity())

		// p + identity = p
		result, err := AddG2(p, identity)
		require.NoError(t, err)
		require.True(t, result.point.Equal(p.point), "p + identity should equal p")

		// identity + p = p
		result2, err := AddG2(identity, p)
		require.NoError(t, err)
		require.True(t, result2.point.Equal(p.point), "identity + p should equal p")
	})
}

// FuzzAdditiveInverseG1 tests that p + (-p) = identity.
func FuzzAdditiveInverseG1(f *testing.F) {
	f.Add([]byte("seed"))

	f.Fuzz(func(t *testing.T, seed []byte) {
		s := deriveScalarOp(seed)
		p, err := ScalarMulG1(G1Generator, s)
		require.NoError(t, err)

		// Compute -p by multiplying by -1 (or equivalently, field order - s).
		negOne := new(fr.Element).SetInt64(-1)
		negP, err := ScalarMulG1(p, negOne)
		require.NoError(t, err)

		// p + (-p) should be identity.
		result, err := AddG1(p, negP)
		require.NoError(t, err)
		require.True(t, result.IsZero(), "p + (-p) should be identity")
	})
}

// FuzzAdditiveInverseG2 tests that p + (-p) = identity.
func FuzzAdditiveInverseG2(f *testing.F) {
	f.Add([]byte("seed"))

	f.Fuzz(func(t *testing.T, seed []byte) {
		s := deriveScalarOp(seed)
		p, err := ScalarMulG2(G2Generator, s)
		require.NoError(t, err)

		// Compute -p by multiplying by -1.
		negOne := new(fr.Element).SetInt64(-1)
		negP, err := ScalarMulG2(p, negOne)
		require.NoError(t, err)

		// p + (-p) should be identity.
		result, err := AddG2(p, negP)
		require.NoError(t, err)
		require.True(t, result.IsZero(), "p + (-p) should be identity")
	})
}

// FuzzScalarMultiplicationByOne tests that 1 * p = p.
func FuzzScalarMultiplicationByOne(f *testing.F) {
	f.Add([]byte("seed"))

	f.Fuzz(func(t *testing.T, seed []byte) {
		s := deriveScalarOp(seed)

		// Create a point.
		p1, err := ScalarMulG1(G1Generator, s)
		require.NoError(t, err)
		p2, err := ScalarMulG2(G2Generator, s)
		require.NoError(t, err)

		// 1 * p should equal p.
		one := new(fr.Element).SetOne()

		result1, err := ScalarMulG1(p1, one)
		require.NoError(t, err)
		require.True(t, result1.point.Equal(p1.point), "1 * p should equal p on G1")

		result2, err := ScalarMulG2(p2, one)
		require.NoError(t, err)
		require.True(t, result2.point.Equal(p2.point), "1 * p should equal p on G2")
	})
}

// FuzzDoubleVsAddSelf tests that 2*p = p + p.
func FuzzDoubleVsAddSelf(f *testing.F) {
	f.Add([]byte("seed"))

	f.Fuzz(func(t *testing.T, seed []byte) {
		s := deriveScalarOp(seed)

		// G1: 2*p should equal p + p.
		p1, err := ScalarMulG1(G1Generator, s)
		require.NoError(t, err)

		two := new(fr.Element).SetUint64(2)
		doubled1, err := ScalarMulG1(p1, two)
		require.NoError(t, err)

		added1, err := AddG1(p1, p1)
		require.NoError(t, err)

		require.True(t, doubled1.point.Equal(added1.point), "2*p should equal p+p on G1")

		// G2: 2*p should equal p + p.
		p2, err := ScalarMulG2(G2Generator, s)
		require.NoError(t, err)

		doubled2, err := ScalarMulG2(p2, two)
		require.NoError(t, err)

		added2, err := AddG2(p2, p2)
		require.NoError(t, err)

		require.True(t, doubled2.point.Equal(added2.point), "2*p should equal p+p on G2")
	})
}
