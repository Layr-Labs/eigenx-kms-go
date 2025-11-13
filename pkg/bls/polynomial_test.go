package bls

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
	"github.com/stretchr/testify/assert"
)

func TestEvaluatePolynomial(t *testing.T) {
	t.Run("Constant Polynomial", func(t *testing.T) {
		// P(x) = 5
		poly := polynomial.Polynomial{fr.NewElement(5)}

		// Should return 5 for any x
		result := EvaluatePolynomial(poly, 0)
		assert.Equal(t, uint64(5), result.Uint64())

		result = EvaluatePolynomial(poly, 10)
		assert.Equal(t, uint64(5), result.Uint64())

		result = EvaluatePolynomial(poly, -5)
		expected := new(fr.Element).SetInt64(5)
		assert.True(t, result.Equal(expected))
	})

	t.Run("Linear Polynomial", func(t *testing.T) {
		// P(x) = 3 + 2x
		var coeff0, coeff1 fr.Element
		coeff0.SetInt64(3)
		coeff1.SetInt64(2)
		poly := polynomial.Polynomial{coeff0, coeff1}

		// P(0) = 3
		result := EvaluatePolynomial(poly, 0)
		assert.Equal(t, uint64(3), result.Uint64())

		// P(1) = 3 + 2 = 5
		result = EvaluatePolynomial(poly, 1)
		assert.Equal(t, uint64(5), result.Uint64())

		// P(5) = 3 + 10 = 13
		result = EvaluatePolynomial(poly, 5)
		assert.Equal(t, uint64(13), result.Uint64())

		// P(-2) = 3 + 2*(-2) = 3 - 4 = -1 (in field arithmetic)
		result = EvaluatePolynomial(poly, -2)
		expected := new(fr.Element).SetInt64(3)
		term := new(fr.Element).SetInt64(-4)
		expected.Add(expected, term)
		assert.True(t, result.Equal(expected))
	})

	t.Run("Quadratic Polynomial", func(t *testing.T) {
		// P(x) = 1 + 2x + 3x²
		var coeff0, coeff1, coeff2 fr.Element
		coeff0.SetInt64(1)
		coeff1.SetInt64(2)
		coeff2.SetInt64(3)
		poly := polynomial.Polynomial{coeff0, coeff1, coeff2}

		// P(0) = 1
		result := EvaluatePolynomial(poly, 0)
		assert.Equal(t, uint64(1), result.Uint64())

		// P(1) = 1 + 2 + 3 = 6
		result = EvaluatePolynomial(poly, 1)
		assert.Equal(t, uint64(6), result.Uint64())

		// P(2) = 1 + 4 + 12 = 17
		result = EvaluatePolynomial(poly, 2)
		assert.Equal(t, uint64(17), result.Uint64())

		// P(3) = 1 + 6 + 27 = 34
		result = EvaluatePolynomial(poly, 3)
		assert.Equal(t, uint64(34), result.Uint64())
	})

	t.Run("Higher Degree Polynomial", func(t *testing.T) {
		// P(x) = x³ + x² + x + 1
		var coeff0, coeff1, coeff2, coeff3 fr.Element
		coeff0.SetInt64(1)
		coeff1.SetInt64(1)
		coeff2.SetInt64(1)
		coeff3.SetInt64(1)
		poly := polynomial.Polynomial{coeff0, coeff1, coeff2, coeff3}

		// P(0) = 1
		result := EvaluatePolynomial(poly, 0)
		assert.Equal(t, uint64(1), result.Uint64())

		// P(1) = 1 + 1 + 1 + 1 = 4
		result = EvaluatePolynomial(poly, 1)
		assert.Equal(t, uint64(4), result.Uint64())

		// P(2) = 8 + 4 + 2 + 1 = 15
		result = EvaluatePolynomial(poly, 2)
		assert.Equal(t, uint64(15), result.Uint64())
	})

	t.Run("Large Coefficients", func(t *testing.T) {
		// Test with large field elements
		var coeff0, coeff1 fr.Element
		coeff0.SetUint64(1000000)
		coeff1.SetUint64(2000000)
		poly := polynomial.Polynomial{coeff0, coeff1}

		// P(10) = 1000000 + 20000000 = 21000000
		result := EvaluatePolynomial(poly, 10)
		assert.Equal(t, uint64(21000000), result.Uint64())
	})

	t.Run("Empty Polynomial", func(t *testing.T) {
		// Edge case: empty polynomial should behave like P(x) = 0
		poly := polynomial.Polynomial{}

		// Should panic or return zero - let's check behavior
		defer func() {
			if r := recover(); r == nil {
				// If no panic, result should be zero
				result := EvaluatePolynomial(poly, 5)
				assert.True(t, result.IsZero())
			}
		}()

		_ = EvaluatePolynomial(poly, 5)
	})

	t.Run("Comparison with Manual Calculation", func(t *testing.T) {
		// P(x) = 7 + 3x + 5x²
		var coeff0, coeff1, coeff2 fr.Element
		coeff0.SetInt64(7)
		coeff1.SetInt64(3)
		coeff2.SetInt64(5)
		poly := polynomial.Polynomial{coeff0, coeff1, coeff2}

		x := int64(4)
		result := EvaluatePolynomial(poly, x)

		// Manual calculation: 7 + 3*4 + 5*16 = 7 + 12 + 80 = 99
		expected := new(fr.Element).SetInt64(99)
		assert.True(t, result.Equal(expected))

		// Alternative manual calculation using field operations
		xFr := new(fr.Element).SetInt64(x)
		manual := new(fr.Element).Set(&coeff0)

		term1 := new(fr.Element).Mul(&coeff1, xFr)
		manual.Add(manual, term1)

		xSquared := new(fr.Element).Mul(xFr, xFr)
		term2 := new(fr.Element).Mul(&coeff2, xSquared)
		manual.Add(manual, term2)

		assert.True(t, result.Equal(manual), "Polynomial evaluation should match manual calculation")
	})
}

func TestEvaluatePolynomial_EdgeCases(t *testing.T) {
	t.Run("Negative X Values", func(t *testing.T) {
		// P(x) = 10 + x
		var coeff0, coeff1 fr.Element
		coeff0.SetInt64(10)
		coeff1.SetInt64(1)
		poly := polynomial.Polynomial{coeff0, coeff1}

		// Test various negative values
		testCases := []struct {
			x        int64
			expected int64
		}{
			{-1, 9},
			{-5, 5},
			{-10, 0},
		}

		for _, tc := range testCases {
			result := EvaluatePolynomial(poly, tc.x)
			expected := new(fr.Element).SetInt64(tc.expected)
			assert.True(t, result.Equal(expected), "P(%d) should equal %d", tc.x, tc.expected)
		}
	})

	t.Run("Maximum Degree Polynomial", func(t *testing.T) {
		// Create a polynomial of degree 100
		degree := 100
		poly := make(polynomial.Polynomial, degree+1)
		for i := 0; i <= degree; i++ {
			poly[i].SetInt64(1)
		}

		// Evaluate at x=1, should be degree+1
		result := EvaluatePolynomial(poly, 1)
		assert.Equal(t, uint64(degree+1), result.Uint64())

		// Evaluate at x=0, should be 1 (constant term)
		result = EvaluatePolynomial(poly, 0)
		assert.Equal(t, uint64(1), result.Uint64())
	})
}

func TestEvaluatePolynomial_Integration(t *testing.T) {
	t.Run("With GeneratePolynomial", func(t *testing.T) {
		secret := new(fr.Element).SetInt64(12345)
		degree := 3

		// Use GeneratePolynomial to create a random polynomial with the secret
		poly, err := GeneratePolynomial(secret, degree)
		if err != nil {
			t.Fatalf("Failed to generate polynomial: %v", err)
		}

		// Secret should be at x=0
		result := EvaluatePolynomial(poly, 0)
		assert.True(t, result.Equal(secret))

		// Generate shares
		shares := make(map[int]*fr.Element)
		for i := 1; i <= 5; i++ {
			shares[i] = EvaluatePolynomial(poly, int64(i))
		}

		// All shares should be different
		for i := 1; i <= 5; i++ {
			for j := i + 1; j <= 5; j++ {
				assert.False(t, shares[i].Equal(shares[j]),
					"Shares %d and %d should be different", i, j)
			}
		}
	})
}
