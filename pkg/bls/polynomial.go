package bls

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

// EvaluatePolynomial evaluates a polynomial at point x
func EvaluatePolynomial(poly polynomial.Polynomial, x int) *fr.Element {
	xFr := new(fr.Element).SetInt64(int64(x))
	result := new(fr.Element).Set(&poly[0])

	xPower := new(fr.Element).SetOne()
	for k := 1; k < len(poly); k++ {
		xPower.Mul(xPower, xFr)
		term := new(fr.Element).Mul(&poly[k], xPower)
		result.Add(result, term)
	}

	return result
}

// ComputeLagrangeCoefficient computes the Lagrange coefficient for participant i at x=0
func ComputeLagrangeCoefficient(i int, participants []int) *fr.Element {
	numerator := new(fr.Element).SetOne()
	denominator := new(fr.Element).SetOne()

	iFr := new(fr.Element).SetInt64(int64(i))

	for _, j := range participants {
		if i != j {
			jFr := new(fr.Element).SetInt64(int64(j))

			// numerator *= (0 - j) = -j
			negJ := new(fr.Element).Neg(jFr)
			numerator.Mul(numerator, negJ)

			// denominator *= (i - j)
			diff := new(fr.Element).Sub(iFr, jFr)
			denominator.Mul(denominator, diff)
		}
	}

	// lambda = numerator / denominator
	lambda := new(fr.Element).Inverse(denominator)
	lambda.Mul(lambda, numerator)

	return lambda
}

// RecoverSecret recovers the secret from shares using Lagrange interpolation
func RecoverSecret(shares map[int]*fr.Element) *fr.Element {
	participants := make([]int, 0, len(shares))
	for id := range shares {
		participants = append(participants, id)
	}

	secret := new(fr.Element).SetZero()

	for id, share := range shares {
		lambda := ComputeLagrangeCoefficient(id, participants)
		term := new(fr.Element).Mul(lambda, share)
		secret.Add(secret, term)
	}

	return secret
}

// GeneratePolynomial generates a random polynomial with given secret and degree
func GeneratePolynomial(secret *fr.Element, degree int) polynomial.Polynomial {
	poly := make(polynomial.Polynomial, degree+1)

	// Set the constant term to the secret
	poly[0].Set(secret)

	// Generate random coefficients for higher degree terms
	for i := 1; i <= degree; i++ {
		_, _ = poly[i].SetRandom()
	}

	return poly
}

// GenerateShares generates shares for participants using polynomial secret sharing
func GenerateShares(poly polynomial.Polynomial, participantIDs []int) map[int]*fr.Element {
	shares := make(map[int]*fr.Element)

	for _, id := range participantIDs {
		shares[id] = EvaluatePolynomial(poly, id)
	}

	return shares
}

// CreateCommitments creates polynomial commitments in G2
func CreateCommitments(poly polynomial.Polynomial) []*G2Point {
	commitments := make([]*G2Point, len(poly))

	for i, coeff := range poly {
		commitments[i] = ScalarMulG2(G2Generator, &coeff)
	}

	return commitments
}

// VerifyShare verifies a share against polynomial commitments
func VerifyShare(nodeID int, share *fr.Element, commitments []*G2Point) bool {
	// Compute share * G2
	shareCommitment := ScalarMulG2(G2Generator, share)

	// Compute expected commitment from polynomial commitments
	// C_expected = Σ commitments[k] * nodeID^k
	expectedCommitment := commitments[0] // Start with constant term

	nodeFr := new(fr.Element).SetInt64(int64(nodeID))
	nodePower := new(fr.Element).SetOne()

	for k := 1; k < len(commitments); k++ {
		nodePower.Mul(nodePower, nodeFr)
		term := ScalarMulG2(commitments[k], nodePower)
		expectedCommitment = AddG2(expectedCommitment, term)
	}

	// Check if share * G2 == expected commitment
	return shareCommitment.Equal(expectedCommitment)
}
