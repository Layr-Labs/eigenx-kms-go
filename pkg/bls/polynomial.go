package bls

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

// EvaluatePolynomial evaluates a polynomial at point x
// audit: x is int64 but really should be uint64
func EvaluatePolynomial(poly polynomial.Polynomial, x int64) *fr.Element {
	xFr := new(fr.Element).SetInt64(x)
	result := poly.Eval(xFr)
	return &result
}

// ComputeLagrangeCoefficient computes the Lagrange coefficient for participant i at x=0
// audit: should participants register a random element than using their index ?
// TODO(anup): there is an optimized cached version that can be done here.
func ComputeLagrangeCoefficient(i int64, participants []int64) *fr.Element {
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
func RecoverSecret(shares map[int64]*fr.Element) (*fr.Element, error) {
	participants := make([]int64, 0, len(shares))
	for id := range shares {
		participants = append(participants, id)
	}

	secret := new(fr.Element).SetZero()

	for id, share := range shares {
		lambda := ComputeLagrangeCoefficient(id, participants)
		term := new(fr.Element).Mul(lambda, share)
		secret.Add(secret, term)
	}

	if secret.IsZero() {
		return nil, errors.New("secret cannot be zero, this should not happen")
	}
	return secret, nil
}

// GeneratePolynomial generates a random polynomial with given secret and degree
// audit: should the polynomial be generated with a random secret ?
func GeneratePolynomial(secret *fr.Element, degree int) (polynomial.Polynomial, error) {
	poly := make(polynomial.Polynomial, degree+1)

	// Set the constant term to the secret
	poly[0].Set(secret)

	// Generate random coefficients for higher degree terms
	for i := 1; i <= degree; i++ {
		if _, err := poly[i].SetRandom(); err != nil {
			return nil, fmt.Errorf("failed to generate random coefficient: %w", err)
		}
	}

	return poly, nil
}

// GenerateShares generates shares for participants using polynomial secret sharing
// audit: should the shares be generated with a random scalar's generated for the participants?
func GenerateShares(poly polynomial.Polynomial, participantIDs []int) map[int]*fr.Element {
	shares := make(map[int]*fr.Element)

	for _, id := range participantIDs {
		shares[id] = EvaluatePolynomial(poly, int64(id))
	}

	return shares
}

// CreateCommitments creates polynomial commitments in G2
// TODO(anupsv): parallelize this, maybe doesn't matter for 20 operators. Look into this further.
func CreateCommitments(poly polynomial.Polynomial) ([]*G2Point, error) {
	commitments := make([]*G2Point, len(poly))

	for i, coeff := range poly {
		commitment, err := ScalarMulG2(G2Generator, &coeff)
		if err != nil {
			return nil, fmt.Errorf("failed to create commitment: %w", err)
		}
		commitments[i] = commitment
	}

	return commitments, nil
}

// VerifyShare verifies a share against polynomial commitments using MultiExp optimization
// audit: nodeId should be uint64
func VerifyShare(nodeID int, share *fr.Element, commitments []*G2Point) (bool, error) {
	if len(commitments) == 0 {
		return false, errors.New("no commitments provided")
	}

	if share == nil {
		return false, errors.New("share is nil")
	}

	// Compute share * G2
	shareCommitment, err := ScalarMulG2(G2Generator, share)
	if err != nil {
		return false, fmt.Errorf("failed to compute share commitment: %w", err)
	}

	// Compute powers of nodeID: [1, nodeID, nodeID^2, ..., nodeID^(n-1)]
	powers := make([]fr.Element, len(commitments))
	nodeFr := new(fr.Element).SetInt64(int64(nodeID))
	powers[0].SetOne() // nodeID^0 = 1

	for i := 1; i < len(commitments); i++ {
		powers[i].Mul(&powers[i-1], nodeFr) // nodeID^i = nodeID^(i-1) * nodeID
	}

	// Extract G2 affine points from commitments
	commitmentPoints := make([]bls12381.G2Affine, len(commitments))
	for i, c := range commitments {
		if c == nil || c.point == nil {
			return false, fmt.Errorf("nil commitment at index %d", i)
		}
		commitmentPoints[i] = *c.point
	}

	// Use MultiExp to compute Σ commitments[k] * nodeID^k efficiently
	var expectedCommitment bls12381.G2Affine
	if _, err := expectedCommitment.MultiExp(commitmentPoints, powers, ecc.MultiExpConfig{}); err != nil {
		return false, fmt.Errorf("failed to compute expected commitment: %w", err)
	}

	// Check if share * G2 == expected commitment
	return shareCommitment.point.Equal(&expectedCommitment), nil
}
