package bls

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
	"github.com/ethereum/go-ethereum/common"
)

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

// AddressToFr converts a common.Address (20 bytes) to an fr.Element for use in polynomial math.
func AddressToFr(addr common.Address) *fr.Element {
	var buf [32]byte
	copy(buf[12:], addr.Bytes()) // right-align 20 bytes in 32-byte buffer (big-endian)
	var elem fr.Element
	elem.SetBytes(buf[:])
	return &elem
}

// EvaluatePolynomial evaluates a polynomial at the point derived from an Ethereum address.
func EvaluatePolynomial(poly polynomial.Polynomial, addr common.Address) *fr.Element {
	xFr := AddressToFr(addr)
	result := poly.Eval(xFr)
	return &result
}

// ComputeLagrangeCoefficient computes the Lagrange coefficient for participant i at x=0
// using Ethereum addresses as identifiers.
func ComputeLagrangeCoefficient(i common.Address, participants []common.Address) *fr.Element {
	numerator := new(fr.Element).SetOne()
	denominator := new(fr.Element).SetOne()

	iFr := AddressToFr(i)

	for _, j := range participants {
		if i != j {
			jFr := AddressToFr(j)

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
// with Ethereum addresses as participant identifiers.
func RecoverSecret(shares map[common.Address]*fr.Element) (*fr.Element, error) {
	participants := make([]common.Address, 0, len(shares))
	for addr := range shares {
		participants = append(participants, addr)
	}

	secret := new(fr.Element).SetZero()

	for addr, share := range shares {
		lambda := ComputeLagrangeCoefficient(addr, participants)
		term := new(fr.Element).Mul(lambda, share)
		secret.Add(secret, term)
	}

	if secret.IsZero() {
		return nil, errors.New("secret cannot be zero, this should not happen")
	}
	return secret, nil
}

// GenerateShares generates shares for participants using polynomial secret sharing
// with Ethereum addresses as participant identifiers.
func GenerateShares(poly polynomial.Polynomial, participants []common.Address) map[common.Address]*fr.Element {
	shares := make(map[common.Address]*fr.Element)

	for _, addr := range participants {
		shares[addr] = EvaluatePolynomial(poly, addr)
	}

	return shares
}

// VerifyShare verifies a share against polynomial commitments using MultiExp optimization
// with an Ethereum address as the participant identifier.
func VerifyShare(addr common.Address, share *fr.Element, commitments []*G2Point) (bool, error) {
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

	// Compute powers of addr: [1, addr, addr^2, ..., addr^(n-1)]
	powers := make([]fr.Element, len(commitments))
	nodeFr := AddressToFr(addr)
	powers[0].SetOne() // addr^0 = 1

	for i := 1; i < len(commitments); i++ {
		powers[i].Mul(&powers[i-1], nodeFr) // addr^i = addr^(i-1) * addr
	}

	// Extract G2 affine points from commitments
	commitmentPoints := make([]bls12381.G2Affine, len(commitments))
	for i, c := range commitments {
		if c == nil || c.point == nil {
			return false, fmt.Errorf("nil commitment at index %d", i)
		}
		commitmentPoints[i] = *c.point
	}

	// Use MultiExp to compute Σ commitments[k] * addr^k efficiently
	var expectedCommitment bls12381.G2Affine
	if _, err := expectedCommitment.MultiExp(commitmentPoints, powers, ecc.MultiExpConfig{}); err != nil {
		return false, fmt.Errorf("failed to compute expected commitment: %w", err)
	}

	// Check if share * G2 == expected commitment
	return shareCommitment.point.Equal(&expectedCommitment), nil
}
