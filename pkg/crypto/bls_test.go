package crypto

import (
	"math/big"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

// TestScalarMulG1 tests scalar multiplication on G1
func Test_ScalarMulG1(t *testing.T) {
	tests := []struct {
		name   string
		scalar *fr.Element
	}{
		{
			name:   "multiply by one",
			scalar: new(fr.Element).SetOne(),
		},
		{
			name:   "multiply by two",
			scalar: new(fr.Element).SetInt64(2),
		},
		{
			name:   "multiply by random",
			scalar: func() *fr.Element { e := new(fr.Element); e.SetRandom(); return e }(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ScalarMulG1(G1Generator, tt.scalar)
			
			// Verify result is not zero (unless scalar is zero)
			// Note: Y is always 0 in our encoding, X contains the marshaled point
			if !tt.scalar.IsZero() && result.X.Cmp(big.NewInt(0)) == 0 {
				t.Error("Expected non-zero result for non-zero scalar")
			}

			// Verify deterministic results
			result2 := ScalarMulG1(G1Generator, tt.scalar)
			if result.X.Cmp(result2.X) != 0 {
				t.Error("Scalar multiplication should be deterministic")
			}
		})
	}
}

// TestScalarMulG2 tests scalar multiplication on G2
func Test_ScalarMulG2(t *testing.T) {
	scalar := new(fr.Element).SetInt64(42)
	
	result := ScalarMulG2(G2Generator, scalar)
	
	// Verify result is not zero
	// Note: Y is always 0 in our encoding, X contains the marshaled point
	if result.X.Cmp(big.NewInt(0)) == 0 {
		t.Error("Expected non-zero result")
	}
	
	// Verify deterministic
	result2 := ScalarMulG2(G2Generator, scalar)
	if !PointsEqualG2(result, result2) {
		t.Error("Scalar multiplication should be deterministic")
	}
}

// TestAddG1 tests point addition on G1
func Test_AddG1(t *testing.T) {
	// Create two points
	scalar1 := new(fr.Element).SetInt64(1)
	scalar2 := new(fr.Element).SetInt64(2)
	
	point1 := ScalarMulG1(G1Generator, scalar1)
	point2 := ScalarMulG1(G1Generator, scalar2)
	
	// Add them
	result := AddG1(point1, point2)
	
	// Verify commutativity: a + b = b + a
	result2 := AddG1(point2, point1)
	if result.X.Cmp(result2.X) != 0 {
		t.Error("Addition should be commutative")
	}
	
	// Verify adding identity
	identity := types.G1Point{X: big.NewInt(0), Y: big.NewInt(0)}
	result3 := AddG1(point1, identity)
	if result3.X.Cmp(point1.X) != 0 {
		t.Error("Adding identity should return original point")
	}
}

// TestAddG2 tests point addition on G2
func Test_AddG2(t *testing.T) {
	scalar1 := new(fr.Element).SetInt64(3)
	scalar2 := new(fr.Element).SetInt64(5)
	
	point1 := ScalarMulG2(G2Generator, scalar1)
	point2 := ScalarMulG2(G2Generator, scalar2)
	
	result := AddG2(point1, point2)
	
	// Verify commutativity
	result2 := AddG2(point2, point1)
	if !PointsEqualG2(result, result2) {
		t.Error("Addition should be commutative")
	}
}

// TestHashToG1 tests hashing to G1
func Test_HashToG1(t *testing.T) {
	tests := []struct {
		appID string
	}{
		{"test-app-1"},
		{"test-app-2"},
		{""},
		{"very-long-application-id-with-many-characters"},
	}

	for _, tt := range tests {
		t.Run(tt.appID, func(t *testing.T) {
			result := HashToG1(tt.appID)
			
			// Verify deterministic
			result2 := HashToG1(tt.appID)
			if result.X.Cmp(result2.X) != 0 {
				t.Error("Hash should be deterministic")
			}
			
			// Verify different inputs give different outputs
			if tt.appID != "" {
				different := HashToG1(tt.appID + "-modified")
				if result.X.Cmp(different.X) == 0 {
					t.Error("Different inputs should give different outputs")
				}
			}
		})
	}
}

// TestEvaluatePolynomial tests polynomial evaluation
func Test_EvaluatePolynomial(t *testing.T) {
	// Create polynomial: f(x) = 1 + 2x + 3x^2
	poly := make(polynomial.Polynomial, 3)
	poly[0].SetInt64(1) // constant term
	poly[1].SetInt64(2) // x coefficient
	poly[2].SetInt64(3) // x^2 coefficient
	
	tests := []struct {
		x        int
		expected int64
	}{
		{0, 1},  // f(0) = 1
		{1, 6},  // f(1) = 1 + 2 + 3 = 6
		{2, 17}, // f(2) = 1 + 4 + 12 = 17
	}
	
	for _, tt := range tests {
		t.Run(string(rune(tt.x)), func(t *testing.T) {
			result := EvaluatePolynomial(poly, tt.x)
			expected := new(fr.Element).SetInt64(tt.expected)
			
			if !result.Equal(expected) {
				t.Errorf("f(%d) = %v, expected %v", tt.x, result, expected)
			}
		})
	}
}

// TestComputeLagrangeCoefficient tests Lagrange coefficient computation
func Test_ComputeLagrangeCoefficient(t *testing.T) {
	participants := []int{1, 2, 3}
	
	// Test that sum of Lagrange coefficients at x=0 equals 1
	sum := new(fr.Element).SetZero()
	for _, i := range participants {
		lambda := ComputeLagrangeCoefficient(i, participants)
		sum.Add(sum, lambda)
	}
	
	// The sum should equal 1 for proper interpolation at x=0
	one := new(fr.Element).SetOne()
	if !sum.Equal(one) {
		t.Errorf("Sum of Lagrange coefficients should be 1, got %v", sum)
	}
}

// TestRecoverSecret tests secret recovery using Lagrange interpolation
func Test_RecoverSecret(t *testing.T) {
	// Create a polynomial with known secret
	secret := new(fr.Element).SetInt64(42)
	degree := 2
	
	// Create polynomial with secret as constant term
	poly := make(polynomial.Polynomial, degree+1)
	poly[0].Set(secret)
	for i := 1; i <= degree; i++ {
		poly[i].SetRandom()
	}
	
	// Generate shares
	shares := make(map[int]*fr.Element)
	for i := 1; i <= 3; i++ {
		shares[i] = EvaluatePolynomial(poly, i)
	}
	
	// Recover secret
	recovered := RecoverSecret(shares)
	
	if !recovered.Equal(secret) {
		t.Errorf("Failed to recover secret: got %v, expected %v", recovered, secret)
	}
	
	// Test with subset of shares (threshold)
	subset := make(map[int]*fr.Element)
	subset[1] = shares[1]
	subset[2] = shares[2]
	subset[3] = shares[3]
	
	recoveredSubset := RecoverSecret(subset)
	if !recoveredSubset.Equal(secret) {
		t.Error("Failed to recover secret with threshold shares")
	}
}

// TestHashCommitment tests commitment hashing
func Test_HashCommitment(t *testing.T) {
	// Create some test commitments
	commitments := []types.G2Point{
		{X: big.NewInt(1), Y: big.NewInt(2)},
		{X: big.NewInt(3), Y: big.NewInt(4)},
	}
	
	hash1 := HashCommitment(commitments)
	hash2 := HashCommitment(commitments)
	
	// Verify deterministic
	if hash1 != hash2 {
		t.Error("Hashing should be deterministic")
	}
	
	// Verify different inputs give different outputs
	commitments2 := []types.G2Point{
		{X: big.NewInt(5), Y: big.NewInt(6)},
	}
	hash3 := HashCommitment(commitments2)
	
	if hash1 == hash3 {
		t.Error("Different commitments should produce different hashes")
	}
}

// TestRecoverAppPrivateKey tests application private key recovery
func Test_RecoverAppPrivateKey(t *testing.T) {
	appID := "test-app"
	threshold := 3
	degree := threshold - 1
	
	// Create a polynomial for secret sharing
	secret := new(fr.Element).SetInt64(42)
	poly := make(polynomial.Polynomial, threshold)
	poly[0].Set(secret)
	for i := 1; i <= degree; i++ {
		poly[i].SetRandom()
	}
	
	// Create shares by evaluating polynomial
	shares := make(map[int]*fr.Element)
	for i := 1; i <= 5; i++ {
		shares[i] = EvaluatePolynomial(poly, i)
	}
	
	// Create partial signatures using the shares
	msgPoint := HashToG1(appID)
	partialSigs := make(map[int]types.G1Point)
	
	// Use first `threshold` shares
	for i := 1; i <= threshold; i++ {
		partialSigs[i] = ScalarMulG1(msgPoint, shares[i])
	}
	
	// Recover the key
	recovered := RecoverAppPrivateKey(appID, partialSigs, threshold)
	
	// The recovered key should be secret * H(appID)
	expected := ScalarMulG1(msgPoint, secret)
	
	if recovered.X.Cmp(expected.X) != 0 {
		t.Error("Recovered key doesn't match expected")
	}
	
	// Verify deterministic recovery
	recovered2 := RecoverAppPrivateKey(appID, partialSigs, threshold)
	if recovered.X.Cmp(recovered2.X) != 0 {
		t.Error("Recovery should be deterministic")
	}
}

// TestComputeMasterPublicKey tests master public key computation
func Test_ComputeMasterPublicKey(t *testing.T) {
	// Create test commitments using valid points (scalar multiples of generator)
	scalar1 := new(fr.Element).SetInt64(10)
	scalar2 := new(fr.Element).SetInt64(20)
	scalar3 := new(fr.Element).SetInt64(30)
	
	commitment1 := ScalarMulG2(G2Generator, scalar1)
	commitment2 := ScalarMulG2(G2Generator, scalar2)
	commitment3 := ScalarMulG2(G2Generator, scalar3)
	
	allCommitments := [][]types.G2Point{
		{commitment1},
		{commitment2},
		{commitment3},
	}
	
	masterPK := ComputeMasterPublicKey(allCommitments)
	
	// Verify it's the sum of first commitments
	expected := allCommitments[0][0]
	for i := 1; i < len(allCommitments); i++ {
		expected = AddG2(expected, allCommitments[i][0])
	}
	
	if !PointsEqualG2(masterPK, expected) {
		t.Error("Master public key should be sum of first commitments")
	}
}