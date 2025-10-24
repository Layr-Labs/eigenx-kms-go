package bls

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

func Test_BLSOperations(t *testing.T) {
	t.Run("PointOperations", func(t *testing.T) { testPointOperations(t) })
	t.Run("HashToPoint", func(t *testing.T) { testHashToPoint(t) })
	t.Run("SignatureScheme", func(t *testing.T) { testSignatureScheme(t) })
	t.Run("PolynomialSecretSharing", func(t *testing.T) { testPolynomialSecretSharing(t) })
	t.Run("ShareVerification", func(t *testing.T) { testShareVerification(t) })
	t.Run("LagrangeInterpolation", func(t *testing.T) { testLagrangeInterpolation(t) })
	t.Run("BigIntConversion", func(t *testing.T) { testBigIntConversion(t) })
	t.Run("PolynomialCommitments", func(t *testing.T) { testPolynomialCommitments(t) })
}

func testPointOperations(t *testing.T) {
	// Test scalar multiplication
	scalar := new(fr.Element).SetInt64(42)
	
	g1Result := ScalarMulG1(G1Generator, scalar)
	if g1Result.IsZero() {
		t.Error("ScalarMulG1 should not return zero for non-zero scalar")
	}
	
	g2Result := ScalarMulG2(G2Generator, scalar)
	if g2Result.IsZero() {
		t.Error("ScalarMulG2 should not return zero for non-zero scalar")
	}
	
	// Test addition
	scalar2 := new(fr.Element).SetInt64(7)
	g1Point2 := ScalarMulG1(G1Generator, scalar2)
	
	sum := AddG1(g1Result, g1Point2)
	if sum.IsZero() {
		t.Error("AddG1 should not return zero for non-zero points")
	}
	
	// Test commutativity
	sum2 := AddG1(g1Point2, g1Result)
	if !sum.Equal(sum2) {
		t.Error("Addition should be commutative")
	}
}

func testHashToPoint(t *testing.T) {
	msg := []byte("test message")
	
	g1Point := HashToG1(msg)
	if g1Point.IsZero() {
		t.Error("HashToG1 should not return zero")
	}
	
	// Test deterministic
	g1Point2 := HashToG1(msg)
	if !g1Point.Equal(g1Point2) {
		t.Error("HashToG1 should be deterministic")
	}
	
	// Different messages should give different points
	msg2 := []byte("different message")
	g1Point3 := HashToG1(msg2)
	if g1Point.Equal(g1Point3) {
		t.Error("Different messages should hash to different points")
	}
}

func testSignatureScheme(t *testing.T) {
	// Generate key pair
	sk, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	
	pkG1 := sk.GetPublicKeyG1()
	pkG2 := sk.GetPublicKeyG2()
	
	msg := []byte("message to sign")
	
	// Test G1 signature
	sigG1 := sk.SignG1(msg)
	valid := VerifyG1(pkG2, msg, sigG1)
	if !valid {
		t.Error("Valid G1 signature should verify")
	}
	
	// Test with wrong message
	wrongMsg := []byte("wrong message")
	valid = VerifyG1(pkG2, wrongMsg, sigG1)
	if valid {
		t.Error("Signature should not verify with wrong message")
	}
	
	// Test G2 signature
	sigG2 := sk.SignG2(msg)
	valid = VerifyG2(pkG1, msg, sigG2)
	if !valid {
		t.Error("Valid G2 signature should verify")
	}
}

func testPolynomialSecretSharing(t *testing.T) {
	// Create a secret
	secret := new(fr.Element).SetInt64(12345)
	degree := 2 // threshold = degree + 1 = 3
	
	// Generate polynomial with secret as constant term
	poly := GeneratePolynomial(secret, degree)
	
	// Verify constant term is the secret
	if !poly[0].Equal(secret) {
		t.Error("Polynomial constant term should be the secret")
	}
	
	// Generate shares for 5 participants
	participantIDs := []int{1, 2, 3, 4, 5}
	shares := GenerateShares(poly, participantIDs)
	
	if len(shares) != len(participantIDs) {
		t.Errorf("Expected %d shares, got %d", len(participantIDs), len(shares))
	}
	
	// Recover secret using threshold shares (any 3 shares)
	thresholdShares := make(map[int]*fr.Element)
	thresholdShares[1] = shares[1]
	thresholdShares[3] = shares[3]
	thresholdShares[5] = shares[5]
	
	recoveredSecret := RecoverSecret(thresholdShares)
	if !recoveredSecret.Equal(secret) {
		t.Error("Failed to recover secret from threshold shares")
	}
	
	// Try with different subset
	thresholdShares2 := make(map[int]*fr.Element)
	thresholdShares2[2] = shares[2]
	thresholdShares2[4] = shares[4]
	thresholdShares2[5] = shares[5]
	
	recoveredSecret2 := RecoverSecret(thresholdShares2)
	if !recoveredSecret2.Equal(secret) {
		t.Error("Failed to recover secret from different threshold shares")
	}
}

func testShareVerification(t *testing.T) {
	// Create polynomial
	secret := new(fr.Element).SetInt64(42)
	poly := GeneratePolynomial(secret, 2)
	
	// Create commitments
	commitments := CreateCommitments(poly)
	
	// Generate shares
	shares := GenerateShares(poly, []int{1, 2, 3, 4, 5})
	
	// Verify all shares
	for nodeID, share := range shares {
		valid := VerifyShare(nodeID, share, commitments)
		if !valid {
			t.Errorf("Valid share for node %d should verify", nodeID)
		}
	}
	
	// Test with invalid share
	invalidShare := new(fr.Element).SetInt64(999999)
	valid := VerifyShare(1, invalidShare, commitments)
	if valid {
		t.Error("Invalid share should not verify")
	}
}

func testLagrangeInterpolation(t *testing.T) {
	participants := []int{1, 3, 5}
	
	// Test that Lagrange coefficients sum to 1 at x=0
	sum := new(fr.Element).SetZero()
	for _, i := range participants {
		lambda := ComputeLagrangeCoefficient(i, participants)
		sum.Add(sum, lambda)
	}
	
	one := new(fr.Element).SetOne()
	if !sum.Equal(one) {
		t.Error("Lagrange coefficients should sum to 1")
	}
}

func testBigIntConversion(t *testing.T) {
	// Test G1 conversion
	scalar := new(fr.Element).SetInt64(123)
	g1Point := ScalarMulG1(G1Generator, scalar)
	
	x, y := g1Point.ToBigInt()
	t.Logf("G1 X bytes length: %d", len(x.Bytes()))
	t.Logf("G1 Y value: %v", y)
	
	g1Recovered, err := G1PointFromBigInt(x, y)
	if err != nil {
		t.Fatalf("Failed to recover G1 point: %v", err)
	}
	
	if !g1Point.Equal(g1Recovered) {
		t.Error("G1 point conversion should be lossless")
	}
	
	// Test G2 conversion
	g2Point := ScalarMulG2(G2Generator, scalar)
	
	x2, y2 := g2Point.ToBigInt()
	g2Recovered, err := G2PointFromBigInt(x2, y2)
	if err != nil {
		t.Fatalf("Failed to recover G2 point: %v", err)
	}
	
	if !g2Point.Equal(g2Recovered) {
		t.Error("G2 point conversion should be lossless")
	}
}

func testPolynomialCommitments(t *testing.T) {
	// Create two different polynomials with same degree
	poly1 := make(polynomial.Polynomial, 3)
	poly1[0].SetInt64(10)
	poly1[1].SetInt64(20)
	poly1[2].SetInt64(30)
	
	poly2 := make(polynomial.Polynomial, 3)
	poly2[0].SetInt64(10)
	poly2[1].SetInt64(25) // Different
	poly2[2].SetInt64(30)
	
	commitments1 := CreateCommitments(poly1)
	commitments2 := CreateCommitments(poly2)
	
	// Same constant terms should have same first commitment
	if !commitments1[0].Equal(commitments2[0]) {
		t.Error("Same constant terms should produce same commitment")
	}
	
	// Different coefficients should have different commitments
	if commitments1[1].Equal(commitments2[1]) {
		t.Error("Different coefficients should produce different commitments")
	}
}