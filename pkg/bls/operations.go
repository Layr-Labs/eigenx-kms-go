package bls

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var (
	// G1Generator is the generator point for G1
	G1Generator *G1Point
	// G2Generator is the generator point for G2
	G2Generator *G2Point
)

func init() {
	// Initialize generators
	_, _, g1Gen, g2Gen := bls12381.Generators()
	G1Generator = NewG1Point(&g1Gen)
	G2Generator = NewG2Point(&g2Gen)
}

// ScalarMulG1 performs scalar multiplication on G1
func ScalarMulG1(point *G1Point, scalar *fr.Element) *G1Point {
	if point == nil || point.point == nil || scalar == nil {
		return NewG1Point(new(bls12381.G1Affine).SetInfinity())
	}

	scalarBig := new(big.Int)
	scalar.BigInt(scalarBig)

	result := new(bls12381.G1Affine).ScalarMultiplication(point.point, scalarBig)
	return NewG1Point(result)
}

// ScalarMulG2 performs scalar multiplication on G2
func ScalarMulG2(point *G2Point, scalar *fr.Element) *G2Point {
	if point == nil || point.point == nil || scalar == nil {
		return NewG2Point(new(bls12381.G2Affine).SetInfinity())
	}

	scalarBig := new(big.Int)
	scalar.BigInt(scalarBig)

	result := new(bls12381.G2Affine).ScalarMultiplication(point.point, scalarBig)
	return NewG2Point(result)
}

// AddG1 adds two G1 points
func AddG1(a, b *G1Point) *G1Point {
	if a == nil || a.point == nil {
		if b == nil || b.point == nil {
			return NewG1Point(new(bls12381.G1Affine).SetInfinity())
		}
		return b
	}
	if b == nil || b.point == nil {
		return a
	}

	result := new(bls12381.G1Affine).Add(a.point, b.point)
	return NewG1Point(result)
}

// AddG2 adds two G2 points
func AddG2(a, b *G2Point) *G2Point {
	if a == nil || a.point == nil {
		if b == nil || b.point == nil {
			return NewG2Point(new(bls12381.G2Affine).SetInfinity())
		}
		return b
	}
	if b == nil || b.point == nil {
		return a
	}

	result := new(bls12381.G2Affine).Add(a.point, b.point)
	return NewG2Point(result)
}

// HashToG1 hashes a message to a G1 point using proper hash-to-curve
func HashToG1(msg []byte) *G1Point {
	g1Point, _ := bls12381.HashToG1(msg, []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"))
	return NewG1Point(&g1Point)
}

// HashToG2 hashes a message to a G2 point using proper hash-to-curve
func HashToG2(msg []byte) *G2Point {
	g2Point, _ := bls12381.HashToG2(msg, []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"))
	return NewG2Point(&g2Point)
}

// GeneratePrivateKey generates a random private key
func GeneratePrivateKey() (*PrivateKey, error) {
	scalar := new(fr.Element)
	if _, err := scalar.SetRandom(); err != nil {
		return nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}
	return &PrivateKey{scalar: scalar}, nil
}

// GeneratePrivateKeyFromSeed generates a deterministic private key from seed
func GeneratePrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) < 32 {
		return nil, fmt.Errorf("seed must be at least 32 bytes")
	}

	// Use the seed to generate a scalar in the field
	frOrder := fr.Modulus()
	sk := new(big.Int).SetBytes(seed[:32])
	sk.Mod(sk, frOrder)

	scalar := new(fr.Element)
	scalar.SetBigInt(sk)

	return &PrivateKey{scalar: scalar}, nil
}

// GetPublicKeyG1 derives the G1 public key from private key
func (sk *PrivateKey) GetPublicKeyG1() *PublicKeyG1 {
	pk := ScalarMulG1(G1Generator, sk.scalar)
	return &PublicKeyG1{point: pk.point}
}

// GetPublicKeyG2 derives the G2 public key from private key
func (sk *PrivateKey) GetPublicKeyG2() *PublicKeyG2 {
	pk := ScalarMulG2(G2Generator, sk.scalar)
	return &PublicKeyG2{point: pk.point}
}

// SignG1 signs a message by hashing to G1 and multiplying by private key
func (sk *PrivateKey) SignG1(msg []byte) *SignatureG1 {
	msgPoint := HashToG1(msg)
	sig := ScalarMulG1(msgPoint, sk.scalar)
	return &SignatureG1{point: sig.point}
}

// SignG2 signs a message by hashing to G2 and multiplying by private key
func (sk *PrivateKey) SignG2(msg []byte) *SignatureG2 {
	msgPoint := HashToG2(msg)
	sig := ScalarMulG2(msgPoint, sk.scalar)
	return &SignatureG2{point: sig.point}
}

// VerifyG1 verifies a G1 signature using pairing check
// e(sig, G2Generator) == e(H(msg), pubkey)
func VerifyG1(pubkey *PublicKeyG2, msg []byte, sig *SignatureG1) bool {
	if pubkey == nil || sig == nil {
		return false
	}

	msgPoint := HashToG1(msg)

	// Pairing check: e(sig, G2Gen) == e(H(msg), pubkey)
	var left, right bls12381.GT
	left, _ = bls12381.Pair([]bls12381.G1Affine{*sig.point}, []bls12381.G2Affine{*G2Generator.point})
	right, _ = bls12381.Pair([]bls12381.G1Affine{*msgPoint.point}, []bls12381.G2Affine{*pubkey.point})

	return left.Equal(&right)
}

// VerifyG2 verifies a G2 signature using pairing check
// e(G1Generator, sig) == e(pubkey, H(msg))
func VerifyG2(pubkey *PublicKeyG1, msg []byte, sig *SignatureG2) bool {
	if pubkey == nil || sig == nil {
		return false
	}

	msgPoint := HashToG2(msg)

	// Pairing check: e(G1Gen, sig) == e(pubkey, H(msg))
	var left, right bls12381.GT
	left, _ = bls12381.Pair([]bls12381.G1Affine{*G1Generator.point}, []bls12381.G2Affine{*sig.point})
	right, _ = bls12381.Pair([]bls12381.G1Affine{*pubkey.point}, []bls12381.G2Affine{*msgPoint.point})

	return left.Equal(&right)
}

// AggregateG1 aggregates multiple G1 signatures
func AggregateG1(sigs []*SignatureG1) *SignatureG1 {
	if len(sigs) == 0 {
		return &SignatureG1{point: new(bls12381.G1Affine).SetInfinity()}
	}

	result := NewG1Point(new(bls12381.G1Affine).SetInfinity())
	for _, sig := range sigs {
		if sig != nil {
			result = AddG1(result, NewG1Point(sig.point))
		}
	}

	return &SignatureG1{point: result.point}
}

// AggregateG2 aggregates multiple G2 signatures
func AggregateG2(sigs []*SignatureG2) *SignatureG2 {
	if len(sigs) == 0 {
		return &SignatureG2{point: new(bls12381.G2Affine).SetInfinity()}
	}

	result := NewG2Point(new(bls12381.G2Affine).SetInfinity())
	for _, sig := range sigs {
		if sig != nil {
			result = AddG2(result, NewG2Point(sig.point))
		}
	}

	return &SignatureG2{point: result.point}
}

// GetScalar returns the private key scalar (for DKG/reshare operations)
func (sk *PrivateKey) GetScalar() *fr.Element {
	return sk.scalar
}

// SetScalar sets the private key scalar (for DKG/reshare operations)
func (sk *PrivateKey) SetScalar(scalar *fr.Element) {
	sk.scalar = new(fr.Element).Set(scalar)
}

// NewPrivateKeyFromScalar creates a private key from a scalar
func NewPrivateKeyFromScalar(scalar *fr.Element) *PrivateKey {
	return &PrivateKey{scalar: new(fr.Element).Set(scalar)}
}
