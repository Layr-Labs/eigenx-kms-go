package bls

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var (
	// G1Generator is the generator point for G1 in affine form
	G1Generator *G1Point
	// G2Generator is the generator point for G2 in affine form
	G2Generator *G2Point
)

const (
	// hashToG1SignatureDST is the standard BLS signature domain.
	hashToG1SignatureDST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
	// hashToG1IBEDST is the IBE identity hashing domain for EigenX.
	hashToG1IBEDST = "EIGENX_KMS_IBE_BLS12381G1_XMD:SHA-256_SSWU_RO_"
)

func init() {
	// Initialize generators
	_, _, g1Gen, g2Gen := bls12381.Generators()
	G1Generator = NewG1Point(&g1Gen)
	G2Generator = NewG2Point(&g2Gen)
}

// ScalarMulG1 performs scalar multiplication on G1
// Warning: This does not check if the point is at infinity or generator. The caller should validate these conditions first if needed.
func ScalarMulG1(point *G1Point, scalar *fr.Element) (*G1Point, error) {

	// check if the point is in subgroup and on curve else return an error
	// even though the function is called IsInSubGroup, it checks if the point is on curve and in subgroup
	if !point.point.IsInSubGroup() {
		return nil, fmt.Errorf("point is not in subgroup or curve")
	}

	if point == nil || point.point == nil || scalar == nil {
		return nil, fmt.Errorf("invalid point or scalar")
	}

	scalarBig := new(big.Int)
	scalar.BigInt(scalarBig)

	result := new(bls12381.G1Affine).ScalarMultiplication(point.point, scalarBig)
	return NewG1Point(result), nil
}

// ScalarMulG2 performs scalar multiplication on G2
// Warning: This does not check if the point is at infinity or generator. The caller should validate these conditions first if needed.
func ScalarMulG2(point *G2Point, scalar *fr.Element) (*G2Point, error) {
	// audit: point should be checked if it's on curve and in subgroup and not generator or infinity
	//        and make sure they are valid cases

	if !point.point.IsInSubGroup() {
		return nil, fmt.Errorf("point is not in subgroup or curve")
	}

	if point == nil || point.point == nil || scalar == nil {
		return nil, fmt.Errorf("invalid point or scalar")
	}

	scalarBig := new(big.Int)
	scalar.BigInt(scalarBig)

	result := new(bls12381.G2Affine).ScalarMultiplication(point.point, scalarBig)
	return NewG2Point(result), nil
}

// AddG1 adds two G1 points
// Warning: This does not check if the point is at infinity or generator. The caller should validate these conditions first if needed.
func AddG1(a, b *G1Point) (*G1Point, error) {

	if a == nil || a.point == nil || b == nil || b.point == nil {
		return nil, fmt.Errorf("a or b G1 point passed in was nil")
	}

	if !a.point.IsInSubGroup() {
		return nil, fmt.Errorf("a is not in subgroup or curve")
	}
	if !b.point.IsInSubGroup() {
		return nil, fmt.Errorf("b is not in subgroup or curve")
	}

	result := new(bls12381.G1Affine).Add(a.point, b.point)
	return NewG1Point(result), nil
}

// AddG2 adds two G2 points
// Warning: This does not check if the point is at infinity or generator. The caller should validate these conditions first if needed.
func AddG2(a, b *G2Point) (*G2Point, error) {

	if a == nil || a.point == nil || b == nil || b.point == nil {
		return nil, fmt.Errorf("a or b G2 point passed in was nil")
	}

	if !a.point.IsInSubGroup() {
		return nil, fmt.Errorf("a is not in subgroup or curve")
	}
	if !b.point.IsInSubGroup() {
		return nil, fmt.Errorf("b is not in subgroup or curve")
	}

	result := new(bls12381.G2Affine).Add(a.point, b.point)
	return NewG2Point(result), nil
}

// HashToG1 hashes a message to a G1 point using proper hash-to-curve
func HashToG1(msg []byte) (*G1Point, error) {
	return HashToG1ForSignature(msg)
}

// HashToG1ForSignature hashes a message to G1 for BLS signatures.
func HashToG1ForSignature(msg []byte) (*G1Point, error) {
	g1Point, err := bls12381.HashToG1(msg, []byte(hashToG1SignatureDST))
	if err != nil {
		return nil, fmt.Errorf("failed to hash to G1: %w", err)
	}
	return NewG1Point(&g1Point), nil
}

// HashToG1ForIBE hashes an identity to G1 for IBE key derivation.
func HashToG1ForIBE(identity []byte) (*G1Point, error) {
	g1Point, err := bls12381.HashToG1(identity, []byte(hashToG1IBEDST))
	if err != nil {
		return nil, fmt.Errorf("failed to hash to G1: %w", err)
	}
	return NewG1Point(&g1Point), nil
}

// HashToG2 hashes a message to a G2 point using proper hash-to-curve
func HashToG2(msg []byte) (*G2Point, error) {
	g2Point, err := bls12381.HashToG2(msg, []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"))
	if err != nil {
		return nil, fmt.Errorf("failed to hash to G2: %w", err)
	}
	return NewG2Point(&g2Point), nil
}

// GeneratePrivateKey generates a random private key
func GeneratePrivateKey() (*PrivateKey, error) {
	// audit: use the gomodule to keep this either only in memory or avoid writing to file system in swap stages.
	//        there is a library for this.
	scalar := new(fr.Element)
	if _, err := scalar.SetRandom(); err != nil {
		return nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}
	return &PrivateKey{scalar: scalar}, nil
}

// GeneratePrivateKeyFromSeed generates a deterministic private key from seed
func GeneratePrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	// audit: use the gomodule to keep this either only in memory or avoid writing to file system in swap stages.
	//        there is a library for this.
	if len(seed) < 32 {
		return nil, fmt.Errorf("seed must be at least 32 bytes")
	}

	// Use the seed to generate a scalar in the field
	frOrder := fr.Modulus()
	sk := new(big.Int).SetBytes(seed[:32])
	sk.Mod(sk, frOrder)

	// audit: check to make sure that the sk is not some basic element like 0 or 1 or -1 or other basic elements.
	scalar := new(fr.Element)
	scalar.SetBigInt(sk)

	return &PrivateKey{scalar: scalar}, nil
}

// GetPublicKeyG1 derives the G1 public key from private key
func (sk *PrivateKey) GetPublicKeyG1() *PublicKeyG1 {
	pk, _ := ScalarMulG1(G1Generator, sk.scalar)
	return &PublicKeyG1{point: pk.point}
}

// GetPublicKeyG2 derives the G2 public key from private key
func (sk *PrivateKey) GetPublicKeyG2() *PublicKeyG2 {
	pk, _ := ScalarMulG2(G2Generator, sk.scalar)
	return &PublicKeyG2{point: pk.point}
}

// SignG1 signs a message by hashing to G1 and multiplying by private key
func (sk *PrivateKey) SignG1(msg []byte) (*SignatureG1, error) {
	msgPoint, err := HashToG1ForSignature(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to hash to G1: %w", err)
	}
	sig, err := ScalarMulG1(msgPoint, sk.scalar)
	if err != nil {
		return nil, fmt.Errorf("failed to sign G1: %w", err)
	}
	return &SignatureG1{point: sig.point}, nil
}

// SignG2 signs a message by hashing to G2 and multiplying by private key
func (sk *PrivateKey) SignG2(msg []byte) (*SignatureG2, error) {
	msgPoint, err := HashToG2(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to hash to G2: %w", err)
	}
	sig, err := ScalarMulG2(msgPoint, sk.scalar)
	if err != nil {
		return nil, fmt.Errorf("failed to sign G2: %w", err)
	}
	return &SignatureG2{point: sig.point}, nil
}

// VerifyG1 verifies a G1 signature using pairing check
// e(sig, G2Generator) == e(H(msg), pubkey)
func VerifyG1(pubkey *PublicKeyG2, msg []byte, sig *SignatureG1) (bool, error) {
	if pubkey == nil || sig == nil {
		return false, fmt.Errorf("pubkey or sig is nil")
	}

	msgPoint, err := HashToG1ForSignature(msg)
	if err != nil {
		return false, fmt.Errorf("failed to hash to G1: %w", err)
	}

	// Pairing check: e(sig, G2Gen) == e(H(msg), pubkey)
	var left, right bls12381.GT
	left, _ = bls12381.Pair([]bls12381.G1Affine{*sig.point}, []bls12381.G2Affine{*G2Generator.point})
	right, _ = bls12381.Pair([]bls12381.G1Affine{*msgPoint.point}, []bls12381.G2Affine{*pubkey.point})

	return left.Equal(&right), nil
}

// VerifyG2 verifies a G2 signature using pairing check
// e(G1Generator, sig) == e(pubkey, H(msg))
func VerifyG2(pubkey *PublicKeyG1, msg []byte, sig *SignatureG2) (bool, error) {
	if pubkey == nil || sig == nil {
		return false, fmt.Errorf("pubkey or sig is nil")
	}

	msgPoint, err := HashToG2(msg)
	if err != nil {
		return false, fmt.Errorf("failed to hash to G2: %w", err)
	}

	// Pairing check: e(G1Gen, sig) == e(pubkey, H(msg))
	var left, right bls12381.GT
	left, _ = bls12381.Pair([]bls12381.G1Affine{*G1Generator.point}, []bls12381.G2Affine{*sig.point})
	right, _ = bls12381.Pair([]bls12381.G1Affine{*pubkey.point}, []bls12381.G2Affine{*msgPoint.point})

	return left.Equal(&right), nil
}

// AggregateG1 aggregates multiple G1 signatures
func AggregateG1(sigs []*SignatureG1) *SignatureG1 {
	if len(sigs) == 0 {
		return &SignatureG1{point: new(bls12381.G1Affine).SetInfinity()}
	}

	result := NewG1Point(new(bls12381.G1Affine).SetInfinity())
	for _, sig := range sigs {
		if sig != nil {
			result, _ = AddG1(result, NewG1Point(sig.point))
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
			result, _ = AddG2(result, NewG2Point(sig.point))
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
