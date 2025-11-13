package bls

import (
	"errors"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// PrivateKey represents a BLS private key
type PrivateKey struct {
	scalar *fr.Element
}

// PublicKeyG1 represents a BLS public key in G1
type PublicKeyG1 struct {
	point *bls12381.G1Affine
}

// PublicKeyG2 represents a BLS public key in G2
type PublicKeyG2 struct {
	point *bls12381.G2Affine
}

// SignatureG1 represents a BLS signature in G1
type SignatureG1 struct {
	point *bls12381.G1Affine
}

// SignatureG2 represents a BLS signature in G2
type SignatureG2 struct {
	point *bls12381.G2Affine
}

// G1Point represents a point on the G1 curve with proper serialization
type G1Point struct {
	point *bls12381.G1Affine
}

// G2Point represents a point on the G2 curve with proper serialization
type G2Point struct {
	point *bls12381.G2Affine
}

// NewG1Point creates a new G1Point from a gnark G1Affine point
func NewG1Point(p *bls12381.G1Affine) *G1Point {
	return &G1Point{point: p}
}

// NewG2Point creates a new G2Point from a gnark G2Affine point
func NewG2Point(p *bls12381.G2Affine) *G2Point {
	return &G2Point{point: p}
}

// Marshal serializes the G1Point to bytes (compressed format)
func (p *G1Point) Marshal() []byte {
	if p.point == nil {
		return make([]byte, 48)
	}
	bytes := p.point.Bytes() // Returns [48]byte
	return bytes[:]          // Convert to slice
}

// Unmarshal deserializes bytes to G1Point
// This is in the compressed format.
func (p *G1Point) Unmarshal(data []byte) error {
	if p.point == nil {
		p.point = new(bls12381.G1Affine)
	}
	_, err := p.point.SetBytes(data) // Use SetBytes for compressed format
	return err
}

// Marshal serializes the G2Point to bytes (compressed format)
func (p *G2Point) Marshal() []byte {
	if p.point == nil {
		return make([]byte, 96)
	}
	bytes := p.point.Bytes() // Returns [96]byte
	return bytes[:]          // Convert to slice
}

// Unmarshal deserializes bytes to G2Point
// This is in the compressed format.
func (p *G2Point) Unmarshal(data []byte) error {
	if p.point == nil {
		p.point = new(bls12381.G2Affine)
	}
	_, err := p.point.SetBytes(data) // Use SetBytes for compressed format
	return err
}

// IsZero checks if the G1Point is the identity/zero point
func (p *G1Point) IsZero() bool {
	if p.point == nil {
		return true
	}
	return p.point.IsInfinity()
}

// IsZero checks if the G2Point is the identity/zero point
func (p *G2Point) IsZero() bool {
	if p.point == nil {
		return true
	}
	return p.point.IsInfinity()
}

// Equal checks if two G1Points are equal
func (p *G1Point) Equal(other *G1Point) bool {
	if p.point == nil && other.point == nil {
		return false
	}
	if p.point == nil || other.point == nil {
		return false
	}
	return p.point.Equal(other.point)
}

// Equal checks if two G2Points are equal
func (p *G2Point) Equal(other *G2Point) bool {
	if p.point == nil && other.point == nil {
		return false
	}
	if p.point == nil || other.point == nil {
		return false
	}
	return p.point.Equal(other.point)
}

// ToBigInt converts G1Point to big integers (for legacy compatibility)
func (p *G1Point) ToBigInt() (*big.Int, *big.Int) {
	if p.IsZero() {
		return big.NewInt(0), big.NewInt(0)
	}
	bytes := p.Marshal()
	// Store full marshaled bytes as X, Y=0 for compatibility
	// Note: SetBytes drops leading zeros, so we need to preserve the length
	return new(big.Int).SetBytes(bytes), big.NewInt(0)
}

// ToBigInt converts G2Point to big integers (for legacy compatibility)
func (p *G2Point) ToBigInt() (*big.Int, *big.Int) {
	bytes := p.Marshal()
	// Store full marshaled bytes as X, Y=0 for compatibility
	return new(big.Int).SetBytes(bytes), big.NewInt(0)
}

// ToAffine converts G1Point to a G1Affine point
func (p *G1Point) ToAffine() *bls12381.G1Affine {
	return p.point
}

// ToAffine converts G2Point to a G2Affine point
func (p *G2Point) ToAffine() *bls12381.G2Affine {
	return p.point
}

// NewG1PointFromCompressedBytes creates a G1Point from compressed bytes
func NewG1PointFromCompressedBytes(compressedBytes []byte) (*G1Point, error) {
	point := new(bls12381.G1Affine)
	_, err := point.SetBytes(compressedBytes)
	if err != nil {
		return nil, err
	}
	return NewG1Point(point), nil
}

// NewG2PointFromCompressedBytes creates a G2Point from compressed bytes
func NewG2PointFromCompressedBytes(compressedBytes []byte) (*G2Point, error) {
	point := new(bls12381.G2Affine)
	_, err := point.SetBytes(compressedBytes)
	if err != nil {
		return nil, err
	}
	return NewG2Point(point), nil
}

// G1PointFromBigInt creates a G1Point from big integers (for legacy compatibility)
// audit: this function is weird, we should probably split it to requiring only x and both x and y.
func G1PointFromBigInt(x, y *big.Int) (*G1Point, error) {
	// X contains the full marshaled bytes in our encoding
	if x == nil {
		return nil, errors.New("x is nil or zero")
	}

	if x.Sign() == 0 {
		// Return identity point
		p := new(bls12381.G1Affine).SetInfinity()
		return NewG1Point(p), nil
	}

	// X should contain exactly the marshaled bytes
	xBytes := x.Bytes()
	var bytes []byte

	if len(xBytes) < 48 {
		// Pad with zeros at the beginning
		// big.int strips leading zeros, so we need to pad with zeros at the beginning
		bytes = make([]byte, 48)
		copy(bytes[48-len(xBytes):], xBytes)
	} else {
		// Too long, use as-is (might be compressed format)
		bytes = xBytes
	}

	point := new(bls12381.G1Affine)
	_, err := point.SetBytes(bytes)
	if err != nil {
		return nil, err
	}
	return NewG1Point(point), nil
}

// G2PointFromBigInt creates a G2Point from big integers (for legacy compatibility)
// audit: this function is weird, we should probably split it to requiring only x and both x and y.
func G2PointFromBigInt(x, y *big.Int) (*G2Point, error) {
	// X contains the full marshaled bytes in our encoding
	if x == nil {
		return nil, errors.New("x is nil or zero")
	}

	if x.Sign() == 0 {
		// Return identity point
		p := new(bls12381.G2Affine).SetInfinity()
		return NewG2Point(p), nil
	}

	// X should contain exactly the marshaled bytes
	xBytes := x.Bytes()
	var bytes []byte

	if len(xBytes) < 96 {
		// Pad with zeros at the beginning
		bytes = make([]byte, 96)
		copy(bytes[96-len(xBytes):], xBytes)
	} else {
		// Too long, use as-is (might be compressed format)
		bytes = xBytes
	}

	point := new(bls12381.G2Affine)
	_, err := point.SetBytes(bytes)
	if err != nil {
		return nil, err
	}
	return NewG2Point(point), nil
}
