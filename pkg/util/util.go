package util

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Map applies a transformation function to each element of a slice and returns a new slice
// with the transformed values. This is a generic implementation of the map higher-order function.
//
// Type Parameters:
//   - A: The type of elements in the input slice
//   - B: The type of elements in the output slice
//
// Parameters:
//   - coll: The input slice to transform
//   - mapper: Function that transforms each element and receives the element's index
//
// Returns:
//   - []B: A new slice containing the transformed elements
func Map[A any, B any](coll []A, mapper func(i A, index uint64) B) []B {
	out := make([]B, len(coll))
	for i, item := range coll {
		out[i] = mapper(item, uint64(i))
	}
	return out
}

// Filter creates a new slice containing only the elements from the input slice
// that satisfy the provided criteria function.
//
// Type Parameters:
//   - A: The type of elements in the slice
//
// Parameters:
//   - coll: The input slice to filter
//   - criteria: Function that determines whether an element should be included
//
// Returns:
//   - []A: A new slice containing only the elements that satisfy the criteria
func Filter[A any](coll []A, criteria func(i A) bool) []A {
	out := []A{}
	for _, item := range coll {
		if criteria(item) {
			out = append(out, item)
		}
	}
	return out
}

// Reduce applies a function against an accumulator and each element in the slice
// to reduce it to a single value.
//
// Type Parameters:
//   - A: The type of elements in the input slice
//   - B: The type of the accumulated result
//
// Parameters:
//   - coll: The input slice to reduce
//   - processor: Function that combines the accumulator with each element
//   - initialState: The initial value of the accumulator
//
// Returns:
//   - B: The final accumulated value
func Reduce[A any, B any](coll []A, processor func(accum B, next A) B, initialState B) B {
	val := initialState
	for _, item := range coll {
		val = processor(val, item)
	}
	return val
}

func StringToECDSAPrivateKey(pk string) (*ecdsa.PrivateKey, error) {
	if len(pk) == 0 {
		return nil, fmt.Errorf("private key is empty")
	}
	pk = strings.TrimPrefix(pk, "0x")

	privateKey, err := crypto.HexToECDSA(pk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert hex string to ECDSA private key: %v", err)
	}
	return privateKey, nil
}

func DeriveAddress(pk ecdsa.PublicKey) common.Address {
	return crypto.PubkeyToAddress(pk)
}

func DeriveAddressFromECDSAPrivateKeyString(key string) (common.Address, error) {
	pk, err := StringToECDSAPrivateKey(key)
	if err != nil {
		return common.Address{0}, fmt.Errorf("failed to convert operator private key: %v", err)
	}
	return DeriveAddressFromECDSAPrivateKey(pk)
}

func DeriveAddressFromECDSAPrivateKey(pk *ecdsa.PrivateKey) (common.Address, error) {
	if pk == nil {
		return common.Address{0}, fmt.Errorf("private key is nil")
	}
	return DeriveAddress(pk.PublicKey), nil
}

// ValidateAppID validates that an application ID meets minimum requirements
// AppID must be at least 5 characters long
func ValidateAppID(appID string) error {
	if appID == "" {
		return fmt.Errorf("appID is empty")
	}
	if len(appID) < 5 {
		return fmt.Errorf("appID is too short (minimum 5 characters)")
	}
	return nil
}

// AddressToNodeID converts an Ethereum address into a deterministic node ID.
// The node ID is derived from the keccak256 hash of the address, matching the on-chain encoding.
// If n = 1,000,000 (# of operators): probability of collision ≈ 5.4 × 10^-8 (≈ 1 in 1.9 × 10^7)
func AddressToNodeID(address common.Address) int64 {
	h := crypto.Keccak256Hash(address.Bytes())
	low64 := binary.BigEndian.Uint64(h[24:32]) // matches Big().Uint64() (low 64 bits)
	low63 := low64 & ((uint64(1) << 63) - 1)   // force non-negative
	return int64(low63)
}
