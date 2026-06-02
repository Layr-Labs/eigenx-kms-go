package types

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
)

// AuthenticatedMessage wraps all inter-node communications with cryptographic authentication
type AuthenticatedMessage struct {
	Payload   []byte   `json:"payload"`   // Raw message bytes (contains from/to addresses)
	Hash      [32]byte `json:"hash"`      // keccak256(payload)
	Signature []byte   `json:"signature"` // BN254 signature over hash
}

// SerializedFrElement wraps a field element for JSON serialization
type SerializedFrElement struct {
	Data string
}

// ShareMessage is sent between nodes during DKG/Reshare
type ShareMessage struct {
	FromOperatorAddress common.Address       `json:"fromOperatorAddress"`
	ToOperatorAddress   common.Address       `json:"toOperatorAddress"`
	SessionTimestamp    int64                `json:"sessionTimestamp"`
	Share               *SerializedFrElement `json:"share"`
}

// CommitmentMessage broadcasts commitments to all nodes
type CommitmentMessage struct {
	FromOperatorAddress common.Address `json:"fromOperatorAddress"`
	ToOperatorAddress   common.Address `json:"toOperatorAddress"` // 0x0 for broadcast
	SessionTimestamp    int64          `json:"sessionTimestamp"`
	Commitments         []G2Point      `json:"commitments"`
}

// AcknowledgementMessage contains an acknowledgement
type AcknowledgementMessage struct {
	FromOperatorAddress common.Address   `json:"fromOperatorAddress"`
	ToOperatorAddress   common.Address   `json:"toOperatorAddress"`
	SessionTimestamp    int64            `json:"sessionTimestamp"`
	Ack                 *Acknowledgement `json:"ack"`
}

// SerializeFr serializes a field element. Panics if elem is nil.
func SerializeFr(elem *fr.Element) *SerializedFrElement {
	if elem == nil {
		panic("SerializeFr: cannot serialize nil field element")
	}
	return &SerializedFrElement{Data: elem.String()}
}

// DeserializeFr deserializes a field element.
// Returns an error if the input is nil, malformed, or >= the BLS12-381 Fr field order
// (gnark-crypto silently reduces mod p, which would corrupt protocol computations).
func DeserializeFr(s *SerializedFrElement) (*fr.Element, error) {
	if s == nil {
		return nil, fmt.Errorf("DeserializeFr: cannot deserialize nil field element")
	}

	// Parse the decimal string into a big.Int first to check range.
	raw, ok := new(big.Int).SetString(s.Data, 10)
	if !ok {
		return nil, fmt.Errorf("DeserializeFr: invalid decimal string")
	}
	if raw.Sign() < 0 || raw.Cmp(fr.Modulus()) >= 0 {
		return nil, fmt.Errorf("DeserializeFr: value out of field range")
	}

	elem := new(fr.Element)
	elem.SetBigInt(raw)
	return elem, nil
}
