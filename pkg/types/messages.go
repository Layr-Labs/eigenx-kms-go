package types

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
)

// AuthenticatedMessage wraps all inter-node communications with cryptographic authentication
type AuthenticatedMessage struct {
	Payload   []byte    `json:"payload"`   // Raw message bytes (contains from/to addresses)
	Hash      [32]byte  `json:"hash"`      // keccak256(payload)
	Signature []byte    `json:"signature"` // BN254 signature over hash
}

// SerializedFrElement wraps a field element for JSON serialization
type SerializedFrElement struct {
	Data string
}

// ShareMessage is sent between nodes during DKG/Reshare
type ShareMessage struct {
	FromOperatorAddress common.Address        `json:"fromOperatorAddress"`
	ToOperatorAddress   common.Address        `json:"toOperatorAddress"`
	Share              *SerializedFrElement `json:"share"`
}

// CommitmentMessage broadcasts commitments to all nodes
type CommitmentMessage struct {
	FromOperatorAddress common.Address `json:"fromOperatorAddress"`
	ToOperatorAddress   common.Address `json:"toOperatorAddress"` // 0x0 for broadcast
	Commitments        []G2Point      `json:"commitments"`
}

// AcknowledgementMessage contains an acknowledgement
type AcknowledgementMessage struct {
	FromOperatorAddress common.Address   `json:"fromOperatorAddress"`
	ToOperatorAddress   common.Address   `json:"toOperatorAddress"`
	Ack                *Acknowledgement `json:"ack"`
}

// CompletionMessage signals completion of reshare
type CompletionMessage struct {
	FromOperatorAddress common.Address        `json:"fromOperatorAddress"`
	ToOperatorAddress   common.Address        `json:"toOperatorAddress"`
	Completion         *CompletionSignature `json:"completion"`
}

// SerializeFr serializes a field element
func SerializeFr(elem *fr.Element) *SerializedFrElement {
	return &SerializedFrElement{Data: elem.String()}
}

// DeserializeFr deserializes a field element
func DeserializeFr(s *SerializedFrElement) *fr.Element {
	elem := new(fr.Element)
	_, _ = elem.SetString(s.Data)
	return elem
}