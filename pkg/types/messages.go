package types

import (
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

// ShareRequestMessage requests, on demand, the reshare share that `Dealer` generated
// for `Requester` in session `SessionTimestamp`. Used during dealer-set-agreement
// finalization when a node is missing a share for a dealer that the on-chain registry
// shows did participate. The dealer responds with an authenticated ShareMessage
// containing only the requester's share. See docs/011_reshareDealerSetAgreement.md.
type ShareRequestMessage struct {
	FromOperatorAddress common.Address `json:"fromOperatorAddress"` // requester
	ToOperatorAddress   common.Address `json:"toOperatorAddress"`   // dealer being asked
	SessionTimestamp    int64          `json:"sessionTimestamp"`
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

// SerializeFr serializes a field element
func SerializeFr(elem *fr.Element) *SerializedFrElement {
	return &SerializedFrElement{Data: elem.String()}
}

// DeserializeFr deserializes a field element
func DeserializeFr(s *SerializedFrElement) *fr.Element {
	if s == nil {
		return nil
	}
	elem := new(fr.Element)
	_, _ = elem.SetString(s.Data)
	return elem
}
