package types

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

// SerializedFrElement wraps a field element for JSON serialization
type SerializedFrElement struct {
	Data string
}

// ShareMessage is sent between nodes during DKG/Reshare
type ShareMessage struct {
	FromID int
	ToID   int
	Share  *SerializedFrElement
}

// CommitmentMessage broadcasts commitments to all nodes
type CommitmentMessage struct {
	FromID      int
	Commitments []G2Point
}

// AcknowledgementMessage contains an acknowledgement
type AcknowledgementMessage struct {
	Ack *Acknowledgement
}

// CompletionMessage signals completion of reshare
type CompletionMessage struct {
	Completion *CompletionSignature
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