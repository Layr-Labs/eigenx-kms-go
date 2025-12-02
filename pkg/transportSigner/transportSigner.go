package transportSigner

type SignedMessage struct {
	Payload   []byte   `json:"payload"`   // Raw message bytes (contains from/to addresses)
	Hash      [32]byte `json:"hash"`      // keccak256(payload)
	Signature []byte   `json:"signature"` // ECDSA signature over hash
}

type ITransportSigner interface {
	CreateAuthenticatedMessage(data []byte) (*SignedMessage, error)
	SignMessage(data []byte) ([]byte, error) // Sign raw message bytes, returns signature
}
