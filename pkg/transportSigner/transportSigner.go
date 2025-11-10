package transportSigner

type SignedMessage struct {
	Payload   []byte   `json:"payload"`   // Raw message bytes (contains from/to addresses)
	Hash      [32]byte `json:"hash"`      // keccak256(payload)
	Signature []byte   `json:"signature"` // BN254 signature over hash
}

type ITransportSigner interface {
	CreateAuthenticatedMessage(data []byte) (*SignedMessage, error)
}
