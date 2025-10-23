package types

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)


// KeyShareVersion represents a versioned set of key shares
type KeyShareVersion struct {
	Version        int64       // Unix timestamp epoch of when this version was created
	PrivateShare   *fr.Element // This node's private key share
	Commitments    []G2Point   // Public commitments (in G2 for master public key)
	IsActive       bool        // Whether this version is the active one
	ParticipantIDs []int       // Which participants were in the operator set for this version
}

// G1Point represents a point on BLS12-381 G1 (used for signatures)
type G1Point struct {
	X, Y *big.Int
}

// G2Point represents a point on BLS12-381 G2 (used for public keys)
type G2Point struct {
	X, Y *big.Int
}

// Acknowledgement is signed by players to prevent dealer equivocation
type Acknowledgement struct {
	DealerID       int
	PlayerID       int
	CommitmentHash [32]byte
	Signature      []byte // Sign(p2p_privkey, dealer_id || commitment_hash)
}

// CompletionSignature signals reshare completion
type CompletionSignature struct {
	NodeID         int
	Epoch          int64
	CommitmentHash [32]byte
	Signature      []byte // Sign(p2p_privkey, epoch || commitment_hash)
}

// AppSignRequest represents a request to sign for an application
type AppSignRequest struct {
	AppID           string
	AttestationTime int64
}

// AppSignResponse contains a partial signature from a node
type AppSignResponse struct {
	OperatorAddress  string  // Operator address instead of NodeID
	PartialSignature G1Point
}

// SecretsRequestV1 represents a request for application secrets
type SecretsRequestV1 struct {
	AppID        string `json:"app_id"`
	Attestation  []byte `json:"attestation"`     // GoogleCS attestation (stubbed)
	RSAPubKeyTmp []byte `json:"rsa_pubkey_tmp"`  // Ephemeral RSA public key
	AttestTime   int64  `json:"attest_time"`     // For key versioning
}

// SecretsResponseV1 represents the response with encrypted secrets
type SecretsResponseV1 struct {
	EncryptedEnv        string `json:"encrypted_env"`         // AES encrypted env vars
	PublicEnv           string `json:"public_env"`            // Plain text env
	EncryptedPartialSig []byte `json:"encrypted_partial_sig"` // RSA encrypted partial sig
}

// AttestationClaims represents parsed attestation data
type AttestationClaims struct {
	AppID       string
	ImageDigest string
	IssuedAt    int64
	PublicKey   []byte
}

// Release represents application release data from on-chain registry
type Release struct {
	ImageDigest  string `json:"image_digest"`
	EncryptedEnv string `json:"encrypted_env"`
	PublicEnv    string `json:"public_env"`
	Timestamp    int64  `json:"timestamp"`
}