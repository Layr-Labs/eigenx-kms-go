package types

import (
	"bytes"
	"encoding/json"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/bls"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
)

const KMSJWTAudience = "EigenX KMS"

// KeyShareVersion represents a versioned set of key shares
type KeyShareVersion struct {
	Version         int64       // Unix timestamp (seconds) of the block that triggered this key version
	PrivateShare    *fr.Element // This node's private key share
	Commitments     []G2Point   // Public commitments (in G2 for master public key)
	MasterPublicKey *G2Point    // Pre-computed master public key for threshold agreement
	IsActive        bool        // Whether this version is the active one
	ParticipantIDs  []int64     // Which participants were in the operator set for this version
}

// MarshalJSON implements json.Marshaler. The Alias type strips the method
// set so default encoding is used, avoiding infinite recursion.
// TODO: wrap PrivateShare with an encrypted field before persisting.
func (ksv *KeyShareVersion) MarshalJSON() ([]byte, error) {
	type Alias KeyShareVersion
	return json.Marshal((*Alias)(ksv))
}

// UnmarshalJSON implements json.Unmarshaler. The Alias type strips the method
// set so default decoding is used, avoiding infinite recursion.
func (ksv *KeyShareVersion) UnmarshalJSON(data []byte) error {
	type Alias KeyShareVersion
	return json.Unmarshal(data, (*Alias)(ksv))
}

// G1Point represents a point on BLS12-381 G1 (used for signatures)
type G1Point struct {
	CompressedBytes []byte
}

// ZeroG1Point is the zero point on the G1 curve
func ZeroG1Point() *G1Point {
	point := new(bls12381.G1Affine)
	point.SetInfinity()
	return &G1Point{CompressedBytes: point.Marshal()}
}

// ZeroG2Point is the zero point on the G1 curve
func ZeroG2Point() *G2Point {
	point := new(bls12381.G2Affine)
	point.SetInfinity()
	return &G2Point{CompressedBytes: point.Marshal()}
}

// IsZero checks if the G1Point is the identity/zero point
func (p *G1Point) IsZero() (bool, error) {
	affinePoint, err := bls.G1PointFromCompressedBytes(p.CompressedBytes)
	if err != nil {
		return false, err
	}
	return affinePoint.IsZero(), nil
}

// IsEqual checks if two G1Points are equal
func (p *G1Point) IsEqual(other *G1Point) bool {
	return bytes.Equal(p.CompressedBytes, other.CompressedBytes)
}

// G2Point represents a point on BLS12-381 G2 (used for public keys)
type G2Point struct {
	CompressedBytes []byte
}

// IsEqual checks if two G2Points are equal
func (p *G2Point) IsEqual(other *G2Point) bool {
	return bytes.Equal(p.CompressedBytes, other.CompressedBytes)
}

// IsInfinity checks if the G2Point is the identity/zero point
func (p *G2Point) IsZero() (bool, error) {
	affinePoint, err := bls.G2PointFromCompressedBytes(p.CompressedBytes)
	if err != nil {
		return false, err
	}
	return affinePoint.IsZero(), nil
}

// Acknowledgement is signed by players to prevent dealer equivocation
type Acknowledgement struct {
	DealerAddress    common.Address
	PlayerAddress    common.Address
	SessionTimestamp int64    // Block timestamp of the protocol session (Phase 3)
	ShareHash        [32]byte // keccak256(share) - commits to received share (Phase 3)
	CommitmentHash   [32]byte
	Signature        []byte // Sign(p2p_privkey, dealerAddress || playerAddress || session_timestamp || shareHash || commitment_hash)
}

// CompletionSignature signals reshare completion
type CompletionSignature struct {
	NodeID           int64
	SessionTimestamp int64
	CommitmentHash   [32]byte
	Signature        []byte // Sign(p2p_privkey, session_timestamp || commitment_hash)
}

// AppSignRequest represents a request to sign for an application
type AppSignRequest struct {
	AppID           string
	AttestationTime int64
}

// AppSignResponse contains a partial signature from a node
type AppSignResponse struct {
	OperatorAddress  string // Operator address instead of NodeID
	PartialSignature G1Point
}

// SecretsRequestV1 represents a request for application secrets
type SecretsRequestV1 struct {
	AppID             string `json:"app_id"`
	AttestationMethod string `json:"attestation_method"` // Attestation method: "gcp", "intel", "ecdsa" (default: "gcp")
	Attestation       []byte `json:"attestation"`        // Attestation data (JWT for GCP/Intel, signature for ECDSA)
	RSAPubKeyTmp      []byte `json:"rsa_pubkey_tmp"`     // Ephemeral RSA public key
	AttestationTime   int64  `json:"attestation_time"`   // For key versioning
	// ECDSA-specific fields (only used when attestation_method is "ecdsa")
	Challenge []byte `json:"challenge,omitempty"`  // Challenge for ECDSA attestation
	PublicKey []byte `json:"public_key,omitempty"` // Public key for ECDSA attestation
}

// SecretsResponseV1 represents the response with encrypted secrets
type SecretsResponseV1 struct {
	EncryptedEnv        string `json:"encrypted_env"`         // AES encrypted env vars
	PublicEnv           string `json:"public_env"`            // Plain text env
	EncryptedPartialSig []byte `json:"encrypted_partial_sig"` // RSA encrypted partial sig
}

// ContainerPolicy defines the expected container execution parameters for an app release.
// These values are stored on-chain by the app developer via createApp() / upgradeApp() and
// verified by each KMS operator node against the JWT submods.container claims.
// An empty or nil field means "no restriction" — validation is skipped for that field.
type ContainerPolicy struct {
	Args          []string          `json:"args"`
	CmdOverride   []string          `json:"cmd_override"`
	Env           map[string]string `json:"env"`
	EnvOverride   map[string]string `json:"env_override"`
	RestartPolicy string            `json:"restart_policy"`
}

// AttestationClaims represents parsed attestation data
type AttestationClaims struct {
	AppID           string
	ImageDigest     string
	Nonce           string
	JTI             string // JWT ID — used to prevent replay attacks
	IssuedAt        int64
	ExpiresAt       int64 // Unix timestamp; used to expire JTI cache entries
	PublicKey       []byte
	ContainerPolicy ContainerPolicy
}

// Release represents application release data from on-chain registry
type Release struct {
	ImageDigest     string          `json:"image_digest"`
	EncryptedEnv    string          `json:"encrypted_env"`
	PublicEnv       string          `json:"public_env"`
	Timestamp       int64           `json:"timestamp"`
	ContainerPolicy ContainerPolicy `json:"container_policy"`
}

// CommitmentBroadcast represents a broadcast of commitments with acknowledgements and merkle proofs (Phase 3)
type CommitmentBroadcast struct {
	FromOperatorID   int64              // Operator sending the broadcast
	SessionTimestamp int64              // Block timestamp of the protocol session
	Commitments      []G2Point          // Dealer's polynomial commitments
	Acknowledgements []*Acknowledgement // All n-1 acks collected as dealer
	MerkleProof      [][32]byte         // Merkle proof for specific recipient
}

// CommitmentBroadcastMessage wraps CommitmentBroadcast for authenticated transport (Phase 5)
type CommitmentBroadcastMessage struct {
	FromOperatorAddress common.Address       `json:"fromOperatorAddress"`
	ToOperatorAddress   common.Address       `json:"toOperatorAddress"`
	FromOperatorID      int64                `json:"fromOperatorID"`
	ToOperatorID        int64                `json:"toOperatorID"`
	SessionTimestamp    int64                `json:"sessionTimestamp"`
	Broadcast           *CommitmentBroadcast `json:"broadcast"`
}
