package attestation

import (
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// AttestationMethod defines the interface for different attestation verification methods.
// Implementations include GCP Confidential Space, Intel Trust Authority, ECDSA, etc.
type AttestationMethod interface {
	// Verify validates an attestation and returns the extracted claims
	Verify(request *AttestationRequest) (*types.AttestationClaims, error)

	// Name returns the unique identifier for this attestation method
	Name() string
}

// AttestationRequest represents a generic attestation verification request.
// Different attestation methods may use different fields from this struct.
type AttestationRequest struct {
	// Method specifies which attestation method to use (e.g., "gpc", "ecdsa")
	Method string

	// Attestation contains the raw attestation data (JWT token, signature, etc.)
	Attestation []byte

	// AppID is the application identifier being attested
	AppID string

	// Challenge is an optional challenge/nonce for challenge-response protocols
	Challenge []byte

	// PublicKey is an optional public key for signature-based attestations
	PublicKey []byte

	// Metadata contains method-specific additional data
	Metadata map[string]interface{}
}
