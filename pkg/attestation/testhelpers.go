package attestation

import (
	"encoding/json"
	"log/slog"
	"os"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// NewStubManager creates an AttestationManager with stub methods for testing
func NewStubManager() *AttestationManager {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewAttestationManager(logger)

	// Register stub GCP method
	_ = manager.RegisterMethod(&StubMethod{methodName: "gcp"})

	// Register stub ECDSA method
	_ = manager.RegisterMethod(&StubECDSAMethod{})

	// Register stub Intel method
	_ = manager.RegisterMethod(&StubMethod{methodName: "intel"})

	return manager
}

// StubMethod is a stub attestation method for testing
type StubMethod struct {
	methodName string
}

func (s *StubMethod) Name() string {
	return s.methodName
}

func (s *StubMethod) Verify(request *AttestationRequest) (*types.AttestationClaims, error) {
	// Parse the attestation to extract image digest if it's JSON
	var claims types.AttestationClaims
	if err := json.Unmarshal(request.Attestation, &claims); err == nil {
		// Use the provided image digest from attestation
		return &claims, nil
	}

	// Fallback to default test claims
	return &types.AttestationClaims{
		AppID:       request.AppID,
		ImageDigest: s.methodName + ":unverified",
		IssuedAt:    0,
		PublicKey:   []byte{},
	}, nil
}

// StubECDSAMethod is a stub ECDSA attestation method for testing
type StubECDSAMethod struct{}

func (s *StubECDSAMethod) Name() string {
	return "ecdsa"
}

func (s *StubECDSAMethod) Verify(request *AttestationRequest) (*types.AttestationClaims, error) {
	// Return test claims
	return &types.AttestationClaims{
		AppID:       request.AppID,
		ImageDigest: "ecdsa:unverified",
		IssuedAt:    0,
		PublicKey:   request.PublicKey,
	}, nil
}
