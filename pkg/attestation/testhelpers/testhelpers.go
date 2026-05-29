// Package testhelpers provides stub attestation methods for use in tests.
//
// These stubs accept any input and return caller-asserted claims. They MUST
// NOT be wired into any production binary — kept in a subpackage so that
// importing pkg/attestation does not pull them in transitively.
package testhelpers

import (
	"encoding/json"
	"log/slog"
	"os"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// NewStubManager creates an AttestationManager with stub methods for testing.
func NewStubManager() *attestation.AttestationManager {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := attestation.NewAttestationManager(logger)

	_ = manager.RegisterMethod(&StubMethod{methodName: "gcp"})
	_ = manager.RegisterMethod(&StubECDSAMethod{})
	_ = manager.RegisterMethod(&StubMethod{methodName: "intel"})
	_ = manager.RegisterMethod(&StubTPMMethod{})

	return manager
}

// StubMethod is a stub attestation method for testing.
type StubMethod struct {
	methodName string
}

func (s *StubMethod) Name() string {
	return s.methodName
}

func (s *StubMethod) Verify(request *attestation.AttestationRequest) (*types.AttestationClaims, error) {
	var claims types.AttestationClaims
	if err := json.Unmarshal(request.Attestation, &claims); err == nil {
		return &claims, nil
	}

	return &types.AttestationClaims{
		AppID:       request.AppID,
		ImageDigest: s.methodName + ":unverified",
		IssuedAt:    0,
		PublicKey:   []byte{},
	}, nil
}

// StubECDSAMethod is a stub ECDSA attestation method for testing.
type StubECDSAMethod struct{}

func (s *StubECDSAMethod) Name() string {
	return "ecdsa"
}

func (s *StubECDSAMethod) Verify(request *attestation.AttestationRequest) (*types.AttestationClaims, error) {
	return &types.AttestationClaims{
		AppID:       request.AppID,
		ImageDigest: "ecdsa:unverified",
		IssuedAt:    0,
		PublicKey:   request.PublicKey,
	}, nil
}

// StubTPMMethod is a stub TPM attestation method for testing.
type StubTPMMethod struct{}

func (s *StubTPMMethod) Name() string {
	return "tpm"
}

func (s *StubTPMMethod) Verify(request *attestation.AttestationRequest) (*types.AttestationClaims, error) {
	var claims types.AttestationClaims
	if err := json.Unmarshal(request.Attestation, &claims); err == nil {
		return &claims, nil
	}

	return &types.AttestationClaims{
		AppID:       request.AppID,
		ImageDigest: "tpm:unverified",
		IssuedAt:    0,
	}, nil
}
