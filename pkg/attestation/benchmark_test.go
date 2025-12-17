package attestation

import (
	"context"
	"crypto/rand"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// BenchmarkECDSAVerification benchmarks ECDSA attestation verification
func BenchmarkECDSAVerification(b *testing.B) {
	method := NewECDSAAttestationMethodDefault()

	// Setup: Generate key and valid attestation
	appPrivateKey, _ := crypto.GenerateKey()
	appPublicKey := crypto.FromECDSAPub(&appPrivateKey.PublicKey)
	nonce := make([]byte, NonceLength)
	rand.Read(nonce)
	challenge, _ := GenerateChallenge(nonce)
	signature, _ := SignChallenge(appPrivateKey, "bench-app", challenge)

	request := &AttestationRequest{
		Method:      "ecdsa",
		AppID:       "bench-app",
		Challenge:   []byte(challenge),
		PublicKey:   appPublicKey,
		Attestation: signature,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = method.Verify(request)
	}
}

// BenchmarkECDSAChallengeGeneration benchmarks challenge generation
func BenchmarkECDSAChallengeGeneration(b *testing.B) {
	nonce := make([]byte, NonceLength)
	rand.Read(nonce)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateChallenge(nonce)
	}
}

// BenchmarkECDSASignature benchmarks signing a challenge
func BenchmarkECDSASignature(b *testing.B) {
	appPrivateKey, _ := crypto.GenerateKey()
	nonce := make([]byte, NonceLength)
	rand.Read(nonce)
	challenge, _ := GenerateChallenge(nonce)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignChallenge(appPrivateKey, "bench-app", challenge)
	}
}

// BenchmarkAttestationManager benchmarks manager overhead
func BenchmarkAttestationManager(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	// Register ECDSA method
	ecdsaMethod := NewECDSAAttestationMethodDefault()
	_ = manager.RegisterMethod(ecdsaMethod)

	// Setup request
	appPrivateKey, _ := crypto.GenerateKey()
	appPublicKey := crypto.FromECDSAPub(&appPrivateKey.PublicKey)
	nonce := make([]byte, NonceLength)
	rand.Read(nonce)
	challenge, _ := GenerateChallenge(nonce)
	signature, _ := SignChallenge(appPrivateKey, "bench-app", challenge)

	request := &AttestationRequest{
		Method:      "ecdsa",
		AppID:       "bench-app",
		Challenge:   []byte(challenge),
		PublicKey:   appPublicKey,
		Attestation: signature,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = manager.VerifyWithMethod("ecdsa", request)
	}
}

// BenchmarkGCPMethodStub benchmarks GCP method with stub verifier (for comparison)
func BenchmarkGCPMethodStub(b *testing.B) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create a real attestation verifier (will fetch JWKs)
	verifier, err := NewAttestationVerifier(ctx, logger, "test-project", time.Hour, true)
	if err != nil {
		b.Fatalf("Failed to create verifier: %v", err)
	}

	gcpMethod := NewGCPAttestationMethod(verifier, GoogleConfidentialSpace)

	// Note: This will fail verification but measures overhead up to that point
	request := &AttestationRequest{
		Method:      "gcp",
		AppID:       "bench-app",
		Attestation: []byte("invalid-jwt-for-benchmarking-overhead"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = gcpMethod.Verify(request)
	}
}

// BenchmarkMethodComparison compares all registered methods
func BenchmarkMethodComparison(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	// Register ECDSA method
	ecdsaMethod := NewECDSAAttestationMethodDefault()
	_ = manager.RegisterMethod(ecdsaMethod)

	// Register mock GCP method for fair comparison
	mockGCP := &mockMethodForBenchmark{name: "gcp"}
	_ = manager.RegisterMethod(mockGCP)

	// Setup ECDSA request
	appPrivateKey, _ := crypto.GenerateKey()
	appPublicKey := crypto.FromECDSAPub(&appPrivateKey.PublicKey)
	nonce := make([]byte, NonceLength)
	rand.Read(nonce)
	challenge, _ := GenerateChallenge(nonce)
	signature, _ := SignChallenge(appPrivateKey, "bench-app", challenge)

	ecdsaRequest := &AttestationRequest{
		Method:      "ecdsa",
		AppID:       "bench-app",
		Challenge:   []byte(challenge),
		PublicKey:   appPublicKey,
		Attestation: signature,
	}

	gcpRequest := &AttestationRequest{
		Method:      "gcp",
		AppID:       "bench-app",
		Attestation: []byte("mock-token"),
	}

	b.Run("ECDSA", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = manager.VerifyWithMethod("ecdsa", ecdsaRequest)
		}
	})

	b.Run("GCP-Mock", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = manager.VerifyWithMethod("gcp", gcpRequest)
		}
	})
}

// mockMethodForBenchmark is a no-op method for benchmarking
type mockMethodForBenchmark struct {
	name string
}

func (m *mockMethodForBenchmark) Name() string {
	return m.name
}

func (m *mockMethodForBenchmark) Verify(request *AttestationRequest) (*types.AttestationClaims, error) {
	return &types.AttestationClaims{
		AppID:       request.AppID,
		ImageDigest: "mock",
	}, nil
}
