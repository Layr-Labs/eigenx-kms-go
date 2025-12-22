package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/blockHandler"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering/localPeeringDataFetcher"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/memory"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/registry"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/inMemoryTransportSigner"
	kmsTypes "github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockChainPoller is a no-op chain poller for testing
type mockChainPoller struct{}

func (m *mockChainPoller) Start(ctx context.Context) error {
	return nil
}

// createTestNode creates a node with AttestationManager for testing
func createTestNodeWithManager(t *testing.T, manager *attestation.AttestationManager) *node.Node {
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	require.NoError(t, err)

	testLogger, err := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	require.NoError(t, err)

	cfg := node.Config{
		OperatorAddress: chainConfig.OperatorAccountAddress1,
		Port:            0,
		ChainID:         config.ChainId_EthereumAnvil,
		AVSAddress:      "0x1234567890123456789012345678901234567890",
		OperatorSetId:   1,
	}

	// Create peering data fetcher
	privKey, err := bn254.NewPrivateKeyFromHexString(chainConfig.OperatorAccountPrivateKey1)
	require.NoError(t, err)

	peer := &peering.OperatorSetPeer{
		OperatorAddress: common.HexToAddress(chainConfig.OperatorAccountAddress1),
		SocketAddress:   "http://localhost:8080",
		WrappedPublicKey: peering.WrappedPublicKey{
			PublicKey:    privKey.Public(),
			ECDSAAddress: common.HexToAddress(chainConfig.OperatorAccountAddress1),
		},
		CurveType: config.CurveTypeBN254,
	}

	operatorSet := &peering.OperatorSetPeers{
		OperatorSetId: 1,
		AVSAddress:    common.HexToAddress("0x1234567890123456789012345678901234567890"),
		Peers:         []*peering.OperatorSetPeer{peer},
	}

	peeringDataFetcher := localPeeringDataFetcher.NewLocalPeeringDataFetcher([]*peering.OperatorSetPeers{operatorSet}, nil)

	bh := blockHandler.NewBlockHandler(testLogger)
	mockPoller := &mockChainPoller{}

	pkBytes, err := hexutil.Decode(chainConfig.OperatorAccountPrivateKey1)
	require.NoError(t, err)

	imts, err := inMemoryTransportSigner.NewBn254InMemoryTransportSigner(pkBytes, testLogger)
	require.NoError(t, err)

	// Create mock base contract caller
	mockBaseContractCaller := contractCaller.NewMockIContractCaller(t)
	mockBaseContractCaller.On("SubmitCommitment", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&ethTypes.Receipt{Status: 1}, nil).Maybe()
	mockRegistryAddress := common.HexToAddress("0x1111111111111111111111111111111111111111")

	persistence := memory.NewMemoryPersistence()
	t.Cleanup(func() { _ = persistence.Close() })

	n, err := node.NewNodeWithManager(cfg, peeringDataFetcher, bh, mockPoller, imts, manager, mockBaseContractCaller, mockRegistryAddress, persistence, testLogger)
	require.NoError(t, err)

	// Add a test key share
	testShare := new(fr.Element).SetInt64(42)
	keyVersion := &kmsTypes.KeyShareVersion{
		Version:        time.Now().Unix(),
		PrivateShare:   testShare,
		Commitments:    []kmsTypes.G2Point{},
		IsActive:       true,
		ParticipantIDs: []int64{1},
	}
	n.GetKeyStore().AddVersion(keyVersion)

	return n
}

func TestSecretsEndpoint_ECDSAAttestation(t *testing.T) {
	// Create attestation manager with only ECDSA enabled
	slogger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := attestation.NewAttestationManager(slogger)

	ecdsaMethod := attestation.NewECDSAAttestationMethodDefault()
	err := manager.RegisterMethod(ecdsaMethod)
	require.NoError(t, err)

	n := createTestNodeWithManager(t, manager)

	// Add test release
	testRelease := &kmsTypes.Release{
		ImageDigest:  "ecdsa:unverified", // ECDSA uses this default
		EncryptedEnv: "encrypted-env-data",
		PublicEnv:    "PUBLIC_VAR=test-value",
		Timestamp:    time.Now().Unix(),
	}
	stubRegistry := n.GetReleaseRegistry().(*registry.StubClient)
	stubRegistry.AddTestRelease("ecdsa-test-app", testRelease)

	// Generate ECDSA key pair for attestation
	appPrivateKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	appPublicKey := crypto.FromECDSAPub(&appPrivateKey.PublicKey)

	// Generate challenge
	nonce := make([]byte, attestation.NonceLength)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	challenge, err := attestation.GenerateChallenge(nonce)
	require.NoError(t, err)

	// Sign challenge
	signature, err := attestation.SignChallenge(appPrivateKey, "ecdsa-test-app", challenge)
	require.NoError(t, err)

	// Generate RSA key pair for response encryption
	rsaEncrypt := encryption.NewRSAEncryption()
	privKeyPEM, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	require.NoError(t, err)

	// Create ECDSA attestation request
	req := kmsTypes.SecretsRequestV1{
		AppID:             "ecdsa-test-app",
		AttestationMethod: "ecdsa",
		Attestation:       signature,
		Challenge:         []byte(challenge),
		PublicKey:         appPublicKey,
		RSAPubKeyTmp:      pubKeyPEM,
		AttestTime:        0,
	}

	// Make HTTP request
	reqBody, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server := node.NewServer(n, 0)
	server.GetHandler().ServeHTTP(w, httpReq)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code, "Response body: %s", w.Body.String())

	var resp kmsTypes.SecretsResponseV1
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, testRelease.EncryptedEnv, resp.EncryptedEnv)
	assert.Equal(t, testRelease.PublicEnv, resp.PublicEnv)
	assert.NotEmpty(t, resp.EncryptedPartialSig)

	// Verify we can decrypt the partial signature
	decryptedSigBytes, err := rsaEncrypt.Decrypt(resp.EncryptedPartialSig, privKeyPEM)
	require.NoError(t, err)

	var partialSig kmsTypes.G1Point
	err = json.Unmarshal(decryptedSigBytes, &partialSig)
	require.NoError(t, err)

	isZero, err := partialSig.IsZero()
	require.NoError(t, err)
	assert.False(t, isZero, "Partial signature should not be zero")
}

func TestSecretsEndpoint_MethodNotEnabled(t *testing.T) {
	// Create manager with only GCP enabled (ECDSA disabled)
	slogger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := attestation.NewAttestationManager(slogger)

	// Register only stub verifier (acts as GCP for testing)
	stubMethod := &stubAttestationMethod{name: "gcp"}
	err := manager.RegisterMethod(stubMethod)
	require.NoError(t, err)

	n := createTestNodeWithManager(t, manager)

	// Try to use ECDSA method (not registered)
	appPrivateKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	appPublicKey := crypto.FromECDSAPub(&appPrivateKey.PublicKey)

	nonce := make([]byte, attestation.NonceLength)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	challenge, err := attestation.GenerateChallenge(nonce)
	require.NoError(t, err)

	signature, err := attestation.SignChallenge(appPrivateKey, "test-app", challenge)
	require.NoError(t, err)

	req := kmsTypes.SecretsRequestV1{
		AppID:             "test-app",
		AttestationMethod: "ecdsa", // Not enabled
		Attestation:       signature,
		Challenge:         []byte(challenge),
		PublicKey:         appPublicKey,
		RSAPubKeyTmp:      []byte("test-key"),
	}

	reqBody, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	server := node.NewServer(n, 0)
	server.GetHandler().ServeHTTP(w, httpReq)

	// Should fail with unauthorized because method not registered
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "not registered")
}

func TestSecretsEndpoint_DefaultsToGCP(t *testing.T) {
	// Create manager with GCP method
	slogger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := attestation.NewAttestationManager(slogger)

	stubMethod := &stubAttestationMethod{
		name: "gcp",
		claims: &kmsTypes.AttestationClaims{
			AppID:       "test-app",
			ImageDigest: "sha256:test123",
			IssuedAt:    time.Now().Unix(),
		},
	}
	err := manager.RegisterMethod(stubMethod)
	require.NoError(t, err)

	n := createTestNodeWithManager(t, manager)

	// Add test release
	testRelease := &kmsTypes.Release{
		ImageDigest:  "sha256:test123",
		EncryptedEnv: "env-data",
		PublicEnv:    "PUBLIC=value",
		Timestamp:    time.Now().Unix(),
	}
	stubRegistry := n.GetReleaseRegistry().(*registry.StubClient)
	stubRegistry.AddTestRelease("test-app", testRelease)

	// Generate RSA keys
	_, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	require.NoError(t, err)

	// Create request WITHOUT specifying method (should default to "gcp")
	req := kmsTypes.SecretsRequestV1{
		AppID: "test-app",
		// AttestationMethod not specified - should default to "gcp"
		Attestation:  []byte("dummy-attestation"),
		RSAPubKeyTmp: pubKeyPEM,
		AttestTime:   0,
	}

	reqBody, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	server := node.NewServer(n, 0)
	server.GetHandler().ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code, "Response body: %s", w.Body.String())
}

func TestSecretsEndpoint_ExpiredECDSAChallenge(t *testing.T) {
	// Create manager with ECDSA using short time window
	slogger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := attestation.NewAttestationManager(slogger)

	ecdsaMethod := attestation.NewECDSAAttestationMethod(attestation.ECDSAAttestationConfig{
		ChallengeTimeWindow: 1 * time.Second, // Very short window
	})
	err := manager.RegisterMethod(ecdsaMethod)
	require.NoError(t, err)

	n := createTestNodeWithManager(t, manager)

	// Generate ECDSA key pair
	appPrivateKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	appPublicKey := crypto.FromECDSAPub(&appPrivateKey.PublicKey)

	// Create expired challenge (2 seconds ago)
	oldTimestamp := time.Now().Unix() - 2
	nonce := make([]byte, attestation.NonceLength)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	challenge := fmt.Sprintf("%d-%x", oldTimestamp, nonce)

	// Sign the expired challenge
	signature, err := attestation.SignChallenge(appPrivateKey, "test-app", challenge)
	require.NoError(t, err)

	req := kmsTypes.SecretsRequestV1{
		AppID:             "test-app",
		AttestationMethod: "ecdsa",
		Attestation:       signature,
		Challenge:         []byte(challenge),
		PublicKey:         appPublicKey,
		RSAPubKeyTmp:      []byte("test-key"),
	}

	reqBody, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	server := node.NewServer(n, 0)
	server.GetHandler().ServeHTTP(w, httpReq)

	// Should fail with unauthorized due to expired challenge
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "expired")
}

func TestSecretsEndpoint_BothMethodsEnabled(t *testing.T) {
	// Create manager with both GCP and ECDSA enabled
	slogger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := attestation.NewAttestationManager(slogger)

	// Register both methods
	gcpStub := &stubAttestationMethod{
		name: "gcp",
		claims: &kmsTypes.AttestationClaims{
			AppID:       "test-app",
			ImageDigest: "sha256:gcp-image",
		},
	}
	ecdsaMethod := attestation.NewECDSAAttestationMethodDefault()

	require.NoError(t, manager.RegisterMethod(gcpStub))
	require.NoError(t, manager.RegisterMethod(ecdsaMethod))

	assert.Equal(t, 2, manager.MethodCount())
	assert.True(t, manager.HasMethod("gcp"))
	assert.True(t, manager.HasMethod("ecdsa"))

	n := createTestNodeWithManager(t, manager)

	// Add release for GCP
	releaseGCP := &kmsTypes.Release{
		ImageDigest:  "sha256:gcp-image",
		EncryptedEnv: "gcp-env",
		PublicEnv:    "PUBLIC=gcp",
		Timestamp:    time.Now().Unix(),
	}
	stubRegistry := n.GetReleaseRegistry().(*registry.StubClient)
	stubRegistry.AddTestRelease("test-app-gcp", releaseGCP)

	// Add release for ECDSA
	releaseECDSA := &kmsTypes.Release{
		ImageDigest:  "ecdsa:unverified",
		EncryptedEnv: "ecdsa-env",
		PublicEnv:    "PUBLIC=ecdsa",
		Timestamp:    time.Now().Unix(),
	}
	stubRegistry.AddTestRelease("test-app-ecdsa", releaseECDSA)

	_, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	require.NoError(t, err)

	// Test 1: Use GCP method
	reqGCP := kmsTypes.SecretsRequestV1{
		AppID:             "test-app-gcp",
		AttestationMethod: "gcp",
		Attestation:       []byte("dummy-gcp-token"),
		RSAPubKeyTmp:      pubKeyPEM,
	}

	reqBody, _ := json.Marshal(reqGCP)
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	server := node.NewServer(n, 0)
	server.GetHandler().ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code, "GCP method should succeed")

	// Test 2: Use ECDSA method
	appPrivKey, _ := crypto.GenerateKey()
	appPubKey := crypto.FromECDSAPub(&appPrivKey.PublicKey)
	nonce := make([]byte, attestation.NonceLength)
	_, _ = rand.Read(nonce)
	challenge, _ := attestation.GenerateChallenge(nonce)
	signature, _ := attestation.SignChallenge(appPrivKey, "test-app-ecdsa", challenge)

	reqECDSA := kmsTypes.SecretsRequestV1{
		AppID:             "test-app-ecdsa",
		AttestationMethod: "ecdsa",
		Attestation:       signature,
		Challenge:         []byte(challenge),
		PublicKey:         appPubKey,
		RSAPubKeyTmp:      pubKeyPEM,
	}

	reqBody2, _ := json.Marshal(reqECDSA)
	httpReq2 := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody2))
	w2 := httptest.NewRecorder()

	server.GetHandler().ServeHTTP(w2, httpReq2)

	assert.Equal(t, http.StatusOK, w2.Code, "ECDSA method should succeed")
}

// stubAttestationMethod is a simple stub for testing
type stubAttestationMethod struct {
	name   string
	claims *kmsTypes.AttestationClaims
}

func (s *stubAttestationMethod) Name() string {
	return s.name
}

func (s *stubAttestationMethod) Verify(request *attestation.AttestationRequest) (*kmsTypes.AttestationClaims, error) {
	if s.claims != nil {
		return s.claims, nil
	}
	return &kmsTypes.AttestationClaims{
		AppID:       request.AppID,
		ImageDigest: "sha256:stub",
		IssuedAt:    time.Now().Unix(),
	}, nil
}
