package node

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering/localPeeringDataFetcher"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/memory"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/inMemoryTransportSigner"
	kmsTypes "github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// mockChainPoller is a no-op chain poller for testing
type mockChainPoller struct{}

func (m *mockChainPoller) Start(ctx context.Context) error {
	return nil
}

func Test_SecretsEndpoint(t *testing.T) {
	t.Run("Flow", func(t *testing.T) { testSecretsEndpointFlow(t) })
	t.Run("Validation", func(t *testing.T) { testSecretsEndpointValidation(t) })
	t.Run("ImageDigestMismatch", func(t *testing.T) { testSecretsEndpointImageDigestMismatch(t) })
	t.Run("AppIDMismatch", func(t *testing.T) { testSecretsEndpointAppIDMismatch(t) })
}

// createTestPeeringDataFetcher creates a test peering data fetcher using ChainConfig data
func createTestPeeringDataFetcher(t *testing.T) peering.IPeeringDataFetcher {
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	if err != nil {
		t.Fatalf("Failed to read chain config: %v", err)
	}

	// Create test operator peer
	privKey, err := bn254.NewPrivateKeyFromHexString(chainConfig.OperatorAccountPrivateKey1)
	if err != nil {
		t.Fatalf("Failed to create BN254 private key: %v", err)
	}

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

	return localPeeringDataFetcher.NewLocalPeeringDataFetcher([]*peering.OperatorSetPeers{operatorSet}, nil)
}

// testSecretsEndpointFlow tests the complete application secrets retrieval flow
func testSecretsEndpointFlow(t *testing.T) {
	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	if err != nil {
		t.Fatalf("Failed to read chain config: %v", err)
	}

	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	cfg := Config{
		OperatorAddress: chainConfig.OperatorAccountAddress1,
		Port:            0,
		ChainID:         config.ChainId_EthereumAnvil,
		AVSAddress:      "0x1234567890123456789012345678901234567890",
		OperatorSetId:   1,
	}

	bh := blockHandler.NewBlockHandler(testLogger)
	peeringDataFetcher := createTestPeeringDataFetcher(t)

	pkBytes, err := hexutil.Decode(chainConfig.OperatorAccountPrivateKey1)
	if err != nil {
		t.Fatalf("Failed to decode BN254 private key: %v", err)
	}
	imts, err := inMemoryTransportSigner.NewBn254InMemoryTransportSigner(pkBytes, testLogger)
	if err != nil {
		t.Fatalf("Failed to create in-memory transport signer: %v", err)
	}

	// Use mock attestation verifier for tests
	mockManager := attestation.NewStubManager()

	// Create testable contract caller with configurable releases
	mockBaseContractCaller := contractCaller.NewTestableContractCallerStub()
	mockRegistryAddress := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Add test release
	testRelease := &kmsTypes.Release{
		ImageDigest:  "sha256:test123",
		EncryptedEnv: "encrypted-env-data-for-test-app",
		PublicEnv:    "PUBLIC_VAR=test-value",
		Timestamp:    time.Now().Unix(),
	}
	mockBaseContractCaller.AddTestRelease("test-app", testRelease)

	persistence := memory.NewMemoryPersistence()
	defer func() { _ = persistence.Close() }()

	node, err := NewNode(cfg, peeringDataFetcher, bh, nil, imts, mockManager, mockBaseContractCaller, mockRegistryAddress, persistence, testLogger)
	if err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	// Add a test key share
	testShare := new(fr.Element).SetInt64(42)
	keyVersion := &kmsTypes.KeyShareVersion{
		Version:        time.Now().Unix(),
		PrivateShare:   testShare,
		Commitments:    []kmsTypes.G2Point{},
		IsActive:       true,
		ParticipantIDs: []int64{1},
	}
	node.keyStore.AddVersion(keyVersion)

	// Generate ephemeral RSA key pair for the test
	rsaEncrypt := encryption.NewRSAEncryption()
	privKeyPEM, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Create test attestation with matching claims
	testClaims := kmsTypes.AttestationClaims{
		AppID:       "test-app",
		ImageDigest: "sha256:test123",
		IssuedAt:    time.Now().Unix(),
		PublicKey:   pubKeyPEM,
	}
	attestationBytes, _ := json.Marshal(testClaims)

	// Create secrets request
	req := kmsTypes.SecretsRequestV1{
		AppID:             "test-app",
		AttestationMethod: "gcp",
		Attestation:       attestationBytes,
		RSAPubKeyTmp:      pubKeyPEM,
		AttestTime:        time.Now().Unix(),
	}

	// Create HTTP request
	reqBody, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")

	// Create response recorder
	w := httptest.NewRecorder()

	// Call the handler
	server := NewServer(node, 0)
	server.handleSecretsRequest(w, httpReq)

	// Check response
	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Parse response
	var resp kmsTypes.SecretsResponseV1
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify response contains expected data
	if resp.EncryptedEnv != testRelease.EncryptedEnv {
		t.Errorf("Expected encrypted_env %s, got %s", testRelease.EncryptedEnv, resp.EncryptedEnv)
	}

	if resp.PublicEnv != testRelease.PublicEnv {
		t.Errorf("Expected public_env %s, got %s", testRelease.PublicEnv, resp.PublicEnv)
	}

	if len(resp.EncryptedPartialSig) == 0 {
		t.Error("Expected non-empty encrypted partial signature")
	}

	// Verify we can decrypt the partial signature
	decryptedSigBytes, err := rsaEncrypt.Decrypt(resp.EncryptedPartialSig, privKeyPEM)
	if err != nil {
		t.Fatalf("Failed to decrypt partial signature: %v", err)
	}

	// Parse the partial signature
	var partialSig kmsTypes.G1Point
	if err := json.Unmarshal(decryptedSigBytes, &partialSig); err != nil {
		t.Fatalf("Failed to parse partial signature: %v", err)
	}

	// Verify it's not zero
	isZero, err := partialSig.IsZero()
	if err != nil {
		t.Fatalf("Failed to check if partial signature is zero: %v", err)
	}
	if isZero {
		t.Error("Partial signature should not be zero")
	}

	fmt.Printf("Test passed: Successfully retrieved and decrypted secrets for test-app\n")
}

// testSecretsEndpointValidation tests various validation scenarios
func testSecretsEndpointValidation(t *testing.T) {
	peeringDataFetcher := createTestPeeringDataFetcher(t)

	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	if err != nil {
		t.Fatalf("Failed to read chain config: %v", err)
	}

	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	cfg := Config{
		OperatorAddress: chainConfig.OperatorAccountAddress1,
		Port:            0,
		ChainID:         config.ChainId_EthereumAnvil,
		AVSAddress:      "0x1234567890123456789012345678901234567890",
		OperatorSetId:   1,
	}
	bh := blockHandler.NewBlockHandler(testLogger)
	mockPoller := &mockChainPoller{}

	pkBytes, err := hexutil.Decode(chainConfig.OperatorAccountPrivateKey1)
	if err != nil {
		t.Fatalf("Failed to decode BN254 private key: %v", err)
	}
	imts, err := inMemoryTransportSigner.NewBn254InMemoryTransportSigner(pkBytes, testLogger)
	if err != nil {
		t.Fatalf("Failed to create in-memory transport signer: %v", err)
	}

	// Use mock attestation verifier for tests
	mockManager := attestation.NewStubManager()

	// Create testable contract caller with configurable releases
	mockBaseContractCaller := contractCaller.NewTestableContractCallerStub()
	mockRegistryAddress := common.HexToAddress("0x1111111111111111111111111111111111111111")

	persistence := memory.NewMemoryPersistence()
	defer func() { _ = persistence.Close() }()

	node, err := NewNode(cfg, peeringDataFetcher, bh, mockPoller, imts, mockManager, mockBaseContractCaller, mockRegistryAddress, persistence, testLogger)
	if err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	// Test missing AppID
	req := kmsTypes.SecretsRequestV1{
		AppID:        "", // Missing
		Attestation:  []byte("test"),
		RSAPubKeyTmp: []byte("test-key"),
	}
	reqBody, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	server := NewServer(node, 0)
	server.handleSecretsRequest(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing AppID, got %d", w.Code)
	}
}

// testSecretsEndpointImageDigestMismatch tests image digest validation
func testSecretsEndpointImageDigestMismatch(t *testing.T) {
	peeringDataFetcher := createTestPeeringDataFetcher(t)

	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	if err != nil {
		t.Fatalf("Failed to read chain config: %v", err)
	}

	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	cfg := Config{
		OperatorAddress: chainConfig.OperatorAccountAddress1,
		Port:            0,
		ChainID:         config.ChainId_EthereumAnvil,
		AVSAddress:      "0x1234567890123456789012345678901234567890",
		OperatorSetId:   1,
	}
	bh := blockHandler.NewBlockHandler(testLogger)
	mockPoller := &mockChainPoller{}

	pkBytes, err := hexutil.Decode(chainConfig.OperatorAccountPrivateKey1)
	if err != nil {
		t.Fatalf("Failed to decode BN254 private key: %v", err)
	}
	imts, err := inMemoryTransportSigner.NewBn254InMemoryTransportSigner(pkBytes, testLogger)
	if err != nil {
		t.Fatalf("Failed to create in-memory transport signer: %v", err)
	}

	// Use mock attestation verifier for tests
	mockManager := attestation.NewStubManager()

	// Create testable contract caller with configurable releases
	mockBaseContractCaller := contractCaller.NewTestableContractCallerStub()
	mockRegistryAddress := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Add test release with specific digest
	testRelease := &kmsTypes.Release{
		ImageDigest:  "sha256:correct-digest",
		EncryptedEnv: "env-data",
		PublicEnv:    "PUBLIC=value",
		Timestamp:    time.Now().Unix(),
	}
	mockBaseContractCaller.AddTestRelease("test-app", testRelease)

	persistence := memory.NewMemoryPersistence()
	defer func() { _ = persistence.Close() }()

	node, err := NewNode(cfg, peeringDataFetcher, bh, mockPoller, imts, mockManager, mockBaseContractCaller, mockRegistryAddress, persistence, testLogger)
	if err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	// Create attestation with DIFFERENT digest
	testClaims := kmsTypes.AttestationClaims{
		AppID:       "test-app",
		ImageDigest: "sha256:wrong-digest", // Different from release
		IssuedAt:    time.Now().Unix(),
		PublicKey:   []byte("dummy-key"),
	}
	attestationBytes, _ := json.Marshal(testClaims)

	req := kmsTypes.SecretsRequestV1{
		AppID:             "test-app",
		AttestationMethod: "gcp",
		Attestation:       attestationBytes,
		RSAPubKeyTmp:      []byte("test-key"),
	}
	reqBody, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	server := NewServer(node, 0)
	server.handleSecretsRequest(w, httpReq)

	// Should fail with forbidden due to digest mismatch
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for image digest mismatch, got %d", w.Code)
	}
}

// testSecretsEndpointAppIDMismatch tests app identity binding between request and attestation claims.
func testSecretsEndpointAppIDMismatch(t *testing.T) {
	peeringDataFetcher := createTestPeeringDataFetcher(t)

	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	if err != nil {
		t.Fatalf("Failed to read chain config: %v", err)
	}

	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	cfg := Config{
		OperatorAddress: chainConfig.OperatorAccountAddress1,
		Port:            0,
		ChainID:         config.ChainId_EthereumAnvil,
		AVSAddress:      "0x1234567890123456789012345678901234567890",
		OperatorSetId:   1,
	}
	bh := blockHandler.NewBlockHandler(testLogger)
	mockPoller := &mockChainPoller{}

	pkBytes, err := hexutil.Decode(chainConfig.OperatorAccountPrivateKey1)
	if err != nil {
		t.Fatalf("Failed to decode BN254 private key: %v", err)
	}
	imts, err := inMemoryTransportSigner.NewBn254InMemoryTransportSigner(pkBytes, testLogger)
	if err != nil {
		t.Fatalf("Failed to create in-memory transport signer: %v", err)
	}

	mockManager := attestation.NewStubManager()
	mockBaseContractCaller := contractCaller.NewTestableContractCallerStub()
	mockRegistryAddress := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Release exists for requested app; request should still fail because claims AppID mismatches.
	mockBaseContractCaller.AddTestRelease("requested-app", &kmsTypes.Release{
		ImageDigest:  "sha256:test-digest",
		EncryptedEnv: "env-data",
		PublicEnv:    "PUBLIC=value",
		Timestamp:    time.Now().Unix(),
	})

	persistence := memory.NewMemoryPersistence()
	defer func() { _ = persistence.Close() }()

	node, err := NewNode(cfg, peeringDataFetcher, bh, mockPoller, imts, mockManager, mockBaseContractCaller, mockRegistryAddress, persistence, testLogger)
	if err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	// claims.AppID intentionally differs from req.AppID.
	testClaims := kmsTypes.AttestationClaims{
		AppID:       "different-attested-app",
		ImageDigest: "sha256:test-digest",
		IssuedAt:    time.Now().Unix(),
		PublicKey:   []byte("dummy-key"),
	}
	attestationBytes, _ := json.Marshal(testClaims)

	req := kmsTypes.SecretsRequestV1{
		AppID:             "requested-app",
		AttestationMethod: "gcp",
		Attestation:       attestationBytes,
		RSAPubKeyTmp:      []byte("test-key"),
	}
	reqBody, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	server := NewServer(node, 0)
	server.handleSecretsRequest(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for app ID mismatch, got %d", w.Code)
	}
}
