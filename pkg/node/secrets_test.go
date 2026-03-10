package node

import (
	"bytes"
	"context"
	"encoding/json"
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

// testSecretsFixture holds the common objects needed by secrets endpoint tests.
type testSecretsFixture struct {
	server             *Server
	node               *Node
	contractCallerStub *contractCaller.TestableContractCallerStub
}

// newTestSecretsFixture creates a fully wired Server and TestableContractCallerStub
// ready for secrets endpoint testing. The returned stub has no releases configured;
// callers should use AddTestRelease / SetPendingRelease as needed.
func newTestSecretsFixture(t *testing.T) *testSecretsFixture {
	t.Helper()

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

	mockManager := attestation.NewStubManager()
	stub := contractCaller.NewTestableContractCallerStub()
	mockRegistryAddress := common.HexToAddress("0x1111111111111111111111111111111111111111")

	persistence := memory.NewMemoryPersistence()
	t.Cleanup(func() { _ = persistence.Close() })

	n, err := NewNode(cfg, peeringDataFetcher, bh, nil, imts, mockManager, stub, mockRegistryAddress, persistence, testLogger)
	if err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	// Add a test key share so partial signatures can be generated.
	testShare := new(fr.Element).SetInt64(42)
	n.keyStore.AddVersion(&kmsTypes.KeyShareVersion{
		Version:        time.Now().Unix(),
		PrivateShare:   testShare,
		Commitments:    []kmsTypes.G2Point{},
		IsActive:       true,
		ParticipantIDs: []int64{1},
	})

	return &testSecretsFixture{
		server:             NewServer(n, 0),
		node:               n,
		contractCallerStub: stub,
	}
}

func Test_SecretsEndpoint(t *testing.T) {
	t.Run("Flow", func(t *testing.T) { testSecretsEndpointFlow(t) })
	t.Run("Validation", func(t *testing.T) { testSecretsEndpointValidation(t) })
	t.Run("ImageDigestMismatch", func(t *testing.T) { testSecretsEndpointImageDigestMismatch(t) })
	t.Run("TwoPhaseUpgrade", func(t *testing.T) { testSecretsEndpointTwoPhaseUpgrade(t) })
}

// createTestPeeringDataFetcher creates a test peering data fetcher using ChainConfig data
func createTestPeeringDataFetcher(t *testing.T) peering.IPeeringDataFetcher {
	t.Helper()

	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	if err != nil {
		t.Fatalf("Failed to read chain config: %v", err)
	}

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
	f := newTestSecretsFixture(t)

	testRelease := &kmsTypes.Release{
		ImageDigest:  "sha256:test123",
		EncryptedEnv: "encrypted-env-data-for-test-app",
		PublicEnv:    "PUBLIC_VAR=test-value",
		Timestamp:    time.Now().Unix(),
	}
	f.contractCallerStub.AddTestRelease("test-app", testRelease)

	rsaEncrypt := encryption.NewRSAEncryption()
	privKeyPEM, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	testClaims := kmsTypes.AttestationClaims{
		AppID:       "test-app",
		ImageDigest: "sha256:test123",
		IssuedAt:    time.Now().Unix(),
		PublicKey:   pubKeyPEM,
	}
	attestationBytes, err := json.Marshal(testClaims)
	if err != nil {
		t.Fatalf("Failed to marshal attestation claims: %v", err)
	}

	req := kmsTypes.SecretsRequestV1{
		AppID:             "test-app",
		AttestationMethod: "gcp",
		Attestation:       attestationBytes,
		RSAPubKeyTmp:      pubKeyPEM,
		AttestTime:        time.Now().Unix(),
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	f.server.handleSecretsRequest(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp kmsTypes.SecretsResponseV1
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.EncryptedEnv != testRelease.EncryptedEnv {
		t.Errorf("Expected encrypted_env %s, got %s", testRelease.EncryptedEnv, resp.EncryptedEnv)
	}

	if resp.PublicEnv != testRelease.PublicEnv {
		t.Errorf("Expected public_env %s, got %s", testRelease.PublicEnv, resp.PublicEnv)
	}

	if len(resp.EncryptedPartialSig) == 0 {
		t.Error("Expected non-empty encrypted partial signature")
	}

	decryptedSigBytes, err := rsaEncrypt.Decrypt(resp.EncryptedPartialSig, privKeyPEM)
	if err != nil {
		t.Fatalf("Failed to decrypt partial signature: %v", err)
	}

	var partialSig kmsTypes.G1Point
	if err := json.Unmarshal(decryptedSigBytes, &partialSig); err != nil {
		t.Fatalf("Failed to parse partial signature: %v", err)
	}

	isZero, err := partialSig.IsZero()
	if err != nil {
		t.Fatalf("Failed to check if partial signature is zero: %v", err)
	}
	if isZero {
		t.Error("Partial signature should not be zero")
	}

	t.Log("Successfully retrieved and decrypted secrets for test-app")
}

// testSecretsEndpointValidation tests various validation scenarios
func testSecretsEndpointValidation(t *testing.T) {
	f := newTestSecretsFixture(t)

	req := kmsTypes.SecretsRequestV1{
		AppID:        "", // Missing
		Attestation:  []byte("test"),
		RSAPubKeyTmp: []byte("test-key"),
	}
	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	f.server.handleSecretsRequest(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing AppID, got %d", w.Code)
	}
}

// testSecretsEndpointImageDigestMismatch tests image digest validation
func testSecretsEndpointImageDigestMismatch(t *testing.T) {
	f := newTestSecretsFixture(t)

	testRelease := &kmsTypes.Release{
		ImageDigest:  "sha256:correct-digest",
		EncryptedEnv: "env-data",
		PublicEnv:    "PUBLIC=value",
		Timestamp:    time.Now().Unix(),
	}
	f.contractCallerStub.AddTestRelease("test-app", testRelease)

	testClaims := kmsTypes.AttestationClaims{
		AppID:       "test-app",
		ImageDigest: "sha256:wrong-digest", // Different from release
		IssuedAt:    time.Now().Unix(),
		PublicKey:   []byte("dummy-key"),
	}
	attestationBytes, err := json.Marshal(testClaims)
	if err != nil {
		t.Fatalf("Failed to marshal attestation claims: %v", err)
	}

	req := kmsTypes.SecretsRequestV1{
		AppID:             "test-app",
		AttestationMethod: "gcp",
		Attestation:       attestationBytes,
		RSAPubKeyTmp:      []byte("test-key"),
	}
	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	f.server.handleSecretsRequest(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for image digest mismatch, got %d", w.Code)
	}
}

// testSecretsEndpointTwoPhaseUpgrade verifies Fix 3 for KMS-009: in-flight requests that were
// issued before an app upgrade completes are not rejected after the developer calls upgradeApp().
//
// Race scenario without the fix:
//  1. App is running with image digest A (confirmed on-chain).
//  2. App sends attestation with digest A and the request enters the KMS pipeline.
//  3. Developer calls upgradeApp() -> on-chain digest immediately becomes B.
//  4. KMS processes the request, reads digest B, rejects the legitimate request.
//
// With two-phase upgrade:
//  1. upgradeApp() writes digest B to pendingRelease (confirmed release stays A).
//  2. In-flight request with digest A -> validated against confirmed release (A) -> succeeds.
//  3. Coordinator calls confirmUpgrade() -> confirmed release becomes B.
//  4. Requests with digest A now fail; requests with digest B succeed.
func testSecretsEndpointTwoPhaseUpgrade(t *testing.T) {
	f := newTestSecretsFixture(t)

	oldDigest := "sha256:old-image-digest"
	newDigest := "sha256:new-image-digest"

	// Start with old digest confirmed on-chain.
	confirmedRelease := &kmsTypes.Release{
		ImageDigest:  oldDigest,
		EncryptedEnv: "encrypted-env-data",
		PublicEnv:    "PUBLIC_VAR=value",
		Timestamp:    time.Now().Unix(),
	}
	f.contractCallerStub.AddTestRelease("test-app", confirmedRelease)

	_, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	makeRequest := func(imageDigest string) int {
		t.Helper()
		claims := kmsTypes.AttestationClaims{
			AppID:       "test-app",
			ImageDigest: imageDigest,
			IssuedAt:    time.Now().Unix(),
			PublicKey:   pubKeyPEM,
		}
		attestationBytes, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("Failed to marshal attestation claims: %v", err)
		}
		req := kmsTypes.SecretsRequestV1{
			AppID:             "test-app",
			AttestationMethod: "gcp",
			Attestation:       attestationBytes,
			RSAPubKeyTmp:      pubKeyPEM,
			AttestTime:        time.Now().Unix(),
		}
		body, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("Failed to marshal request: %v", err)
		}
		httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(body))
		w := httptest.NewRecorder()
		f.server.handleSecretsRequest(w, httpReq)
		return w.Code
	}

	// Phase 1: before upgrade — old digest succeeds.
	if code := makeRequest(oldDigest); code != http.StatusOK {
		t.Fatalf("Phase 1: expected 200 for old digest before upgrade, got %d", code)
	}

	// Simulate upgradeApp(): new digest written to pending state, confirmed release unchanged.
	pendingRelease := &kmsTypes.Release{
		ImageDigest:  newDigest,
		EncryptedEnv: "new-encrypted-env-data",
		PublicEnv:    "PUBLIC_VAR=new-value",
		Timestamp:    time.Now().Unix(),
	}
	f.contractCallerStub.SetPendingRelease("test-app", pendingRelease)

	// Phase 2: upgrade pending — in-flight request with old digest still succeeds (race condition fixed).
	if code := makeRequest(oldDigest); code != http.StatusOK {
		t.Fatalf("Phase 2: expected 200 for old digest while upgrade is pending, got %d (race condition not fixed)", code)
	}

	// Phase 2: new digest not yet confirmed — should be rejected.
	if code := makeRequest(newDigest); code != http.StatusForbidden {
		t.Fatalf("Phase 2: expected 403 for new digest before confirmation, got %d", code)
	}

	// Simulate confirmUpgrade(): Coordinator promotes pending release to confirmed.
	if err := f.contractCallerStub.ConfirmUpgrade("test-app"); err != nil {
		t.Fatalf("ConfirmUpgrade failed: %v", err)
	}

	// Phase 3: after confirmation — new digest succeeds, old digest is rejected.
	if code := makeRequest(newDigest); code != http.StatusOK {
		t.Fatalf("Phase 3: expected 200 for new digest after confirmation, got %d", code)
	}
	if code := makeRequest(oldDigest); code != http.StatusForbidden {
		t.Fatalf("Phase 3: expected 403 for old digest after confirmation, got %d", code)
	}
}
