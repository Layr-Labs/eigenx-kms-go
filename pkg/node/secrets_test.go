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

func Test_SecretsEndpoint(t *testing.T) {
	t.Run("Flow", func(t *testing.T) { testSecretsEndpointFlow(t) })
	t.Run("Validation", func(t *testing.T) { testSecretsEndpointValidation(t) })
	t.Run("ImageDigestMismatch", func(t *testing.T) { testSecretsEndpointImageDigestMismatch(t) })
	t.Run("AppIDMismatch", func(t *testing.T) { testSecretsEndpointAppIDMismatch(t) })
	t.Run("ContainerPolicyMismatch", func(t *testing.T) { testSecretsEndpointContainerPolicyMismatch(t) })
	t.Run("ContainerPolicyCmdOverrideMismatch", func(t *testing.T) { testSecretsEndpointCmdOverrideMismatch(t) })
	t.Run("ContainerPolicyEnvOverrideMismatch", func(t *testing.T) { testSecretsEndpointEnvOverrideMismatch(t) })
	t.Run("ContainerPolicyEnvOverrideSuccess", func(t *testing.T) { testSecretsEndpointEnvOverrideSuccess(t) })
	t.Run("ContainerPolicySuccess", func(t *testing.T) { testSecretsEndpointContainerPolicySuccess(t) })
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

// newTestServer creates a test Server backed by a mock contract caller with no pre-configured
// releases. Use mockCaller.AddTestRelease to set up releases and server.node.keyStore.AddVersion
// to add key shares as needed by each test.
func newTestServer(t *testing.T) (*Server, *contractCaller.TestableContractCallerStub) {
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

	persistence := memory.NewMemoryPersistence()
	t.Cleanup(func() { _ = persistence.Close() })

	bh := blockHandler.NewBlockHandler(testLogger)
	node, err := NewNode(cfg, createTestPeeringDataFetcher(t), bh, &mockChainPoller{}, imts, mockManager, mockBaseContractCaller, mockRegistryAddress, persistence, testLogger)
	if err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	return NewServer(node, 0), mockBaseContractCaller
}

// testSecretsEndpointFlow tests the complete application secrets retrieval flow
func testSecretsEndpointFlow(t *testing.T) {
	server, mockCaller := newTestServer(t)

	testRelease := &kmsTypes.Release{
		ImageDigest:  "sha256:test123",
		EncryptedEnv: "encrypted-env-data-for-test-app",
		PublicEnv:    "PUBLIC_VAR=test-value",
		Timestamp:    time.Now().Unix(),
	}
	mockCaller.AddTestRelease("test-app", testRelease)

	server.node.keyStore.AddVersion(&kmsTypes.KeyShareVersion{
		Version:        time.Now().Unix(),
		PrivateShare:   new(fr.Element).SetInt64(42),
		Commitments:    []kmsTypes.G2Point{},
		IsActive:       true,
		ParticipantIDs: []int64{1},
	})

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
	attestationBytes, _ := json.Marshal(testClaims)

	req := kmsTypes.SecretsRequestV1{
		AppID:             "test-app",
		AttestationMethod: "gcp",
		Attestation:       attestationBytes,
		RSAPubKeyTmp:      pubKeyPEM,
		AttestationTime:   time.Now().Unix(),
	}
	reqBody, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleSecretsRequest(w, httpReq)

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
}

// testSecretsEndpointValidation tests various validation scenarios
func testSecretsEndpointValidation(t *testing.T) {
	server, _ := newTestServer(t)

	req := kmsTypes.SecretsRequestV1{
		AppID:        "", // Missing
		Attestation:  []byte("test"),
		RSAPubKeyTmp: []byte("test-key"),
	}
	reqBody, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	server.handleSecretsRequest(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing AppID, got %d", w.Code)
	}
}

// testSecretsEndpointImageDigestMismatch tests image digest validation
func testSecretsEndpointImageDigestMismatch(t *testing.T) {
	server, mockCaller := newTestServer(t)

	mockCaller.AddTestRelease("test-app", &kmsTypes.Release{
		ImageDigest:  "sha256:correct-digest",
		EncryptedEnv: "env-data",
		PublicEnv:    "PUBLIC=value",
		Timestamp:    time.Now().Unix(),
	})

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

	server.handleSecretsRequest(w, httpReq)

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

// testSecretsEndpointContainerPolicyMismatch tests that mismatched container execution
// fields are rejected even when the image digest matches.
func testSecretsEndpointContainerPolicyMismatch(t *testing.T) {
	server, mockCaller := newTestServer(t)

	mockCaller.AddTestRelease("test-app", &kmsTypes.Release{
		ImageDigest:  "sha256:correct-digest",
		EncryptedEnv: "env-data",
		PublicEnv:    "PUBLIC=value",
		Timestamp:    time.Now().Unix(),
		ContainerPolicy: kmsTypes.ContainerPolicy{
			Args:          []string{"/entrypoint.sh", "start"},
			RestartPolicy: "Never",
		},
	})

	testClaims := kmsTypes.AttestationClaims{
		AppID:       "test-app",
		ImageDigest: "sha256:correct-digest",
		ContainerPolicy: kmsTypes.ContainerPolicy{
			Args:          []string{"/malicious.sh", "exploit"}, // wrong args
			RestartPolicy: "Never",
		},
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

	server.handleSecretsRequest(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for container policy mismatch, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// testSecretsEndpointCmdOverrideMismatch tests that a CmdOverride mismatch is rejected.
func testSecretsEndpointCmdOverrideMismatch(t *testing.T) {
	server, mockCaller := newTestServer(t)

	mockCaller.AddTestRelease("test-app", &kmsTypes.Release{
		ImageDigest:  "sha256:correct-digest",
		EncryptedEnv: "env-data",
		PublicEnv:    "PUBLIC=value",
		Timestamp:    time.Now().Unix(),
		ContainerPolicy: kmsTypes.ContainerPolicy{
			CmdOverride: []string{"/bin/server", "--port=8080"},
		},
	})

	testClaims := kmsTypes.AttestationClaims{
		AppID:       "test-app",
		ImageDigest: "sha256:correct-digest",
		ContainerPolicy: kmsTypes.ContainerPolicy{
			CmdOverride: []string{"/bin/server", "--port=9999"}, // wrong port
		},
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

	server.handleSecretsRequest(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for cmd_override mismatch, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// testSecretsEndpointEnvOverrideMismatch tests that an EnvOverride value mismatch is rejected.
func testSecretsEndpointEnvOverrideMismatch(t *testing.T) {
	server, mockCaller := newTestServer(t)

	mockCaller.AddTestRelease("test-app", &kmsTypes.Release{
		ImageDigest:  "sha256:correct-digest",
		EncryptedEnv: "env-data",
		PublicEnv:    "PUBLIC=value",
		Timestamp:    time.Now().Unix(),
		ContainerPolicy: kmsTypes.ContainerPolicy{
			EnvOverride: map[string]string{"LOG_LEVEL": "info"},
		},
	})

	testClaims := kmsTypes.AttestationClaims{
		AppID:       "test-app",
		ImageDigest: "sha256:correct-digest",
		ContainerPolicy: kmsTypes.ContainerPolicy{
			EnvOverride: map[string]string{"LOG_LEVEL": "debug"}, // wrong value
		},
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

	server.handleSecretsRequest(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for env_override mismatch, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// testSecretsEndpointEnvOverrideSuccess tests that extra EnvOverride keys beyond the policy are allowed.
func testSecretsEndpointEnvOverrideSuccess(t *testing.T) {
	server, mockCaller := newTestServer(t)

	mockCaller.AddTestRelease("test-app", &kmsTypes.Release{
		ImageDigest:  "sha256:correct-digest",
		EncryptedEnv: "env-data",
		PublicEnv:    "PUBLIC=value",
		Timestamp:    time.Now().Unix(),
		ContainerPolicy: kmsTypes.ContainerPolicy{
			EnvOverride: map[string]string{"LOG_LEVEL": "info"},
		},
	})

	server.node.keyStore.AddVersion(&kmsTypes.KeyShareVersion{
		Version:        time.Now().Unix(),
		PrivateShare:   new(fr.Element).SetInt64(42),
		Commitments:    []kmsTypes.G2Point{},
		IsActive:       true,
		ParticipantIDs: []int64{1},
	})

	_, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	testClaims := kmsTypes.AttestationClaims{
		AppID:       "test-app",
		ImageDigest: "sha256:correct-digest",
		ContainerPolicy: kmsTypes.ContainerPolicy{
			EnvOverride: map[string]string{
				"LOG_LEVEL": "info",
				"REGION":    "us-east-1", // extra key not in policy — must still pass
			},
		},
	}
	attestationBytes, _ := json.Marshal(testClaims)

	req := kmsTypes.SecretsRequestV1{
		AppID:             "test-app",
		AttestationMethod: "gcp",
		Attestation:       attestationBytes,
		RSAPubKeyTmp:      pubKeyPEM,
		AttestTime:        time.Now().Unix(),
	}
	reqBody, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	server.handleSecretsRequest(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 when env_override is a superset of policy, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// testSecretsEndpointContainerPolicySuccess tests that a request succeeds when all
// container execution fields match the on-chain policy, including extra env vars not in
// the policy (which are allowed).
func testSecretsEndpointContainerPolicySuccess(t *testing.T) {
	server, mockCaller := newTestServer(t)

	mockCaller.AddTestRelease("my-app", &kmsTypes.Release{
		ImageDigest:  "sha256:app-digest",
		EncryptedEnv: "encrypted-env-data",
		PublicEnv:    "PUBLIC=value",
		Timestamp:    time.Now().Unix(),
		ContainerPolicy: kmsTypes.ContainerPolicy{
			Args:          []string{"/entrypoint.sh", "start"},
			RestartPolicy: "Never",
			Env:           map[string]string{"APP_MODE": "production"},
		},
	})

	server.node.keyStore.AddVersion(&kmsTypes.KeyShareVersion{
		Version:        time.Now().Unix(),
		PrivateShare:   new(fr.Element).SetInt64(99),
		Commitments:    []kmsTypes.G2Point{},
		IsActive:       true,
		ParticipantIDs: []int64{1},
	})

	_, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Attestation claims match the on-chain policy exactly; extra env vars are allowed
	testClaims := kmsTypes.AttestationClaims{
		AppID:       "my-app",
		ImageDigest: "sha256:app-digest",
		ContainerPolicy: kmsTypes.ContainerPolicy{
			Args:          []string{"/entrypoint.sh", "start"},
			RestartPolicy: "Never",
			Env: map[string]string{
				"APP_MODE": "production",
				"HOSTNAME": "tee-instance", // extra env var not in policy — must still pass
			},
		},
	}
	attestationBytes, _ := json.Marshal(testClaims)

	req := kmsTypes.SecretsRequestV1{
		AppID:             "my-app",
		AttestationMethod: "gcp",
		Attestation:       attestationBytes,
		RSAPubKeyTmp:      pubKeyPEM,
		AttestTime:        time.Now().Unix(),
	}
	reqBody, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	server.handleSecretsRequest(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 when container policy matches, got %d. Body: %s", w.Code, w.Body.String())
	}
}
