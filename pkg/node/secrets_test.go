package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/registry"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func Test_SecretsEndpoint(t *testing.T) {
	t.Run("Flow", func(t *testing.T) { testSecretsEndpointFlow(t) })
	t.Run("Validation", func(t *testing.T) { testSecretsEndpointValidation(t) })
	t.Run("ImageDigestMismatch", func(t *testing.T) { testSecretsEndpointImageDigestMismatch(t) })
}

// createTestPeeringDataFetcher creates a test peering data fetcher
func createTestPeeringDataFetcher(operators []types.OperatorInfo) peering.IPeeringDataFetcher {
	// Use the stub for testing
	return peering.NewStubPeeringDataFetcher(nil)
}

// testSecretsEndpointFlow tests the complete application secrets retrieval flow
func testSecretsEndpointFlow(t *testing.T) {
	// Setup test node with a mock key share
	operators := []types.OperatorInfo{
		{ID: 1, P2PPubKey: []byte("key1"), P2PNodeURL: "http://node1", KMSServerURL: "http://kms1"},
	}
	
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	cfg := Config{
		ID:         1,
		Port:       0, // Use random port
		P2PPrivKey: []byte("test-priv-key"),
		P2PPubKey:  []byte("test-pub-key"),
		Operators:  operators,
		Logger:     testLogger,
	}
	
	peeringDataFetcher := createTestPeeringDataFetcher(operators)
	node := NewNode(cfg, peeringDataFetcher)
	
	// Add a test key share
	testShare := new(fr.Element).SetInt64(42)
	keyVersion := &types.KeyShareVersion{
		Version:        time.Now().Unix(),
		PrivateShare:   testShare,
		Commitments:    []types.G2Point{},
		IsActive:       true,
		ParticipantIDs: []int{1},
	}
	node.keyStore.AddVersion(keyVersion)
	
	// Generate ephemeral RSA key pair for the test
	rsaEncrypt := encryption.NewRSAEncryption()
	privKeyPEM, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	
	// Add test release to registry
	testRelease := &types.Release{
		ImageDigest:  "sha256:test123",
		EncryptedEnv: "encrypted-env-data-for-test-app",
		PublicEnv:    "PUBLIC_VAR=test-value",
		Timestamp:    time.Now().Unix(),
	}
	stubRegistry, ok := node.releaseRegistry.(*registry.StubClient)
	if !ok {
		t.Fatal("Expected StubClient for release registry")
	}
	stubRegistry.AddTestRelease("test-app", testRelease)
	
	// Create test attestation with matching claims
	testClaims := types.AttestationClaims{
		AppID:       "test-app",
		ImageDigest: "sha256:test123", // Matches release
		IssuedAt:    time.Now().Unix(),
		PublicKey:   pubKeyPEM,
	}
	attestationBytes, _ := json.Marshal(testClaims)
	
	// Create secrets request
	req := types.SecretsRequestV1{
		AppID:        "test-app",
		Attestation:  attestationBytes,
		RSAPubKeyTmp: pubKeyPEM,
		AttestTime:   time.Now().Unix(),
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
	var resp types.SecretsResponseV1
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
	var partialSig types.G1Point
	if err := json.Unmarshal(decryptedSigBytes, &partialSig); err != nil {
		t.Fatalf("Failed to parse partial signature: %v", err)
	}
	
	// Verify it's not zero
	if partialSig.X.Sign() == 0 {
		t.Error("Partial signature should not be zero")
	}
	
	fmt.Printf("Test passed: Successfully retrieved and decrypted secrets for test-app\n")
}

// testSecretsEndpointValidation tests various validation scenarios
func testSecretsEndpointValidation(t *testing.T) {
	// Setup test node
	operators := []types.OperatorInfo{
		{ID: 1, P2PPubKey: []byte("key1"), P2PNodeURL: "http://node1", KMSServerURL: "http://kms1"},
	}
	
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	peeringDataFetcher := createTestPeeringDataFetcher(operators)
	node := NewNode(Config{
		ID:         1,
		Port:       0,
		P2PPrivKey: []byte("test-priv-key"),
		P2PPubKey:  []byte("test-pub-key"),
		Operators:  operators,
		Logger:     testLogger,
	}, peeringDataFetcher)
	
	server := NewServer(node, 0)
	
	tests := []struct {
		name           string
		request        types.SecretsRequestV1
		expectedStatus int
		description    string
	}{
		{
			name: "missing app_id",
			request: types.SecretsRequestV1{
				AppID:        "",
				Attestation:  []byte("test"),
				RSAPubKeyTmp: []byte("test-pubkey"),
				AttestTime:   time.Now().Unix(),
			},
			expectedStatus: http.StatusBadRequest,
			description:    "Should reject empty app_id",
		},
		{
			name: "missing rsa_pubkey",
			request: types.SecretsRequestV1{
				AppID:        "test-app",
				Attestation:  []byte("test"),
				RSAPubKeyTmp: []byte{},
				AttestTime:   time.Now().Unix(),
			},
			expectedStatus: http.StatusBadRequest,
			description:    "Should reject empty RSA public key",
		},
		{
			name: "nonexistent app",
			request: types.SecretsRequestV1{
				AppID:        "nonexistent-app",
				Attestation:  []byte("test"),
				RSAPubKeyTmp: []byte("test-pubkey"),
				AttestTime:   time.Now().Unix(),
			},
			expectedStatus: http.StatusNotFound,
			description:    "Should reject unknown app_id",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(tt.request)
			httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
			httpReq.Header.Set("Content-Type", "application/json")
			
			w := httptest.NewRecorder()
			server.handleSecretsRequest(w, httpReq)
			
			if w.Code != tt.expectedStatus {
				t.Errorf("%s: Expected status %d, got %d. Body: %s", 
					tt.description, tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

// testSecretsEndpointImageDigestMismatch tests image digest validation
func testSecretsEndpointImageDigestMismatch(t *testing.T) {
	// Setup test node
	operators := []types.OperatorInfo{
		{ID: 1, P2PPubKey: []byte("key1"), P2PNodeURL: "http://node1", KMSServerURL: "http://kms1"},
	}
	
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	peeringDataFetcher := createTestPeeringDataFetcher(operators)
	node := NewNode(Config{
		ID:         1,
		Port:       0,
		P2PPrivKey: []byte("test-priv-key"),
		P2PPubKey:  []byte("test-pub-key"),
		Operators:  operators,
		Logger:     testLogger,
	}, peeringDataFetcher)
	
	// Create attestation with wrong image digest
	testClaims := types.AttestationClaims{
		AppID:       "test-app",
		ImageDigest: "sha256:wrong-digest", // Different from registry
		IssuedAt:    time.Now().Unix(),
		PublicKey:   []byte("test-pubkey"),
	}
	attestationBytes, _ := json.Marshal(testClaims)
	
	req := types.SecretsRequestV1{
		AppID:        "test-app",
		Attestation:  attestationBytes,
		RSAPubKeyTmp: []byte("test-pubkey"),
		AttestTime:   time.Now().Unix(),
	}
	
	reqBody, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	server := NewServer(node, 0)
	server.handleSecretsRequest(w, httpReq)
	
	// Should reject with 403 Forbidden due to image digest mismatch
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for image digest mismatch, got %d. Body: %s", 
			w.Code, w.Body.String())
	}
}