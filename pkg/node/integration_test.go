package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/registry"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

func Test_ApplicationSecrets(t *testing.T) {
	t.Run("Flow", func(t *testing.T) { testApplicationSecretsFlow(t) })
}

// testApplicationSecretsFlow tests the complete end-to-end flow as specified in the design docs
func testApplicationSecretsFlow(t *testing.T) {
	// Setup: Create 3 KMS nodes with DKG key shares
	numNodes := 3
	threshold := dkg.CalculateThreshold(numNodes)
	operators := make([]types.OperatorInfo, numNodes)
	nodes := make([]*Node, numNodes)
	servers := make([]*httptest.Server, numNodes)
	
	// Create operators
	for i := 0; i < numNodes; i++ {
		operators[i] = types.OperatorInfo{
			ID:           i + 1,
			P2PPubKey:    []byte(fmt.Sprintf("pubkey-%d", i+1)),
			P2PNodeURL:   fmt.Sprintf("http://node%d", i+1),
			KMSServerURL: fmt.Sprintf("http://kms%d", i+1),
		}
	}
	
	// Create shared secret and polynomial for proper DKG simulation
	masterSecret := new(fr.Element).SetInt64(12345)
	poly := make(polynomial.Polynomial, threshold)
	poly[0].Set(masterSecret)
	for i := 1; i < threshold; i++ {
		poly[i].SetRandom()
	}
	
	// Create nodes and test servers
	for i := 0; i < numNodes; i++ {
		cfg := Config{
			ID:         i + 1,
			Port:       8000 + i + 1,
			P2PPrivKey: []byte(fmt.Sprintf("privkey-%d", i+1)),
			P2PPubKey:  []byte(fmt.Sprintf("pubkey-%d", i+1)),
			Operators:  operators,
		}
		
		nodes[i] = NewNode(cfg)
		
		// Add proper polynomial-based key shares (simulate successful DKG)
		keyShare := crypto.EvaluatePolynomial(poly, i+1) // Node IDs are 1-indexed
		keyVersion := &types.KeyShareVersion{
			Version:        time.Now().Unix(),
			PrivateShare:   keyShare,
			Commitments:    []types.G2Point{},
			IsActive:       true,
			ParticipantIDs: []int{1, 2, 3},
		}
		nodes[i].keyStore.AddVersion(keyVersion)
		
		// Create test server
		server := NewServer(nodes[i], 0)
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/secrets" {
				server.handleSecretsRequest(w, r)
			} else {
				http.NotFound(w, r)
			}
		}))
		
		// Add test release to each node's registry
		testRelease := &types.Release{
			ImageDigest:  "sha256:app123",
			EncryptedEnv: "encrypted-secrets-for-my-app",
			PublicEnv:    "NODE_ENV=production",
			Timestamp:    time.Now().Unix(),
		}
		stubRegistry := nodes[i].releaseRegistry.(*registry.StubClient)
		stubRegistry.AddTestRelease("my-app", testRelease)
	}
	
	defer func() {
		for _, server := range servers {
			server.Close()
		}
	}()
	
	// Application Flow: Request secrets from all KMS servers
	
	// Step 1: Generate ephemeral RSA key pair (as application would)
	rsaEncrypt := encryption.NewRSAEncryption()
	privKeyPEM, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	
	// Step 2: Create runtime attestation
	attestationClaims := types.AttestationClaims{
		AppID:       "my-app",
		ImageDigest: "sha256:app123",
		IssuedAt:    time.Now().Unix(),
		PublicKey:   pubKeyPEM,
	}
	attestationBytes, _ := json.Marshal(attestationClaims)
	
	// Step 3: Create secrets request
	req := types.SecretsRequestV1{
		AppID:        "my-app",
		Attestation:  attestationBytes,
		RSAPubKeyTmp: pubKeyPEM,
		AttestTime:   time.Now().Unix(),
	}
	
	// Step 4: Loop through all KMS servers
	var responses []types.SecretsResponseV1
	var partialSigs []types.G1Point
	
	for i, server := range servers {
		reqBody, _ := json.Marshal(req)
		
		resp, err := http.Post(server.URL+"/secrets", "application/json", bytes.NewBuffer(reqBody))
		if err != nil {
			t.Fatalf("Failed to request secrets from server %d: %v", i+1, err)
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Server %d returned status %d: %s", i+1, resp.StatusCode, string(body))
		}
		
		var secretsResp types.SecretsResponseV1
		if err := json.NewDecoder(resp.Body).Decode(&secretsResp); err != nil {
			t.Fatalf("Failed to parse response from server %d: %v", i+1, err)
		}
		
		// Decrypt partial signature
		decryptedSigBytes, err := rsaEncrypt.Decrypt(secretsResp.EncryptedPartialSig, privKeyPEM)
		if err != nil {
			t.Fatalf("Failed to decrypt partial signature from server %d: %v", i+1, err)
		}
		
		var partialSig types.G1Point
		if err := json.Unmarshal(decryptedSigBytes, &partialSig); err != nil {
			t.Fatalf("Failed to parse partial signature from server %d: %v", i+1, err)
		}
		
		responses = append(responses, secretsResp)
		partialSigs = append(partialSigs, partialSig)
		
		fmt.Printf("Received valid response from KMS node %d\n", i+1)
	}
	
	// Step 5: Verify threshold agreement on environment data
	if len(responses) < threshold {
		t.Fatalf("Insufficient responses: got %d, need %d", len(responses), threshold)
	}
	
	// Verify all nodes returned same encrypted environment
	expectedEnv := responses[0].EncryptedEnv
	for i, resp := range responses {
		if resp.EncryptedEnv != expectedEnv {
			t.Fatalf("Environment mismatch from server %d", i+1)
		}
	}
	
	// Step 6: Recover application private key using threshold signatures
	partialSigMap := make(map[int]types.G1Point)
	for i, sig := range partialSigs {
		partialSigMap[i+1] = sig
	}
	
	appPrivateKey := crypto.RecoverAppPrivateKey("my-app", partialSigMap, threshold)
	
	// Step 7: Verify the recovered key is valid (non-zero)
	if appPrivateKey.X.Sign() == 0 {
		t.Fatal("Recovered application private key should not be zero")
	}
	
	// Step 8: In a real application, you would now:
	// - Verify appPrivateKey against master public key
	// - Decrypt encrypted_env with IBE using appPrivateKey
	// - Generate mnemonic using HKDF(appPrivateKey)
	// - Source environment variables and start application
	
	fmt.Printf("✓ Successfully completed application secrets flow!\n")
	fmt.Printf("  - Retrieved secrets from %d KMS servers\n", len(responses))
	fmt.Printf("  - Verified threshold agreement on environment data\n")
	fmt.Printf("  - Recovered application private key via threshold signatures\n")
	fmt.Printf("  - Encrypted env: %s\n", responses[0].EncryptedEnv)
	fmt.Printf("  - Public env: %s\n", responses[0].PublicEnv)
}

// Helper function to make HTTP request to KMS server
func requestSecretsFromKMS(serverURL string, req types.SecretsRequestV1) (*types.SecretsResponseV1, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	
	resp, err := http.Post(serverURL+"/secrets", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	
	var response types.SecretsResponseV1
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	
	return &response, nil
}