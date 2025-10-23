package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// KMSClient provides a client interface for applications to retrieve secrets from KMS
type KMSClient struct {
	kmsServerURLs []string
	rsaEncryption *encryption.RSAEncryption
	threshold     int
}

// NewKMSClient creates a new KMS client
func NewKMSClient(kmsServerURLs []string) *KMSClient {
	threshold := dkg.CalculateThreshold(len(kmsServerURLs))
	return &KMSClient{
		kmsServerURLs: kmsServerURLs,
		rsaEncryption: encryption.NewRSAEncryption(),
		threshold:     threshold,
	}
}

// SecretsResult contains the recovered secrets and private key
type SecretsResult struct {
	AppPrivateKey   types.G1Point
	EncryptedEnv    string
	PublicEnv       string
	PartialSigs     map[int]types.G1Point
	ResponseCount   int
	ThresholdNeeded int
}

// RetrieveSecrets implements the complete application secret retrieval flow
func (c *KMSClient) RetrieveSecrets(appID, imageDigest string) (*SecretsResult, error) {
	fmt.Printf("KMS Client: Starting secret retrieval for app %s\n", appID)

	// Step 1: Generate ephemeral RSA key pair
	privKeyPEM, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}
	
	fmt.Printf("KMS Client: Generated ephemeral RSA key pair\n")

	// Step 2: Create runtime attestation (simulated)
	attestationClaims := types.AttestationClaims{
		AppID:       appID,
		ImageDigest: imageDigest,
		IssuedAt:    time.Now().Unix(),
		PublicKey:   pubKeyPEM,
	}
	attestationBytes, err := json.Marshal(attestationClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation: %w", err)
	}

	// Step 3: Create secrets request
	req := types.SecretsRequestV1{
		AppID:        appID,
		Attestation:  attestationBytes,
		RSAPubKeyTmp: pubKeyPEM,
		AttestTime:   time.Now().Unix(),
	}

	// Step 4: Request secrets from all KMS servers
	var responses []types.SecretsResponseV1
	var partialSigs []types.G1Point

	for i, serverURL := range c.kmsServerURLs {
		fmt.Printf("KMS Client: Requesting from server %d: %s\n", i+1, serverURL)

		resp, err := c.requestSecretsFromKMS(serverURL, req)
		if err != nil {
			fmt.Printf("KMS Client: Failed to get secrets from %s: %v\n", serverURL, err)
			continue
		}

		// Decrypt the partial signature
		decryptedSigBytes, err := c.rsaEncryption.Decrypt(resp.EncryptedPartialSig, privKeyPEM)
		if err != nil {
			fmt.Printf("KMS Client: Failed to decrypt partial signature from %s: %v\n", serverURL, err)
			continue
		}

		var partialSig types.G1Point
		if err := json.Unmarshal(decryptedSigBytes, &partialSig); err != nil {
			fmt.Printf("KMS Client: Failed to parse partial signature from %s: %v\n", serverURL, err)
			continue
		}

		responses = append(responses, *resp)
		partialSigs = append(partialSigs, partialSig)

		fmt.Printf("KMS Client: ✓ Received valid response from server %d\n", i+1)
	}

	// Step 5: Verify we have threshold responses
	if len(responses) < c.threshold {
		return nil, fmt.Errorf("insufficient responses: got %d, need %d", len(responses), c.threshold)
	}

	// Step 6: Verify all responses have consistent environment data
	expectedEnv := responses[0].EncryptedEnv
	for i, resp := range responses {
		if resp.EncryptedEnv != expectedEnv {
			return nil, fmt.Errorf("environment data mismatch from server %d", i+1)
		}
	}

	fmt.Printf("KMS Client: ✓ Verified threshold agreement on environment data\n")

	// Step 7: Recover application private key using threshold signatures
	partialSigMap := make(map[int]types.G1Point)
	for i, sig := range partialSigs {
		partialSigMap[i+1] = sig // Node IDs are 1-indexed
	}

	appPrivateKey := crypto.RecoverAppPrivateKey(appID, partialSigMap, c.threshold)

	if appPrivateKey.X.Sign() == 0 {
		return nil, fmt.Errorf("recovered application private key is invalid")
	}

	fmt.Printf("KMS Client: ✓ Successfully recovered application private key\n")

	return &SecretsResult{
		AppPrivateKey:   appPrivateKey,
		EncryptedEnv:    responses[0].EncryptedEnv,
		PublicEnv:       responses[0].PublicEnv,
		PartialSigs:     partialSigMap,
		ResponseCount:   len(responses),
		ThresholdNeeded: c.threshold,
	}, nil
}

// requestSecretsFromKMS makes an HTTP request to a single KMS server
func (c *KMSClient) requestSecretsFromKMS(serverURL string, req types.SecretsRequestV1) (*types.SecretsResponseV1, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(serverURL+"/secrets", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("KMS server returned status %d: %s", resp.StatusCode, string(body))
	}

	var response types.SecretsResponseV1
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &response, nil
}

// GetAppPublicKey returns the public key for an application (for encryption)
func GetAppPublicKey(appID string) types.G1Point {
	return crypto.GetAppPublicKey(appID)
}

// EncryptForApp encrypts data for a specific application using IBE
func (c *KMSClient) EncryptForApp(appID string, masterPublicKey types.G2Point, plaintext []byte) ([]byte, error) {
	return crypto.EncryptForApp(appID, masterPublicKey, plaintext)
}

// DecryptWithPrivateKey decrypts data using the recovered application private key
func (c *KMSClient) DecryptWithPrivateKey(appID string, appPrivateKey types.G1Point, ciphertext []byte) ([]byte, error) {
	return crypto.DecryptForApp(appID, appPrivateKey, ciphertext)
}