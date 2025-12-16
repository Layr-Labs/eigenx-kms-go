package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// ExampleAppClient demonstrates how an application would retrieve secrets from KMS
func ExampleAppClient() {
	appID := "demo-app"

	// Step 1: Generate ephemeral RSA key pair
	rsaEncrypt := encryption.NewRSAEncryption()
	privKeyPEM, pubKeyPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		fmt.Printf("Failed to generate RSA key pair: %v\n", err)
		return
	}

	fmt.Printf("Generated ephemeral RSA key pair\n")

	// Step 2: Create runtime attestation (in real app, this would be from TEE)
	testClaims := types.AttestationClaims{
		AppID:       appID,
		ImageDigest: "sha256:demo456", // Must match registry
		IssuedAt:    time.Now().Unix(),
		PublicKey:   pubKeyPEM,
	}
	attestationBytes, _ := json.Marshal(testClaims)

	// Step 3: Create secrets request (using stub/test attestation)
	// Note: In production, use "gcp" or "intel" with proper TEE attestation
	req := types.SecretsRequestV1{
		AppID:             appID,
		AttestationMethod: "gcp", // Can be "gcp", "intel", or "ecdsa"
		Attestation:       attestationBytes,
		RSAPubKeyTmp:      pubKeyPEM,
		AttestTime:        time.Now().Unix(),
	}

	// Step 4: Request secrets from multiple KMS servers (threshold required)
	kmsServers := []string{
		"http://localhost:8001",
		"http://localhost:8002",
		"http://localhost:8003",
	}

	var responses []types.SecretsResponseV1
	var partialSigs []types.G1Point

	for i, serverURL := range kmsServers {
		fmt.Printf("Requesting secrets from KMS server %d: %s\n", i+1, serverURL)

		resp, err := requestSecretsFromKMS(serverURL, req)
		if err != nil {
			fmt.Printf("Failed to get secrets from %s: %v\n", serverURL, err)
			continue
		}

		// Decrypt the partial signature
		decryptedSigBytes, err := rsaEncrypt.Decrypt(resp.EncryptedPartialSig, privKeyPEM)
		if err != nil {
			fmt.Printf("Failed to decrypt partial signature from %s: %v\n", serverURL, err)
			continue
		}

		var partialSig types.G1Point
		if err := json.Unmarshal(decryptedSigBytes, &partialSig); err != nil {
			fmt.Printf("Failed to parse partial signature from %s: %v\n", serverURL, err)
			continue
		}

		responses = append(responses, *resp)
		partialSigs = append(partialSigs, partialSig)

		fmt.Printf("Successfully received response from %s\n", serverURL)
	}

	// Step 5: Verify we have threshold responses
	threshold := (2*len(kmsServers) + 2) / 3 // ⌈2n/3⌉
	if len(responses) < threshold {
		fmt.Printf("Insufficient responses: got %d, need %d\n", len(responses), threshold)
		return
	}

	// Step 6: Verify all responses have consistent environment data
	expectedEnv := responses[0].EncryptedEnv
	for i, resp := range responses {
		if resp.EncryptedEnv != expectedEnv {
			fmt.Printf("Inconsistent environment data from server %d\n", i)
			return
		}
	}

	// Step 7: Recover application private key using Lagrange interpolation
	partialSigMap := make(map[int64]types.G1Point)
	for i, sig := range partialSigs {
		partialSigMap[int64(i+1)] = sig // Node IDs are 1-indexed
	}

	appPrivateKey, err := crypto.RecoverAppPrivateKey(appID, partialSigMap, threshold)
	if err != nil {
		fmt.Printf("Failed to recover application private key: %v\n", err)
		return
	}

	fmt.Printf("Successfully recovered application private key!\n")
	fmt.Printf("Private key: %s\n", hex.EncodeToString(appPrivateKey.CompressedBytes[:8]))

	// Step 8: Use the private key to decrypt environment variables
	// In a real application, you would:
	// 1. Decrypt the encrypted_env using the app_private_key
	// 2. Generate mnemonic using HKDF(app_private_key)
	// 3. Source the environment variables and start application logic

	fmt.Printf("Encrypted environment: %s\n", responses[0].EncryptedEnv)
	fmt.Printf("Public environment: %s\n", responses[0].PublicEnv)
	fmt.Printf("Application can now decrypt secrets and start!\n")
}

// requestSecretsFromKMS makes an HTTP request to a KMS server
func requestSecretsFromKMS(serverURL string, req types.SecretsRequestV1) (*types.SecretsResponseV1, error) {
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

func main() {
	fmt.Println("=== EigenX KMS Client Example ===")
	fmt.Println("This example shows how applications retrieve secrets from KMS")
	fmt.Println("Note: Start KMS servers first with 'go run cmd/poc/main.go'")
	fmt.Println()

	ExampleAppClient()
}
