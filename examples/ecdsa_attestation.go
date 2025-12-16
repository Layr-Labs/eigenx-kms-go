package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	kmscrypto "github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/crypto"
)

/*
ECDSA Attestation Example

This example demonstrates how to use ECDSA attestation with the KMS /secrets endpoint.
ECDSA attestation is simpler than GCP Confidential Space but provides proof of key ownership.

Flow:
1. Generate application's ECDSA key pair (represents app identity)
2. Generate ephemeral RSA key pair (for encrypted response)
3. Create challenge (timestamp + nonce)
4. Sign challenge with app's ECDSA private key
5. Request secrets from KMS with ECDSA attestation
6. Decrypt partial signatures and recover app private key

Security Note:
- ECDSA attestation only proves key ownership, not TEE execution
- Suitable for development/testing, not production secrets
- For production, use GCP Confidential Space or Intel Trust Authority
*/

func main() {
	fmt.Println("=== ECDSA Attestation Example ===")
	fmt.Println("Demonstrating secret retrieval using ECDSA challenge-response attestation")
	fmt.Println()

	// Configuration
	appID := "ecdsa-demo-app"
	kmsServers := []string{
		"http://localhost:8001",
		"http://localhost:8002",
		"http://localhost:8003",
	}

	// Step 1: Generate application's ECDSA key pair (this represents the app's identity)
	fmt.Println("📝 Step 1: Generating application ECDSA key pair...")
	appPrivateKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Printf("❌ Failed to generate ECDSA key: %v\n", err)
		return
	}
	appPublicKey := crypto.FromECDSAPub(&appPrivateKey.PublicKey)
	appAddress := crypto.PubkeyToAddress(appPrivateKey.PublicKey)
	fmt.Printf("✅ Generated ECDSA key pair\n")
	fmt.Printf("   Address: %s\n", appAddress.Hex())
	fmt.Printf("   Public Key: %s\n", hex.EncodeToString(appPublicKey[:32])+"...")
	fmt.Println()

	// Step 2: Generate ephemeral RSA key pair for encrypted response
	fmt.Println("🔐 Step 2: Generating ephemeral RSA key pair...")
	rsaEncrypt := encryption.NewRSAEncryption()
	rsaPrivKeyPEM, rsaPubKeyPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		fmt.Printf("❌ Failed to generate RSA key pair: %v\n", err)
		return
	}
	fmt.Println("✅ Generated RSA ephemeral key pair")
	fmt.Println()

	// Step 3: Create ECDSA attestation challenge
	fmt.Println("🎲 Step 3: Creating attestation challenge...")
	nonce := make([]byte, attestation.NonceLength)
	if _, err := rand.Read(nonce); err != nil {
		fmt.Printf("❌ Failed to generate nonce: %v\n", err)
		return
	}

	challenge, err := attestation.GenerateChallenge(nonce)
	if err != nil {
		fmt.Printf("❌ Failed to generate challenge: %v\n", err)
		return
	}
	fmt.Printf("✅ Generated challenge: %s\n", challenge[:50]+"...")
	fmt.Println()

	// Step 4: Sign the challenge
	fmt.Println("✍️  Step 4: Signing challenge with app private key...")
	signature, err := attestation.SignChallenge(appPrivateKey, appID, challenge)
	if err != nil {
		fmt.Printf("❌ Failed to sign challenge: %v\n", err)
		return
	}
	fmt.Printf("✅ Signature created: %s\n", hex.EncodeToString(signature[:32])+"...")
	fmt.Println()

	// Step 5: Request secrets from KMS servers
	fmt.Println("🌐 Step 5: Requesting secrets from KMS operators...")

	req := types.SecretsRequestV1{
		AppID:             appID,
		AttestationMethod: "ecdsa",
		Attestation:       signature,
		Challenge:         []byte(challenge),
		PublicKey:         appPublicKey,
		RSAPubKeyTmp:      rsaPubKeyPEM,
		AttestTime:        0, // Use current key version
	}

	var responses []types.SecretsResponseV1
	var partialSigs []types.G1Point

	for i, serverURL := range kmsServers {
		fmt.Printf("   [%d/%d] Contacting %s...\n", i+1, len(kmsServers), serverURL)

		resp, err := requestSecretsFromKMS(serverURL, req)
		if err != nil {
			fmt.Printf("   ⚠️  Failed: %v\n", err)
			continue
		}

		// Decrypt the partial signature using RSA private key
		decryptedSigBytes, err := rsaEncrypt.Decrypt(resp.EncryptedPartialSig, rsaPrivKeyPEM)
		if err != nil {
			fmt.Printf("   ❌ Failed to decrypt partial signature: %v\n", err)
			continue
		}

		var partialSig types.G1Point
		if err := json.Unmarshal(decryptedSigBytes, &partialSig); err != nil {
			fmt.Printf("   ❌ Failed to parse partial signature: %v\n", err)
			continue
		}

		responses = append(responses, *resp)
		partialSigs = append(partialSigs, partialSig)
		fmt.Printf("   ✅ Received partial signature\n")
	}
	fmt.Println()

	// Step 6: Verify threshold
	threshold := (2*len(kmsServers) + 2) / 3 // ⌈2n/3⌉
	fmt.Printf("📊 Step 6: Verifying threshold responses...\n")
	fmt.Printf("   Received: %d responses\n", len(responses))
	fmt.Printf("   Threshold: %d required\n", threshold)

	if len(responses) < threshold {
		fmt.Printf("❌ Insufficient responses: got %d, need %d\n", len(responses), threshold)
		return
	}
	fmt.Println("✅ Threshold met!")
	fmt.Println()

	// Step 7: Recover application private key
	fmt.Println("🔓 Step 7: Recovering application private key...")
	partialSigMap := make(map[int64]types.G1Point)
	for i, sig := range partialSigs {
		partialSigMap[int64(i+1)] = sig
	}

	appPrivKey, err := kmscrypto.RecoverAppPrivateKey(appID, partialSigMap, threshold)
	if err != nil {
		fmt.Printf("❌ Failed to recover app private key: %v\n", err)
		return
	}
	fmt.Printf("✅ Successfully recovered app private key!\n")
	fmt.Printf("   Key (first 16 bytes): %s...\n", hex.EncodeToString(appPrivKey.CompressedBytes[:16]))
	fmt.Println()

	// Step 8: Display results
	fmt.Println("📦 Step 8: Retrieved secrets:")
	fmt.Printf("   Encrypted Env: %s\n", responses[0].EncryptedEnv)
	fmt.Printf("   Public Env: %s\n", responses[0].PublicEnv)
	fmt.Println()

	fmt.Println("✅ ECDSA attestation flow completed successfully!")
	fmt.Println()
	fmt.Println("💡 Next steps:")
	fmt.Println("   1. Use app private key to decrypt encrypted_env")
	fmt.Println("   2. Derive symmetric keys using HKDF(app_private_key)")
	fmt.Println("   3. Load decrypted environment variables")
	fmt.Println("   4. Start application with secrets")
}

// requestSecretsFromKMS makes an HTTP request to a KMS server's /secrets endpoint
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
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var response types.SecretsResponseV1
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &response, nil
}
