package kmsClient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/ethereum/go-ethereum/common"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/util"
)

// KMSClient provides a client interface for applications to interact with KMS operators
type KMSClient struct {
	operatorURLs  []string
	rsaEncryption *encryption.RSAEncryption
	threshold     int
	logger        *zap.Logger
}

// NewKMSClient creates a new KMS client with operator URLs
func NewKMSClient(operatorURLs []string, logger *zap.Logger) *KMSClient {
	threshold := dkg.CalculateThreshold(len(operatorURLs))
	return &KMSClient{
		operatorURLs:  operatorURLs,
		rsaEncryption: encryption.NewRSAEncryption(),
		threshold:     threshold,
		logger:        logger,
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

	for i, serverURL := range c.operatorURLs {
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

	appPrivateKey, err := crypto.RecoverAppPrivateKey(appID, partialSigMap, c.threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to recover app private key: %w", err)
	}

	fmt.Printf("KMS Client: ✓ Successfully recovered application private key\n")

	return &SecretsResult{
		AppPrivateKey:   *appPrivateKey,
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

// GetMasterPublicKey fetches the master public key from operators by querying /pubkey
func (c *KMSClient) GetMasterPublicKey() (types.G2Point, error) {
	c.logger.Sugar().Infow("Fetching master public key from operators", "operator_count", len(c.operatorURLs))

	var allCommitments [][]types.G2Point
	seenCommitments := make(map[string]struct{})

	for i, operatorURL := range c.operatorURLs {
		resp, err := http.Get(operatorURL + "/pubkey")
		if err != nil {
			c.logger.Sugar().Warnw("Failed to contact operator", "operator_index", i, "url", operatorURL, "error", err)
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			c.logger.Sugar().Warnw("Operator returned error", "operator_index", i, "status", resp.StatusCode, "body", string(body))
			continue
		}

		var response struct {
			Commitments []types.G2Point `json:"commitments"`
			IsActive    bool            `json:"isActive"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			c.logger.Sugar().Warnw("Failed to decode response", "operator_index", i, "error", err)
			continue
		}

		if !response.IsActive || len(response.Commitments) == 0 {
			c.logger.Sugar().Debugw("Operator has no active commitments", "operator_index", i)
			continue
		}
		var commitmentKey []byte
		for _, commitment := range response.Commitments {
			commitmentKey = append(commitmentKey, commitment.CompressedBytes...)
		}
		key := fmt.Sprintf("%x", commitmentKey)
		if _, exists := seenCommitments[key]; exists {
			continue
		}
		seenCommitments[key] = struct{}{}
		allCommitments = append(allCommitments, response.Commitments)
		c.logger.Sugar().Debugw("Collected commitments from operator", "operator_index", i)
	}

	if len(allCommitments) == 0 {
		return types.G2Point{}, fmt.Errorf("failed to collect commitments from any operator")
	}

	masterPubKey, err := crypto.ComputeMasterPublicKey(allCommitments)
	if err != nil {
		return types.G2Point{}, fmt.Errorf("failed to compute master public key: %w", err)
	}
	c.logger.Sugar().Infow("Computed master public key", "commitment_count", len(allCommitments))

	return *masterPubKey, nil
}

// CollectPartialSignatures collects partial signatures from threshold operators for an app
func (c *KMSClient) CollectPartialSignatures(appID string, attestationTime int64) (map[int]types.G1Point, error) {
	c.logger.Sugar().Infow("Collecting partial signatures",
		"app_id", appID,
		"threshold", c.threshold,
		"operators", len(c.operatorURLs))

	partialSigs := make(map[int]types.G1Point)
	collected := 0

	for i, operatorURL := range c.operatorURLs {
		if collected >= c.threshold {
			break
		}

		req := types.AppSignRequest{
			AppID:           appID,
			AttestationTime: attestationTime,
		}

		reqBody, err := json.Marshal(req)
		if err != nil {
			c.logger.Sugar().Warnw("Failed to marshal request", "operator_index", i, "error", err)
			continue
		}

		resp, err := http.Post(operatorURL+"/app/sign", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			c.logger.Sugar().Warnw("Failed to contact operator", "operator_index", i, "url", operatorURL, "error", err)
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			c.logger.Sugar().Warnw("Operator returned error", "operator_index", i, "status", resp.StatusCode, "body", string(body))
			continue
		}

		var response types.AppSignResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			c.logger.Sugar().Warnw("Failed to decode response", "operator_index", i, "error", err)
			continue
		}

		isZero, err := response.PartialSignature.IsZero()
		if err != nil {
			c.logger.Sugar().Warnw("Failed to validate partial signature", "operator_index", i, "error", err)
			continue
		}
		if isZero {
			c.logger.Sugar().Warnw("Received zero partial signature", "operator_index", i, "operator_address", response.OperatorAddress)
			continue
		}

		// Convert operator address to node ID (must match the IDs used during DKG)
		operatorAddress := common.HexToAddress(response.OperatorAddress)
		nodeID := util.AddressToNodeID(operatorAddress)

		partialSigs[nodeID] = response.PartialSignature
		collected++
		c.logger.Sugar().Debugw("Collected partial signature", "operator_index", i, "node_id", nodeID, "operator_address", response.OperatorAddress, "total", collected)
	}

	if collected < c.threshold {
		return nil, fmt.Errorf("insufficient partial signatures: collected %d, needed %d", collected, c.threshold)
	}

	c.logger.Sugar().Infow("Successfully collected threshold partial signatures", "collected", collected, "threshold", c.threshold)
	return partialSigs, nil
}

// EncryptForApp encrypts data for a specific application using IBE
func (c *KMSClient) EncryptForApp(appID string, masterPublicKey types.G2Point, plaintext []byte) ([]byte, error) {
	return crypto.EncryptForApp(appID, masterPublicKey, plaintext)
}

// DecryptForApp decrypts data by collecting partial signatures and recovering app private key
func (c *KMSClient) DecryptForApp(appID string, ciphertext []byte, attestationTime int64) ([]byte, error) {
	// Collect partial signatures from threshold operators
	partialSigs, err := c.CollectPartialSignatures(appID, attestationTime)
	if err != nil {
		return nil, fmt.Errorf("failed to collect partial signatures: %w", err)
	}

	// Recover application private key
	appPrivateKey, err := crypto.RecoverAppPrivateKey(appID, partialSigs, c.threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to recover app private key: %w", err)
	}

	// Decrypt using recovered key
	return crypto.DecryptForApp(appID, *appPrivateKey, ciphertext)
}
