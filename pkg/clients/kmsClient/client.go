package kmsClient

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/util"
)

// ContractCaller defines the interface for fetching operator information from the blockchain
type ContractCaller interface {
	GetOperatorSetMembersWithPeering(avsAddress string, operatorSetID uint32) (*peering.OperatorSetPeers, error)
}

// ClientConfig holds the configuration for the KMS client
type ClientConfig struct {
	AVSAddress     string
	OperatorSetID  uint32
	Logger         *zap.Logger
	ContractCaller ContractCaller
}

// Client provides a reusable library interface for KMS operations
type Client struct {
	avsAddress     string
	operatorSetID  uint32
	contractCaller ContractCaller
	logger         *zap.Logger
}

// SecretsResult contains the recovered secrets and private key
type SecretsResult struct {
	AppPrivateKey   types.G1Point
	EncryptedEnv    string
	PublicEnv       string
	PartialSigs     map[int64]types.G1Point
	ResponseCount   int
	ThresholdNeeded int
}

// SecretsOptions configures secret retrieval behavior
type SecretsOptions struct {
	// AttestationMethod specifies which attestation method to use
	// Options: "gcp" (default), "intel", "ecdsa"
	AttestationMethod string

	// For GCP/Intel attestation (production)
	ImageDigest string

	// For ECDSA attestation (development)
	ECDSAPrivateKey *ecdsa.PrivateKey // Optional: if nil, generates new key

	// RSA key pair for encrypting partial signatures in transit
	RSAPrivateKeyPEM []byte // Required: RSA private key in PEM format
	RSAPublicKeyPEM  []byte // Required: RSA public key in PEM format
}

// NewClient creates a new KMS client instance with dependency injection
func NewClient(config *ClientConfig) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if config.AVSAddress == "" {
		return nil, fmt.Errorf("AVS address is required")
	}
	if config.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if config.ContractCaller == nil {
		return nil, fmt.Errorf("contract caller is required")
	}

	return &Client{
		avsAddress:     config.AVSAddress,
		operatorSetID:  config.OperatorSetID,
		contractCaller: config.ContractCaller,
		logger:         config.Logger,
	}, nil
}

// GetOperators fetches operator information from the blockchain
func (c *Client) GetOperators() (*peering.OperatorSetPeers, error) {
	c.logger.Sugar().Infow("Fetching operators from chain",
		"avs", c.avsAddress,
		"operator_set_id", c.operatorSetID,
	)

	// Get operator set with peering data
	operators, err := c.contractCaller.GetOperatorSetMembersWithPeering(c.avsAddress, c.operatorSetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get operators from chain: %w", err)
	}

	if len(operators.Peers) == 0 {
		return nil, fmt.Errorf("no operators found for AVS %s operator set %d", c.avsAddress, c.operatorSetID)
	}

	c.logger.Sugar().Infow("Found operators on-chain", "count", len(operators.Peers))
	for i, op := range operators.Peers {
		c.logger.Sugar().Debugw("Operator details",
			"index", i+1,
			"address", op.OperatorAddress.Hex(),
			"socket", op.SocketAddress,
		)
	}

	return operators, nil
}

// GetMasterPublicKey fetches the master public key from operators
func (c *Client) GetMasterPublicKey(operators *peering.OperatorSetPeers) (*types.G2Point, error) {
	if operators == nil || len(operators.Peers) == 0 {
		return nil, fmt.Errorf("no operators provided")
	}

	c.logger.Sugar().Infow("Collecting commitments from operators", "count", len(operators.Peers))

	// Step 1: Collect commitments from all operators
	var allCommitments [][]types.G2Point
	successful := 0

	for i, operator := range operators.Peers {
		resp, err := http.Get(operator.SocketAddress + "/pubkey")
		if err != nil {
			c.logger.Sugar().Warnw("Failed to contact operator",
				"operator_index", i,
				"address", operator.SocketAddress,
				"error", err,
			)
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			c.logger.Sugar().Warnw("Operator returned error",
				"operator_index", i,
				"status_code", resp.StatusCode,
				"body", string(body),
			)
			continue
		}

		var response struct {
			OperatorAddress string          `json:"operatorAddress"`
			Commitments     []types.G2Point `json:"commitments"`
			Version         int64           `json:"version"`
			IsActive        bool            `json:"isActive"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			c.logger.Sugar().Warnw("Failed to decode response from operator",
				"operator_index", i,
				"error", err,
			)
			continue
		}

		if !response.IsActive {
			c.logger.Sugar().Warnw("Operator does not have active key version", "operator_index", i)
			continue
		}

		if len(response.Commitments) == 0 {
			c.logger.Sugar().Warnw("Operator has no commitments", "operator_index", i)
			continue
		}

		allCommitments = append(allCommitments, response.Commitments)
		successful++
		c.logger.Sugar().Debugw("Collected commitments from operator",
			"operator_index", i,
			"operator_address", response.OperatorAddress,
		)
	}

	if successful == 0 {
		return nil, fmt.Errorf("failed to collect commitments from any operator")
	}

	// Step 2: Compute master public key from commitments
	c.logger.Sugar().Infow("Computing master public key", "commitments", successful)
	masterPubKey, err := crypto.ComputeMasterPublicKey(allCommitments)
	if err != nil {
		return nil, fmt.Errorf("failed to compute master public key: %w", err)
	}

	return masterPubKey, nil
}

// Encrypt encrypts data for an application using IBE
func (c *Client) Encrypt(appID string, data []byte, operators *peering.OperatorSetPeers) ([]byte, error) {
	if appID == "" {
		return nil, fmt.Errorf("app ID is required")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("data to encrypt is required")
	}

	c.logger.Sugar().Infow("Encrypting data for app", "app_id", appID)

	// Get master public key from operators
	masterPubKey, err := c.GetMasterPublicKey(operators)
	if err != nil {
		return nil, fmt.Errorf("failed to get master public key: %w", err)
	}

	c.logger.Sugar().Debug("Retrieved master public key from operators")

	// Encrypt data using IBE
	encryptedData, err := crypto.EncryptForApp(appID, *masterPubKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	c.logger.Sugar().Info("Successfully encrypted data")
	return encryptedData, nil
}

// CollectPartialSignatures collects partial signatures from threshold number of operators
func (c *Client) CollectPartialSignatures(appID string, operators *peering.OperatorSetPeers, threshold int) (map[int64]types.G1Point, error) {
	if appID == "" {
		return nil, fmt.Errorf("app ID is required")
	}
	if operators == nil || len(operators.Peers) == 0 {
		return nil, fmt.Errorf("no operators provided")
	}
	if threshold <= 0 {
		return nil, fmt.Errorf("threshold must be positive")
	}

	c.logger.Sugar().Infow("Collecting partial signatures",
		"app_id", appID,
		"threshold", threshold,
		"total_operators", len(operators.Peers),
	)

	partialSigs := make(map[int64]types.G1Point)

	// Generate a random attestation time for signature requests
	attestationTime := int64(0) // Use current active key version

	collected := 0
	for i, operator := range operators.Peers {
		if collected >= threshold {
			break
		}

		// Request partial signature from operator
		req := types.AppSignRequest{
			AppID:           appID,
			AttestationTime: attestationTime,
		}

		reqBody, err := json.Marshal(req)
		if err != nil {
			c.logger.Sugar().Warnw("Failed to marshal request for operator",
				"operator_index", i,
				"error", err,
			)
			continue
		}

		resp, err := http.Post(operator.SocketAddress+"/app/sign", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			c.logger.Sugar().Warnw("Failed to contact operator",
				"operator_index", i,
				"address", operator.SocketAddress,
				"error", err,
			)
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			c.logger.Sugar().Warnw("Operator returned error",
				"operator_index", i,
				"status_code", resp.StatusCode,
				"body", string(body),
			)
			continue
		}

		var response types.AppSignResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			c.logger.Sugar().Warnw("Failed to decode response from operator",
				"operator_index", i,
				"error", err,
			)
			continue
		}

		// Validate partial signature is not zero
		isZero, err := response.PartialSignature.IsZero()
		if err != nil {
			c.logger.Sugar().Warnw("Failed to validate partial signature", "operator_index", i, "error", err)
			continue
		}
		if isZero {
			c.logger.Sugar().Warnw("Received zero partial signature", "operator_index", i)
			continue
		}

		// Convert operator address to node ID (must match the IDs used during DKG)
		operatorAddress := common.HexToAddress(response.OperatorAddress)
		nodeID := util.AddressToNodeID(operatorAddress)

		partialSigs[nodeID] = response.PartialSignature
		collected++

		c.logger.Sugar().Debugw("Collected partial signature from operator",
			"operator_index", i,
			"node_id", nodeID,
			"operator_address", response.OperatorAddress)
	}

	if collected < threshold {
		return nil, fmt.Errorf("insufficient partial signatures: collected %d, needed %d", collected, threshold)
	}

	c.logger.Sugar().Infow("Successfully collected partial signatures",
		"collected", collected,
		"threshold", threshold,
	)
	return partialSigs, nil
}

// Decrypt decrypts data by collecting partial signatures from operators
func (c *Client) Decrypt(appID string, encryptedData []byte, operators *peering.OperatorSetPeers, threshold int) ([]byte, error) {
	if appID == "" {
		return nil, fmt.Errorf("app ID is required")
	}
	if len(encryptedData) == 0 {
		return nil, fmt.Errorf("encrypted data is required")
	}
	if operators == nil || len(operators.Peers) == 0 {
		return nil, fmt.Errorf("no operators provided")
	}

	c.logger.Sugar().Infow("Decrypting data for app", "app_id", appID)

	// Calculate threshold if not provided
	if threshold == 0 {
		threshold = (2*len(operators.Peers) + 2) / 3
	}

	// Collect partial signatures from operators
	partialSigs, err := c.CollectPartialSignatures(appID, operators, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to collect partial signatures: %w", err)
	}

	// Recover application private key
	appPrivateKey, err := crypto.RecoverAppPrivateKey(appID, partialSigs, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to recover application private key: %w", err)
	}

	// Decrypt data
	decryptedData, err := crypto.DecryptForApp(appID, *appPrivateKey, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	c.logger.Sugar().Info("Successfully decrypted data")
	return decryptedData, nil
}

// RetrieveSecretsWithOptions implements secret retrieval with configurable attestation method
// RSA key pair must be provided in opts for encrypting partial signatures in transit
func (c *Client) RetrieveSecretsWithOptions(appID string, opts *SecretsOptions) (*SecretsResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("options are required")
	}
	if opts.AttestationMethod == "" {
		opts.AttestationMethod = "gcp"
	}
	if len(opts.RSAPrivateKeyPEM) == 0 || len(opts.RSAPublicKeyPEM) == 0 {
		return nil, fmt.Errorf("RSA key pair is required in options")
	}

	c.logger.Sugar().Infow("Starting secret retrieval",
		"app_id", appID,
		"attestation_method", opts.AttestationMethod,
	)

	// Step 1: Get operators from chain
	operators, err := c.GetOperators()
	if err != nil {
		return nil, fmt.Errorf("failed to get operators: %w", err)
	}

	threshold := dkg.CalculateThreshold(len(operators.Peers))

	// Step 2: Create attestation based on method
	var req types.SecretsRequestV1

	switch opts.AttestationMethod {
	case "ecdsa":
		req, err = c.createECDSAAttestationRequest(appID, opts, opts.RSAPublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to create ECDSA attestation: %w", err)
		}

	case "gcp", "intel":
		attestationClaims := types.AttestationClaims{
			AppID:       appID,
			ImageDigest: opts.ImageDigest,
			IssuedAt:    time.Now().Unix(),
			PublicKey:   opts.RSAPublicKeyPEM,
		}
		attestationBytes, err := json.Marshal(attestationClaims)
		if err != nil {
			return nil, fmt.Errorf("failed to create attestation: %w", err)
		}

		req = types.SecretsRequestV1{
			AppID:             appID,
			AttestationMethod: opts.AttestationMethod,
			Attestation:       attestationBytes,
			RSAPubKeyTmp:      opts.RSAPublicKeyPEM,
			AttestTime:        time.Now().Unix(),
		}

	default:
		return nil, fmt.Errorf("unsupported attestation method: %s", opts.AttestationMethod)
	}

	// Step 3: Request secrets from all KMS servers and collect partial signatures
	responses, partialSigs, err := c.GetEncryptedSecretsFromKMSNodesWithPartialSigs(operators, req, opts.RSAPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to collect secrets: %w", err)
	}

	// Step 4: Verify we have threshold responses
	if len(responses) < threshold {
		return nil, fmt.Errorf("insufficient responses: got %d, need %d", len(responses), threshold)
	}

	// Step 5: Verify all responses have consistent environment data
	expectedEnv := responses[0].EncryptedEnv
	for i, resp := range responses {
		if resp.EncryptedEnv != expectedEnv {
			return nil, fmt.Errorf("environment data mismatch from server %d", i+1)
		}
	}

	c.logger.Sugar().Info("Verified threshold agreement on environment data")

	// Step 6: Recover application private key using threshold signatures
	partialSigMap := make(map[int64]types.G1Point)
	for i, sig := range partialSigs {
		partialSigMap[int64(i+1)] = sig
	}

	appPrivateKey, err := crypto.RecoverAppPrivateKey(appID, partialSigMap, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to recover app private key: %w", err)
	}

	c.logger.Sugar().Info("Successfully recovered application private key")

	return &SecretsResult{
		AppPrivateKey:   *appPrivateKey,
		EncryptedEnv:    responses[0].EncryptedEnv,
		PublicEnv:       responses[0].PublicEnv,
		PartialSigs:     partialSigMap,
		ResponseCount:   len(responses),
		ThresholdNeeded: threshold,
	}, nil
}

// GetEncryptedSecretsFromKMSNodesWithPartialSigs requests secrets from all KMS operators
// and decrypts partial signatures using the provided RSA private key
func (c *Client) GetEncryptedSecretsFromKMSNodesWithPartialSigs(
	operators *peering.OperatorSetPeers,
	req types.SecretsRequestV1,
	rsaPrivateKeyPEM []byte,
) ([]types.SecretsResponseV1, []types.G1Point, error) {
	rsaEncryption := encryption.NewRSAEncryption()

	var responses []types.SecretsResponseV1
	var partialSigs []types.G1Point

	for i, peer := range operators.Peers {
		c.logger.Sugar().Debugw("Requesting secrets from operator",
			"operator_index", i+1,
			"url", peer.SocketAddress,
		)

		resp, err := c.requestSecretsFromKMS(peer.SocketAddress, req)
		if err != nil {
			c.logger.Sugar().Warnw("Failed to get secrets from operator",
				"url", peer.SocketAddress,
				"error", err,
			)
			continue
		}

		// Decrypt the partial signature
		decryptedSigBytes, err := rsaEncryption.Decrypt(resp.EncryptedPartialSig, rsaPrivateKeyPEM)
		if err != nil {
			c.logger.Sugar().Warnw("Failed to decrypt partial signature",
				"url", peer.SocketAddress,
				"error", err,
			)
			continue
		}

		var partialSig types.G1Point
		if err := json.Unmarshal(decryptedSigBytes, &partialSig); err != nil {
			c.logger.Sugar().Warnw("Failed to parse partial signature",
				"url", peer.SocketAddress,
				"error", err,
			)
			continue
		}

		responses = append(responses, *resp)
		partialSigs = append(partialSigs, partialSig)

		c.logger.Sugar().Debugw("Received valid response from operator", "operator_index", i+1)
	}

	if len(responses) == 0 {
		return nil, nil, fmt.Errorf("failed to collect any valid responses from operators")
	}

	return responses, partialSigs, nil
}

// requestSecretsFromKMS makes an HTTP request to a single KMS server
func (c *Client) requestSecretsFromKMS(serverURL string, req types.SecretsRequestV1) (*types.SecretsResponseV1, error) {
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

// createECDSAAttestationRequest creates a SecretsRequestV1 with ECDSA attestation
func (c *Client) createECDSAAttestationRequest(appID string, opts *SecretsOptions, rsaPubKeyPEM []byte) (types.SecretsRequestV1, error) {
	var privateKey *ecdsa.PrivateKey
	var err error

	if opts.ECDSAPrivateKey != nil {
		privateKey = opts.ECDSAPrivateKey
		c.logger.Sugar().Debug("Using provided ECDSA private key")
	} else {
		privateKey, err = ethcrypto.GenerateKey()
		if err != nil {
			return types.SecretsRequestV1{}, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		c.logger.Sugar().Debug("Generated new ECDSA private key")
	}

	publicKey := ethcrypto.FromECDSAPub(&privateKey.PublicKey)
	address := ethcrypto.PubkeyToAddress(privateKey.PublicKey)
	c.logger.Sugar().Debugw("ECDSA attestation", "address", address.Hex())

	// Generate challenge
	nonce := make([]byte, attestation.NonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return types.SecretsRequestV1{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	challenge, err := attestation.GenerateChallenge(nonce)
	if err != nil {
		return types.SecretsRequestV1{}, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Sign challenge
	signature, err := attestation.SignChallenge(privateKey, appID, challenge)
	if err != nil {
		return types.SecretsRequestV1{}, fmt.Errorf("failed to sign challenge: %w", err)
	}

	c.logger.Sugar().Debug("Created ECDSA signature")

	return types.SecretsRequestV1{
		AppID:             appID,
		AttestationMethod: "ecdsa",
		Attestation:       signature,
		Challenge:         []byte(challenge),
		PublicKey:         publicKey,
		RSAPubKeyTmp:      rsaPubKeyPEM,
		AttestTime:        time.Now().Unix(),
	}, nil
}

// EncryptForApp encrypts data for a specific application using IBE
func (c *Client) EncryptForApp(appID string, plaintext []byte) ([]byte, error) {
	operators, err := c.GetOperators()
	if err != nil {
		return nil, fmt.Errorf("failed to get operators: %w", err)
	}

	masterPubKey, err := c.GetMasterPublicKey(operators)
	if err != nil {
		return nil, fmt.Errorf("failed to get master public key: %w", err)
	}

	return crypto.EncryptForApp(appID, *masterPubKey, plaintext)
}

// DecryptForApp decrypts data by collecting partial signatures and recovering app private key
func (c *Client) DecryptForApp(appID string, ciphertext []byte, attestationTime int64) ([]byte, error) {
	operators, err := c.GetOperators()
	if err != nil {
		return nil, fmt.Errorf("failed to get operators: %w", err)
	}

	threshold := dkg.CalculateThreshold(len(operators.Peers))

	// Collect partial signatures from threshold operators
	partialSigs, err := c.collectPartialSignaturesForDecrypt(appID, operators, attestationTime, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to collect partial signatures: %w", err)
	}

	// Recover application private key
	appPrivateKey, err := crypto.RecoverAppPrivateKey(appID, partialSigs, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to recover app private key: %w", err)
	}

	// Decrypt using recovered key
	return crypto.DecryptForApp(appID, *appPrivateKey, ciphertext)
}

// collectPartialSignaturesForDecrypt collects partial signatures using operator address-based node IDs
func (c *Client) collectPartialSignaturesForDecrypt(appID string, operators *peering.OperatorSetPeers, attestationTime int64, threshold int) (map[int64]types.G1Point, error) {
	c.logger.Sugar().Infow("Collecting partial signatures for decryption",
		"app_id", appID,
		"threshold", threshold,
		"operators", len(operators.Peers))

	partialSigs := make(map[int64]types.G1Point)
	collected := 0

	for i, peer := range operators.Peers {
		if collected >= threshold {
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

		resp, err := http.Post(peer.SocketAddress+"/app/sign", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			c.logger.Sugar().Warnw("Failed to contact operator", "operator_index", i, "url", peer.SocketAddress, "error", err)
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

	if collected < threshold {
		return nil, fmt.Errorf("insufficient partial signatures: collected %d, needed %d", collected, threshold)
	}

	c.logger.Sugar().Infow("Successfully collected threshold partial signatures", "collected", collected, "threshold", threshold)
	return partialSigs, nil
}
