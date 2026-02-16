package kmsClient

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

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
	HTTPClient     *http.Client // Optional: if nil, creates default client with 30s timeout
}

// Client provides a reusable library interface for KMS operations
type Client struct {
	avsAddress     string
	operatorSetID  uint32
	contractCaller ContractCaller
	httpClient     *http.Client
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

	// Use provided HTTP client or create default with 30s timeout
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	return &Client{
		avsAddress:     config.AVSAddress,
		operatorSetID:  config.OperatorSetID,
		contractCaller: config.ContractCaller,
		httpClient:     httpClient,
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

// GetMasterPublicKey fetches the master public key from operators concurrently
func (c *Client) GetMasterPublicKey(operators *peering.OperatorSetPeers) (*types.G2Point, error) {
	if operators == nil || len(operators.Peers) == 0 {
		return nil, fmt.Errorf("no operators provided")
	}

	c.logger.Sugar().Infow("Collecting commitments from operators", "count", len(operators.Peers))

	type result struct {
		commitments []types.G2Point
		opAddress   string
	}

	resultChan := make(chan result, len(operators.Peers))
	var wg sync.WaitGroup

	// Collect commitments from all operators concurrently
	for i, operator := range operators.Peers {
		wg.Add(1)
		go func(idx int, op *peering.OperatorSetPeer) {
			defer wg.Done()

			resp, err := c.httpClient.Get(op.SocketAddress + "/pubkey")
			if err != nil {
				c.logger.Sugar().Warnw("Failed to contact operator",
					"operator_index", idx,
					"address", op.SocketAddress,
					"error", err,
				)
				return
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				c.logger.Sugar().Warnw("Operator returned error",
					"operator_index", idx,
					"status_code", resp.StatusCode,
					"body", string(body),
				)
				return
			}

			var response struct {
				OperatorAddress string          `json:"operatorAddress"`
				Commitments     []types.G2Point `json:"commitments"`
				Version         int64           `json:"version"`
				IsActive        bool            `json:"isActive"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				c.logger.Sugar().Warnw("Failed to decode response from operator",
					"operator_index", idx,
					"error", err,
				)
				return
			}

			if !response.IsActive {
				c.logger.Sugar().Warnw("Operator does not have active key version", "operator_index", idx)
				return
			}

			if len(response.Commitments) == 0 {
				c.logger.Sugar().Warnw("Operator has no commitments", "operator_index", idx)
				return
			}

			c.logger.Sugar().Debugw("Collected commitments from operator",
				"operator_index", idx,
				"operator_address", response.OperatorAddress,
			)
			resultChan <- result{commitments: response.Commitments, opAddress: response.OperatorAddress}
		}(i, operator)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var allCommitments [][]types.G2Point
	for res := range resultChan {
		allCommitments = append(allCommitments, res.commitments)
	}

	// SECURITY/CONSISTENCY NOTE (accepted behavior):
	// This path is intentionally best-effort for now. We accept any non-empty set of
	// commitments returned by reachable operators and compute a master public key from
	// that subset. We do NOT currently enforce quorum, cross-operator version agreement,
	// or authenticated/on-chain proof validation in this method.
	//
	// Rationale: prioritize availability when some operators are offline. The tradeoff is
	// that clients can observe split views and may derive a master key that later fails
	// decryption/reconstruction flows if responses were stale or Byzantine.
	if len(allCommitments) == 0 {
		return nil, fmt.Errorf("failed to collect commitments from any operator")
	}

	// Compute master public key from commitments
	c.logger.Sugar().Infow("Computing master public key", "commitments", len(allCommitments))
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

// CollectPartialSignatures collects partial signatures from threshold number of operators concurrently
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

	type result struct {
		nodeID    int64
		signature types.G1Point
		opAddress string
	}

	resultChan := make(chan result, len(operators.Peers))
	var wg sync.WaitGroup

	// Request partial signatures from all operators concurrently
	attestationTime := int64(0) // Use current active key version

	for i, operator := range operators.Peers {
		wg.Add(1)
		go func(idx int, op *peering.OperatorSetPeer) {
			defer wg.Done()

			req := types.AppSignRequest{
				AppID:           appID,
				AttestationTime: attestationTime,
			}

			reqBody, err := json.Marshal(req)
			if err != nil {
				c.logger.Sugar().Warnw("Failed to marshal request for operator",
					"operator_index", idx,
					"error", err,
				)
				return
			}

			resp, err := c.httpClient.Post(op.SocketAddress+"/app/sign", "application/json", bytes.NewReader(reqBody))
			if err != nil {
				c.logger.Sugar().Warnw("Failed to contact operator",
					"operator_index", idx,
					"address", op.SocketAddress,
					"error", err,
				)
				return
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				c.logger.Sugar().Warnw("Operator returned error",
					"operator_index", idx,
					"status_code", resp.StatusCode,
					"body", string(body),
				)
				return
			}

			var response types.AppSignResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				c.logger.Sugar().Warnw("Failed to decode response from operator",
					"operator_index", idx,
					"error", err,
				)
				return
			}

			// Validate partial signature is not zero
			isZero, err := response.PartialSignature.IsZero()
			if err != nil {
				c.logger.Sugar().Warnw("Failed to validate partial signature", "operator_index", idx, "error", err)
				return
			}
			if isZero {
				c.logger.Sugar().Warnw("Received zero partial signature", "operator_index", idx)
				return
			}

			// SECURITY: bind response identity to the operator we actually queried.
			// Never trust response.OperatorAddress as the source of truth for nodeID.
			expectedAddress := op.OperatorAddress.Hex()
			if !strings.EqualFold(response.OperatorAddress, expectedAddress) {
				c.logger.Sugar().Warnw("Operator address mismatch in partial signature response",
					"operator_index", idx,
					"expected_operator_address", expectedAddress,
					"response_operator_address", response.OperatorAddress,
				)
				return
			}
			nodeID := util.AddressToNodeID(op.OperatorAddress)

			c.logger.Sugar().Debugw("Collected partial signature from operator",
				"operator_index", idx,
				"node_id", nodeID,
				"operator_address", response.OperatorAddress)

			resultChan <- result{nodeID: nodeID, signature: response.PartialSignature, opAddress: response.OperatorAddress}
		}(i, operator)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	partialSigs := make(map[int64]types.G1Point)
	// TODO(security): only count cryptographically verified partial signatures.
	// Current code counts non-zero shares and relies on later interpolation failure.
	for res := range resultChan {
		partialSigs[res.nodeID] = res.signature
		if len(partialSigs) >= threshold {
			break
		}
	}

	if len(partialSigs) < threshold {
		return nil, fmt.Errorf("insufficient partial signatures: collected %d, needed %d", len(partialSigs), threshold)
	}

	c.logger.Sugar().Infow("Successfully collected partial signatures",
		"collected", len(partialSigs),
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
	// partialSigs is already a map[int64]types.G1Point with correct node IDs
	appPrivateKey, err := crypto.RecoverAppPrivateKey(appID, partialSigs, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to recover app private key: %w", err)
	}

	c.logger.Sugar().Info("Successfully recovered application private key")

	return &SecretsResult{
		AppPrivateKey:   *appPrivateKey,
		EncryptedEnv:    responses[0].EncryptedEnv,
		PublicEnv:       responses[0].PublicEnv,
		PartialSigs:     partialSigs,
		ResponseCount:   len(responses),
		ThresholdNeeded: threshold,
	}, nil
}

// GetEncryptedSecretsFromKMSNodesWithPartialSigs requests secrets from all KMS operators concurrently
// and decrypts partial signatures using the provided RSA private key
// Returns responses and partial signatures mapped by node ID
func (c *Client) GetEncryptedSecretsFromKMSNodesWithPartialSigs(
	operators *peering.OperatorSetPeers,
	req types.SecretsRequestV1,
	rsaPrivateKeyPEM []byte,
) ([]types.SecretsResponseV1, map[int64]types.G1Point, error) {
	rsaEncryption := encryption.NewRSAEncryption()

	type result struct {
		response   types.SecretsResponseV1
		partialSig types.G1Point
		nodeID     int64
		opAddress  string
		opIndex    int
	}

	resultChan := make(chan result, len(operators.Peers))
	var wg sync.WaitGroup

	// Request secrets from all operators concurrently
	for i, peer := range operators.Peers {
		wg.Add(1)
		go func(idx int, op *peering.OperatorSetPeer) {
			defer wg.Done()

			c.logger.Sugar().Debugw("Requesting secrets from operator",
				"operator_index", idx+1,
				"url", op.SocketAddress,
			)

			resp, err := c.requestSecretsFromKMS(op.SocketAddress, req)
			if err != nil {
				c.logger.Sugar().Warnw("Failed to get secrets from operator",
					"url", op.SocketAddress,
					"error", err,
				)
				return
			}

			// Decrypt the partial signature
			decryptedSigBytes, err := rsaEncryption.Decrypt(resp.EncryptedPartialSig, rsaPrivateKeyPEM)
			if err != nil {
				c.logger.Sugar().Warnw("Failed to decrypt partial signature",
					"url", op.SocketAddress,
					"error", err,
				)
				return
			}

			var partialSig types.G1Point
			if err := json.Unmarshal(decryptedSigBytes, &partialSig); err != nil {
				c.logger.Sugar().Warnw("Failed to parse partial signature",
					"url", op.SocketAddress,
					"error", err,
				)
				return
			}

			// Convert operator address to node ID
			nodeID := util.AddressToNodeID(op.OperatorAddress)

			c.logger.Sugar().Debugw("Received valid response from operator",
				"operator_index", idx+1,
				"node_id", nodeID)

			resultChan <- result{
				response:   *resp,
				partialSig: partialSig,
				nodeID:     nodeID,
				opAddress:  op.OperatorAddress.Hex(),
				opIndex:    idx,
			}
		}(i, peer)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var responses []types.SecretsResponseV1
	partialSigs := make(map[int64]types.G1Point)

	for res := range resultChan {
		responses = append(responses, res.response)
		partialSigs[res.nodeID] = res.partialSig
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

	resp, err := c.httpClient.Post(serverURL+"/secrets", "application/json", bytes.NewBuffer(reqBody))
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

	type result struct {
		nodeID    int64
		signature types.G1Point
		opAddress string
	}

	resultChan := make(chan result, len(operators.Peers))
	var wg sync.WaitGroup

	// Request partial signatures from all operators concurrently
	for i, peer := range operators.Peers {
		wg.Add(1)
		go func(idx int, op *peering.OperatorSetPeer) {
			defer wg.Done()

			req := types.AppSignRequest{
				AppID:           appID,
				AttestationTime: attestationTime,
			}

			reqBody, err := json.Marshal(req)
			if err != nil {
				c.logger.Sugar().Warnw("Failed to marshal request", "operator_index", idx, "error", err)
				return
			}

			resp, err := c.httpClient.Post(op.SocketAddress+"/app/sign", "application/json", bytes.NewReader(reqBody))
			if err != nil {
				c.logger.Sugar().Warnw("Failed to contact operator", "operator_index", idx, "url", op.SocketAddress, "error", err)
				return
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				c.logger.Sugar().Warnw("Operator returned error", "operator_index", idx, "status", resp.StatusCode, "body", string(body))
				return
			}

			var response types.AppSignResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				c.logger.Sugar().Warnw("Failed to decode response", "operator_index", idx, "error", err)
				return
			}

			isZero, err := response.PartialSignature.IsZero()
			if err != nil {
				c.logger.Sugar().Warnw("Failed to validate partial signature", "operator_index", idx, "error", err)
				return
			}
			if isZero {
				c.logger.Sugar().Warnw("Received zero partial signature", "operator_index", idx, "operator_address", response.OperatorAddress)
				return
			}

			// SECURITY: bind response identity to the operator we actually queried.
			// Never trust response.OperatorAddress as the source of truth for nodeID.
			expectedAddress := op.OperatorAddress.Hex()
			if !strings.EqualFold(response.OperatorAddress, expectedAddress) {
				c.logger.Sugar().Warnw("Operator address mismatch in partial signature response",
					"operator_index", idx,
					"expected_operator_address", expectedAddress,
					"response_operator_address", response.OperatorAddress,
				)
				return
			}
			nodeID := util.AddressToNodeID(op.OperatorAddress)

			c.logger.Sugar().Debugw("Collected partial signature", "operator_index", idx, "node_id", nodeID, "operator_address", response.OperatorAddress)
			resultChan <- result{nodeID: nodeID, signature: response.PartialSignature, opAddress: response.OperatorAddress}
		}(i, peer)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	partialSigs := make(map[int64]types.G1Point)
	// TODO(security): DOS vector. only count cryptographically verified partial signatures.
	// Current code counts non-zero shares and relies on later interpolation failure.
	for res := range resultChan {
		partialSigs[res.nodeID] = res.signature
		if len(partialSigs) >= threshold {
			break
		}
	}

	if len(partialSigs) < threshold {
		return nil, fmt.Errorf("insufficient partial signatures: collected %d, needed %d", len(partialSigs), threshold)
	}

	c.logger.Sugar().Infow("Successfully collected threshold partial signatures", "collected", len(partialSigs), "threshold", threshold)
	return partialSigs, nil
}
