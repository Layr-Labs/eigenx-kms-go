package kmsclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"go.uber.org/zap"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// ClientConfig holds the configuration for the KMS client
type ClientConfig struct {
	AVSAddress     string
	OperatorSetID  uint32
	Logger         *zap.Logger
	ContractCaller *caller.ContractCaller
}

// Client provides a reusable library interface for KMS operations
type Client struct {
	avsAddress     string
	operatorSetID  uint32
	contractCaller *caller.ContractCaller
	logger         *zap.Logger
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

		// Use operator index as node ID for collection
		// In real implementation, this would use the actual node ID from the operator
		partialSigs[int64(i)] = response.PartialSignature
		collected++

		c.logger.Sugar().Debugw("Collected partial signature from operator", "operator_index", i)
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
