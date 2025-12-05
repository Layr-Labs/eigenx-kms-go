package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/merkle"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// RetryConfig configures retry behavior
type RetryConfig struct {
	MaxAttempts     int
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	BackoffMultiple float64
}

// DefaultRetryConfig provides default retry settings
var DefaultRetryConfig = RetryConfig{
	MaxAttempts:     5,
	InitialBackoff:  100 * time.Millisecond,
	MaxBackoff:      5 * time.Second,
	BackoffMultiple: 2.0,
}

// Client handles network communication
type Client struct {
	nodeID       int
	operatorAddr common.Address
	signer       transportSigner.ITransportSigner
	retryConfig  RetryConfig
}

// NewClient creates a new transport client
func NewClient(nodeID int, operatorAddr common.Address, signer transportSigner.ITransportSigner) *Client {
	return &Client{
		nodeID:       nodeID,
		operatorAddr: operatorAddr,
		signer:       signer,
		retryConfig:  DefaultRetryConfig,
	}
}

// buildRequestURL constructs a full URL for an operator endpoint
func buildRequestURL(socketAddress, path string) string {
	return fmt.Sprintf("%s%s", socketAddress, path)
}

// QueryOperatorPubkey queries an operator's /pubkey endpoint for commitments
func (c *Client) QueryOperatorPubkey(operator *peering.OperatorSetPeer) ([]types.G2Point, error) {
	url := buildRequestURL(operator.SocketAddress, "/pubkey")
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to contact operator: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("operator returned status %d", resp.StatusCode)
	}

	var response struct {
		Commitments []types.G2Point `json:"commitments"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Commitments, nil
}

// SendDKGShare sends an authenticated DKG share to another node with retries
func (c *Client) SendDKGShare(toOperator *peering.OperatorSetPeer, share *fr.Element, sessionTimestamp int64) error {
	msg := types.ShareMessage{
		FromOperatorAddress: c.operatorAddr,
		ToOperatorAddress:   toOperator.OperatorAddress,
		SessionTimestamp:    sessionTimestamp,
		Share:               types.SerializeFr(share),
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create authenticated message
	authMsg, err := c.signer.CreateAuthenticatedMessage(msgBytes)
	if err != nil {
		return fmt.Errorf("failed to create authenticated message: %w", err)
	}

	data, err := json.Marshal(authMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal authenticated message: %w", err)
	}

	backoff := c.retryConfig.InitialBackoff
	for attempt := 0; attempt < c.retryConfig.MaxAttempts; attempt++ {
		url := buildRequestURL(toOperator.SocketAddress, "/dkg/share")
		resp, err := http.Post(url, "application/json", bytes.NewReader(data))
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}

		if attempt < c.retryConfig.MaxAttempts-1 {
			time.Sleep(backoff)
			backoff = time.Duration(float64(backoff) * c.retryConfig.BackoffMultiple)
			if backoff > c.retryConfig.MaxBackoff {
				backoff = c.retryConfig.MaxBackoff
			}
		}
	}

	return fmt.Errorf("failed to send DKG share after %d attempts", c.retryConfig.MaxAttempts)
}

// SendReshareShare sends an authenticated reshare share to another node with retries
func (c *Client) SendReshareShare(toOperator *peering.OperatorSetPeer, share *fr.Element, sessionTimestamp int64) error {
	msg := types.ShareMessage{
		FromOperatorAddress: c.operatorAddr,
		ToOperatorAddress:   toOperator.OperatorAddress,
		SessionTimestamp:    sessionTimestamp,
		Share:               types.SerializeFr(share),
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create authenticated message
	authMsg, err := c.signer.CreateAuthenticatedMessage(msgBytes)
	if err != nil {
		return fmt.Errorf("failed to create authenticated message: %w", err)
	}

	data, err := json.Marshal(authMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal authenticated message: %w", err)
	}

	backoff := c.retryConfig.InitialBackoff
	for attempt := 0; attempt < c.retryConfig.MaxAttempts; attempt++ {
		url := buildRequestURL(toOperator.SocketAddress, "/reshare/share")
		resp, err := http.Post(url, "application/json", bytes.NewReader(data))
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}

		if attempt < c.retryConfig.MaxAttempts-1 {
			time.Sleep(backoff)
			backoff = time.Duration(float64(backoff) * c.retryConfig.BackoffMultiple)
			if backoff > c.retryConfig.MaxBackoff {
				backoff = c.retryConfig.MaxBackoff
			}
		}
	}

	return fmt.Errorf("failed to send reshare share after %d attempts", c.retryConfig.MaxAttempts)
}

// BroadcastDKGCommitments broadcasts authenticated DKG commitments to all operators
func (c *Client) BroadcastDKGCommitments(operators []*peering.OperatorSetPeer, commitments []types.G2Point, sessionTimestamp int64) error {

	// Send to all other operators
	for _, op := range operators {
		if op.OperatorAddress == c.operatorAddr {
			continue // Skip self
		}
		msg := types.CommitmentMessage{
			FromOperatorAddress: c.operatorAddr,
			ToOperatorAddress:   op.OperatorAddress, // Zero address for broadcast
			SessionTimestamp:    sessionTimestamp,
			Commitments:         commitments,
		}

		msgBytes, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}

		// Create authenticated message
		authMsg, err := c.signer.CreateAuthenticatedMessage(msgBytes)
		if err != nil {
			return fmt.Errorf("failed to create authenticated message: %w", err)
		}

		data, err := json.Marshal(authMsg)
		if err != nil {
			return fmt.Errorf("failed to marshal authenticated message: %w", err)
		}

		url := buildRequestURL(op.SocketAddress, "/dkg/commitment")
		_, _ = http.Post(url, "application/json", bytes.NewReader(data))
	}
	return nil
}

// BroadcastReshareCommitments broadcasts authenticated reshare commitments to all operators
func (c *Client) BroadcastReshareCommitments(operators []*peering.OperatorSetPeer, commitments []types.G2Point, sessionTimestamp int64) error {

	// Send to all other operators
	for _, op := range operators {
		if op.OperatorAddress == c.operatorAddr {
			continue // Skip self
		}
		msg := types.CommitmentMessage{
			FromOperatorAddress: c.operatorAddr,
			ToOperatorAddress:   op.OperatorAddress, // Zero address for broadcast
			SessionTimestamp:    sessionTimestamp,
			Commitments:         commitments,
		}

		msgBytes, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}

		// Create authenticated message
		authMsg, err := c.signer.CreateAuthenticatedMessage(msgBytes)
		if err != nil {
			return fmt.Errorf("failed to create authenticated message: %w", err)
		}

		data, err := json.Marshal(authMsg)
		if err != nil {
			return fmt.Errorf("failed to marshal authenticated message: %w", err)
		}
		url := buildRequestURL(op.SocketAddress, "/reshare/commitment")
		_, _ = http.Post(url, "application/json", bytes.NewReader(data))
	}
	return nil
}

// SendDKGAcknowledgement sends an authenticated DKG acknowledgement to a specific operator
func (c *Client) SendDKGAcknowledgement(ack *types.Acknowledgement, toOperator *peering.OperatorSetPeer, sessionTimestamp int64) error {
	msg := types.AcknowledgementMessage{
		FromOperatorAddress: c.operatorAddr,
		ToOperatorAddress:   toOperator.OperatorAddress,
		SessionTimestamp:    sessionTimestamp,
		Ack:                 ack,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create authenticated message
	authMsg, err := c.signer.CreateAuthenticatedMessage(msgBytes)
	if err != nil {
		return fmt.Errorf("failed to create authenticated message: %w", err)
	}

	data, err := json.Marshal(authMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal authenticated message: %w", err)
	}

	url := buildRequestURL(toOperator.SocketAddress, "/dkg/ack")
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return nil
}

// SendReshareAcknowledgement sends an authenticated reshare acknowledgement to a specific operator
func (c *Client) SendReshareAcknowledgement(ack *types.Acknowledgement, toOperator *peering.OperatorSetPeer, sessionTimestamp int64) error {
	msg := types.AcknowledgementMessage{
		FromOperatorAddress: c.operatorAddr,
		ToOperatorAddress:   toOperator.OperatorAddress,
		SessionTimestamp:    sessionTimestamp,
		Ack:                 ack,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create authenticated message
	authMsg, err := c.signer.CreateAuthenticatedMessage(msgBytes)
	if err != nil {
		return fmt.Errorf("failed to create authenticated message: %w", err)
	}

	data, err := json.Marshal(authMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal authenticated message: %w", err)
	}

	url := buildRequestURL(toOperator.SocketAddress, "/reshare/ack")
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return nil
}

// BroadcastCompletionSignature broadcasts an authenticated completion signature
func (c *Client) BroadcastCompletionSignature(operators []*peering.OperatorSetPeer, completion *types.CompletionSignature, sessionTimestamp int64) error {

	for _, op := range operators {
		if op.OperatorAddress == c.operatorAddr {
			continue // Skip self
		}
		msg := types.CompletionMessage{
			FromOperatorAddress: c.operatorAddr,
			ToOperatorAddress:   op.OperatorAddress, // Zero address for broadcast
			SessionTimestamp:    sessionTimestamp,
			Completion:          completion,
		}

		msgBytes, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}

		// Create authenticated message
		authMsg, err := c.signer.CreateAuthenticatedMessage(msgBytes)
		if err != nil {
			return fmt.Errorf("failed to create authenticated message: %w", err)
		}

		data, err := json.Marshal(authMsg)
		if err != nil {
			return fmt.Errorf("failed to marshal authenticated message: %w", err)
		}
		url := buildRequestURL(op.SocketAddress, "/reshare/complete")
		_, _ = http.Post(url, "application/json", bytes.NewReader(data))
	}
	return nil
}

// BroadcastCommitmentsWithProofs broadcasts commitments and acknowledgements with operator-specific merkle proofs (Phase 5)
// Each operator receives a broadcast containing all acks and a merkle proof for their specific ack
func (c *Client) BroadcastCommitmentsWithProofs(
	operators []*peering.OperatorSetPeer,
	epoch int64,
	commitments []types.G2Point,
	acks []*types.Acknowledgement,
	merkleTree *merkle.MerkleTree,
) error {
	if merkleTree == nil {
		return fmt.Errorf("merkle tree is nil")
	}

	// Send to each operator with their specific proof
	for i, op := range operators {
		if op.OperatorAddress == c.operatorAddr {
			continue // Skip self
		}

		// Find the ack for this operator
		var recipientAck *types.Acknowledgement
		var leafIndex int
		for idx, ack := range acks {
			opNodeID := addressToNodeID(op.OperatorAddress)
			if ack.PlayerID == opNodeID {
				recipientAck = ack
				leafIndex = idx
				break
			}
		}

		if recipientAck == nil {
			return fmt.Errorf("no ack found for operator %s", op.OperatorAddress.Hex())
		}

		// Generate merkle proof for this specific operator
		proof, err := merkleTree.GenerateProof(leafIndex)
		if err != nil {
			return fmt.Errorf("failed to generate proof for operator %d: %w", i, err)
		}

		// Create broadcast message with proof
		broadcast := &types.CommitmentBroadcast{
			FromOperatorID:   c.nodeID,
			Epoch:            epoch,
			Commitments:      commitments,
			Acknowledgements: acks,
			MerkleProof:      proof.Proof,
		}

		// Send to operator
		if err := c.sendCommitmentBroadcast(op, broadcast, epoch); err != nil {
			// Log error but continue to other operators
			fmt.Printf("Failed to send commitment broadcast to %s: %v\n", op.OperatorAddress.Hex(), err)
		}
	}

	return nil
}

// sendCommitmentBroadcast sends a commitment broadcast to a specific operator (Phase 5)
func (c *Client) sendCommitmentBroadcast(
	toOperator *peering.OperatorSetPeer,
	broadcast *types.CommitmentBroadcast,
	sessionTimestamp int64,
) error {
	toNodeID := addressToNodeID(toOperator.OperatorAddress)

	// Create message wrapper
	msg := types.CommitmentBroadcastMessage{
		FromOperatorID: c.nodeID,
		ToOperatorID:   toNodeID,
		SessionID:      sessionTimestamp,
		Broadcast:      broadcast,
	}

	// Serialize message
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal broadcast message: %w", err)
	}

	// Send to operator
	url := buildRequestURL(toOperator.SocketAddress, "/dkg/broadcast")
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to send broadcast: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("broadcast failed with status %d", resp.StatusCode)
	}

	return nil
}

// addressToNodeID converts an Ethereum address to a node ID using keccak256 hash
func addressToNodeID(address common.Address) int {
	hash := crypto.Keccak256(address.Bytes())
	nodeID := int(common.BytesToHash(hash).Big().Uint64())
	return nodeID
}
