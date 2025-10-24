package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
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

// MessageSigner interface for signing messages
type MessageSigner interface {
	CreateAuthenticatedMessage(payload interface{}) (*types.AuthenticatedMessage, error)
}

// Client handles network communication
type Client struct {
	nodeID       int
	operatorAddr common.Address
	signer       MessageSigner
	retryConfig  RetryConfig
}

// NewClient creates a new transport client
func NewClient(nodeID int, operatorAddr common.Address, signer MessageSigner) *Client {
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

// SendDKGShare sends an authenticated DKG share to another node with retries
func (c *Client) SendDKGShare(toOperator *peering.OperatorSetPeer, share *fr.Element, sessionTimestamp int64) error {
	msg := types.ShareMessage{
		FromOperatorAddress: c.operatorAddr,
		ToOperatorAddress:   toOperator.OperatorAddress,
		SessionTimestamp:    sessionTimestamp,
		Share:               types.SerializeFr(share),
	}

	// Create authenticated message
	authMsg, err := c.signer.CreateAuthenticatedMessage(msg)
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

	// Create authenticated message
	authMsg, err := c.signer.CreateAuthenticatedMessage(msg)
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
	// Create broadcast message (ToOperatorAddress is zero for broadcast)
	msg := types.CommitmentMessage{
		FromOperatorAddress: c.operatorAddr,
		ToOperatorAddress:   common.Address{}, // Zero address for broadcast
		SessionTimestamp:    sessionTimestamp,
		Commitments:         commitments,
	}

	// Create authenticated message
	authMsg, err := c.signer.CreateAuthenticatedMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to create authenticated message: %w", err)
	}

	data, err := json.Marshal(authMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal authenticated message: %w", err)
	}

	// Send to all other operators
	for _, op := range operators {
		if op.OperatorAddress == c.operatorAddr {
			continue // Skip self
		}
		url := buildRequestURL(op.SocketAddress, "/dkg/commitment")
		_, _ = http.Post(url, "application/json", bytes.NewReader(data))
	}
	return nil
}

// BroadcastReshareCommitments broadcasts authenticated reshare commitments to all operators
func (c *Client) BroadcastReshareCommitments(operators []*peering.OperatorSetPeer, commitments []types.G2Point, sessionTimestamp int64) error {
	// Create broadcast message (ToOperatorAddress is zero for broadcast)
	msg := types.CommitmentMessage{
		FromOperatorAddress: c.operatorAddr,
		ToOperatorAddress:   common.Address{}, // Zero address for broadcast
		SessionTimestamp:    sessionTimestamp,
		Commitments:         commitments,
	}

	// Create authenticated message
	authMsg, err := c.signer.CreateAuthenticatedMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to create authenticated message: %w", err)
	}

	data, err := json.Marshal(authMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal authenticated message: %w", err)
	}

	// Send to all other operators
	for _, op := range operators {
		if op.OperatorAddress == c.operatorAddr {
			continue // Skip self
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

	// Create authenticated message
	authMsg, err := c.signer.CreateAuthenticatedMessage(msg)
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

	// Create authenticated message
	authMsg, err := c.signer.CreateAuthenticatedMessage(msg)
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
	msg := types.CompletionMessage{
		FromOperatorAddress: c.operatorAddr,
		ToOperatorAddress:   common.Address{}, // Zero address for broadcast
		SessionTimestamp:    sessionTimestamp,
		Completion:          completion,
	}

	// Create authenticated message
	authMsg, err := c.signer.CreateAuthenticatedMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to create authenticated message: %w", err)
	}

	data, err := json.Marshal(authMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal authenticated message: %w", err)
	}

	for _, op := range operators {
		if op.OperatorAddress == c.operatorAddr {
			continue // Skip self
		}
		url := buildRequestURL(op.SocketAddress, "/reshare/complete")
		_, _ = http.Post(url, "application/json", bytes.NewReader(data))
	}
	return nil
}
