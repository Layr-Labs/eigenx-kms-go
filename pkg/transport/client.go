package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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
	nodeID      int
	retryConfig RetryConfig
}

// NewClient creates a new transport client
func NewClient(nodeID int) *Client {
	return &Client{
		nodeID:      nodeID,
		retryConfig: DefaultRetryConfig,
	}
}

// SendShareWithRetry sends a share to another node with retries
func (c *Client) SendShareWithRetry(toOperator types.OperatorInfo, share *fr.Element, endpoint string) error {
	msg := types.ShareMessage{
		FromID: c.nodeID,
		ToID:   toOperator.ID,
		Share:  types.SerializeFr(share),
	}

	data, _ := json.Marshal(msg)
	backoff := c.retryConfig.InitialBackoff

	for attempt := 0; attempt < c.retryConfig.MaxAttempts; attempt++ {
		resp, err := http.Post(toOperator.P2PNodeURL+endpoint, "application/json", bytes.NewReader(data))
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

	return fmt.Errorf("failed to send share after %d attempts", c.retryConfig.MaxAttempts)
}

// BroadcastCommitments broadcasts commitments to all operators
func (c *Client) BroadcastCommitments(operators []types.OperatorInfo, commitments []types.G2Point, endpoint string) error {
	msg := types.CommitmentMessage{
		FromID:      c.nodeID,
		Commitments: commitments,
	}

	data, _ := json.Marshal(msg)

	for _, op := range operators {
		if op.ID == c.nodeID {
			continue
		}
		_, _ = http.Post(op.P2PNodeURL+endpoint, "application/json", bytes.NewReader(data))
	}
	return nil
}

// SendAcknowledgement sends an acknowledgement to a specific operator
func (c *Client) SendAcknowledgement(ack *types.Acknowledgement, toOperator types.OperatorInfo, endpoint string) error {
	msg := types.AcknowledgementMessage{Ack: ack}
	data, _ := json.Marshal(msg)

	resp, err := http.Post(toOperator.P2PNodeURL+endpoint, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return nil
}

// BroadcastCompletionSignature broadcasts a completion signature
func (c *Client) BroadcastCompletionSignature(operators []types.OperatorInfo, completion *types.CompletionSignature) error {
	msg := types.CompletionMessage{Completion: completion}
	data, _ := json.Marshal(msg)

	for _, op := range operators {
		if op.ID == c.nodeID {
			continue
		}
		_, _ = http.Post(op.P2PNodeURL+"/reshare/complete", "application/json", bytes.NewReader(data))
	}
	return nil
}