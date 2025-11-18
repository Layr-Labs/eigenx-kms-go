package node

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestHandleCommitmentBroadcast tests the commitment broadcast handler (Phase 5)
func TestHandleCommitmentBroadcast(t *testing.T) {
	// This test verifies the handler function exists and accepts the correct message type
	// Full integration tests with real sessions will be in Phase 7

	t.Run("Handler exists", func(t *testing.T) {
		server := &Server{}
		require.NotNil(t, server.handleCommitmentBroadcast)
	})

	t.Run("Method not allowed", func(t *testing.T) {
		server := &Server{node: &Node{}}

		req := httptest.NewRequest(http.MethodGet, "/dkg/broadcast", nil)
		w := httptest.NewRecorder()

		server.handleCommitmentBroadcast(w, req)

		require.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		server := &Server{node: &Node{}}

		req := httptest.NewRequest(http.MethodPost, "/dkg/broadcast", bytes.NewReader([]byte("invalid json")))
		w := httptest.NewRecorder()

		server.handleCommitmentBroadcast(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestCommitmentBroadcastMessage_Serialization tests message serialization (Phase 5)
func TestCommitmentBroadcastMessage_Serialization(t *testing.T) {
	msg := types.CommitmentBroadcastMessage{
		FromOperatorID: 1,
		ToOperatorID:   2,
		SessionID:      12345,
		Broadcast: &types.CommitmentBroadcast{
			FromOperatorID:   1,
			Epoch:            5,
			Commitments:      []types.G2Point{},
			Acknowledgements: []*types.Acknowledgement{},
			MerkleProof:      [][32]byte{{1, 2, 3}},
		},
	}

	// Serialize
	data, err := json.Marshal(msg)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Deserialize
	var decoded types.CommitmentBroadcastMessage
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify fields
	require.Equal(t, msg.FromOperatorID, decoded.FromOperatorID)
	require.Equal(t, msg.ToOperatorID, decoded.ToOperatorID)
	require.Equal(t, msg.SessionID, decoded.SessionID)
	require.NotNil(t, decoded.Broadcast)
	require.Equal(t, msg.Broadcast.Epoch, decoded.Broadcast.Epoch)
}
