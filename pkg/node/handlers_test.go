package node

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/stretchr/testify/assert"
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
		FromOperatorID:   1,
		ToOperatorID:     2,
		SessionTimestamp: 12345,
		Broadcast: &types.CommitmentBroadcast{
			FromOperatorID:   1,
			SessionTimestamp: 5,
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
	require.Equal(t, msg.SessionTimestamp, decoded.SessionTimestamp)
	require.NotNil(t, decoded.Broadcast)
	require.Equal(t, msg.Broadcast.SessionTimestamp, decoded.Broadcast.SessionTimestamp)
}

func TestHandleAppSign_Allowlist(t *testing.T) {
	makeRequest := func(server *Server, appID string) *httptest.ResponseRecorder {
		t.Helper()
		reqBody, _ := json.Marshal(types.AppSignRequest{AppID: appID, AttestationTime: 1})
		httpReq := httptest.NewRequest(http.MethodPost, "/app/sign", bytes.NewBuffer(reqBody))
		w := httptest.NewRecorder()
		server.handleAppSign(w, httpReq)
		return w
	}

	t.Run("nil allowlist allows all apps", func(t *testing.T) {
		f := newTestSecretsFixture(t)
		f.node.appAllowlist = nil

		w := makeRequest(f.server, "any-app")
		// Should not be 403 — it will likely fail later (e.g. no key share for signing),
		// but the allowlist gate must not reject it.
		assert.NotEqual(t, http.StatusForbidden, w.Code)
	})

	t.Run("allowed app passes through", func(t *testing.T) {
		f := newTestSecretsFixture(t)
		f.node.appAllowlist = map[string]bool{"allowed-app": true}

		w := makeRequest(f.server, "allowed-app")
		assert.NotEqual(t, http.StatusForbidden, w.Code)
	})

	t.Run("blocked app returns 403", func(t *testing.T) {
		f := newTestSecretsFixture(t)
		f.node.appAllowlist = map[string]bool{"allowed-app": true}

		w := makeRequest(f.server, "blocked-app")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}
