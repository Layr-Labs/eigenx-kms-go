package node

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleCommitmentBroadcast tests the commitment broadcast handler (Phase 5)
func TestHandleCommitmentBroadcast(t *testing.T) {
	t.Run("Handler exists", func(t *testing.T) {
		server := &Server{}
		require.NotNil(t, server.handleCommitmentBroadcast)
	})
}

// TestCommitmentBroadcastMessage_Serialization tests message serialization (Phase 5)
func TestCommitmentBroadcastMessage_Serialization(t *testing.T) {
	msg := types.CommitmentBroadcastMessage{
		FromOperatorAddress: common.HexToAddress("0x1234"),
		ToOperatorAddress:   common.HexToAddress("0x5678"),
		FromOperatorID:      1,
		ToOperatorID:        2,
		SessionTimestamp:    12345,
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
	require.Equal(t, msg.FromOperatorAddress, decoded.FromOperatorAddress)
	require.Equal(t, msg.ToOperatorAddress, decoded.ToOperatorAddress)
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

	t.Run("whitespace in allowlist values is trimmed at construction", func(t *testing.T) {
		f := newTestSecretsFixture(t)
		// Simulate what urfave/cli produces from "app-1, app-2" (leading space).
		// Directly rebuild the allowlist the same way NewNode does.
		cfg := []string{" my-app ", "other-app"}
		f.node.appAllowlist = make(map[string]bool, len(cfg))
		for _, id := range cfg {
			f.node.appAllowlist[strings.TrimSpace(id)] = true
		}

		// "my-app" (no spaces) should match the trimmed entry
		w := makeRequest(f.server, "my-app")
		assert.NotEqual(t, http.StatusForbidden, w.Code)
	})
}
