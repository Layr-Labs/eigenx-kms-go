package kmsClient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewClient_ValidationErrors(t *testing.T) {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	tests := []struct {
		name        string
		config      *ClientConfig
		expectedErr string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectedErr: "config cannot be nil",
		},
		{
			name: "empty AVS address",
			config: &ClientConfig{
				AVSAddress:     "",
				OperatorSetID:  0,
				Logger:         logger,
				ContractCaller: nil, // Will be mocked
			},
			expectedErr: "AVS address is required",
		},
		{
			name: "nil logger",
			config: &ClientConfig{
				AVSAddress:     "0x1234567890123456789012345678901234567890",
				OperatorSetID:  0,
				Logger:         nil,
				ContractCaller: nil,
			},
			expectedErr: "logger is required",
		},
		{
			name: "nil contract caller",
			config: &ClientConfig{
				AVSAddress:     "0x1234567890123456789012345678901234567890",
				OperatorSetID:  0,
				Logger:         logger,
				ContractCaller: nil,
			},
			expectedErr: "contract caller is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			assert.Nil(t, client)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

// Note: Full integration tests with a real Ethereum RPC node are in integration tests.
// These unit tests focus on validation logic without requiring external dependencies.

func TestCollectPartialSignatures_ValidationErrors(t *testing.T) {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	// Create a minimal client for testing validation logic
	client := &Client{
		avsAddress:    "0x1234567890123456789012345678901234567890",
		operatorSetID: 0,
		logger:        logger,
	}

	tests := []struct {
		name        string
		appID       string
		operators   interface{}
		threshold   int
		expectedErr string
	}{
		{
			name:        "empty app ID",
			appID:       "",
			operators:   nil,
			threshold:   1,
			expectedErr: "app ID is required",
		},
		{
			name:        "nil operators with positive threshold",
			appID:       "test-app",
			operators:   nil,
			threshold:   1,
			expectedErr: "no operators provided",
		},
		{
			name:        "nil operators with zero threshold",
			appID:       "test-app",
			operators:   nil,
			threshold:   0,
			expectedErr: "no operators provided", // nil operators checked before threshold
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigs, err := client.CollectPartialSignatures(tt.appID, nil, tt.threshold)
			assert.Nil(t, sigs)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestEncrypt_ValidationErrors(t *testing.T) {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	// Create a minimal client for testing validation logic
	client := &Client{
		avsAddress:    "0x1234567890123456789012345678901234567890",
		operatorSetID: 0,
		logger:        logger,
	}

	tests := []struct {
		name        string
		appID       string
		data        []byte
		expectedErr string
	}{
		{
			name:        "empty app ID",
			appID:       "",
			data:        []byte("test data"),
			expectedErr: "app ID is required",
		},
		{
			name:        "empty data",
			appID:       "test-app",
			data:        []byte{},
			expectedErr: "data to encrypt is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := client.Encrypt(tt.appID, tt.data, nil)
			assert.Nil(t, encrypted)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestDecrypt_ValidationErrors(t *testing.T) {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	// Create a minimal client for testing validation logic
	client := &Client{
		avsAddress:    "0x1234567890123456789012345678901234567890",
		operatorSetID: 0,
		logger:        logger,
	}

	tests := []struct {
		name          string
		appID         string
		encryptedData []byte
		expectedErr   string
	}{
		{
			name:          "empty app ID",
			appID:         "",
			encryptedData: []byte("encrypted"),
			expectedErr:   "app ID is required",
		},
		{
			name:          "empty encrypted data",
			appID:         "test-app",
			encryptedData: []byte{},
			expectedErr:   "encrypted data is required",
		},
		{
			name:          "nil operators",
			appID:         "test-app",
			encryptedData: []byte("encrypted"),
			expectedErr:   "no operators provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decrypted, err := client.Decrypt(tt.appID, tt.encryptedData, nil, 1)
			assert.Nil(t, decrypted)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

// createMockPubkeyServer creates a test HTTP server that returns a /pubkey response
func createMockPubkeyServer(t *testing.T, commitments []types.G2Point, mpk *types.G2Point) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pubkey" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		resp := map[string]interface{}{
			"operatorAddress": "0x0000000000000000000000000000000000000001",
			"commitments":     commitments,
			"masterPublicKey": mpk,
			"version":         int64(1),
			"isActive":        true,
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
}

func TestGetMasterPublicKey_ThresholdAgreement_AllHonest(t *testing.T) {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	commitments := []types.G2Point{crypto.G2Generator}

	// Create 4 mock servers all returning the same MPK
	peers := make([]*peering.OperatorSetPeer, 4)
	for i := 0; i < 4; i++ {
		srv := createMockPubkeyServer(t, commitments, &crypto.G2Generator)
		defer srv.Close()
		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress("0x" + string(rune('1'+i)) + "000000000000000000000000000000000000000"),
			SocketAddress:   srv.URL,
		}
	}

	client := &Client{
		avsAddress:    "0x1234567890123456789012345678901234567890",
		operatorSetID: 0,
		logger:        logger,
		httpClient:    &http.Client{},
	}

	operators := &peering.OperatorSetPeers{Peers: peers}
	mpk, err := client.GetMasterPublicKey(operators)
	require.NoError(t, err)
	require.NotNil(t, mpk)
	assert.True(t, mpk.IsEqual(&crypto.G2Generator), "MPK should match the honest value")
}

func TestGetMasterPublicKey_ThresholdAgreement_OneCorrupted(t *testing.T) {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	honestCommitments := []types.G2Point{crypto.G2Generator}
	honestMPK := crypto.G2Generator

	// Create a different "corrupted" MPK
	corruptedMPK := *types.ZeroG2Point()

	// 4 operators: 3 honest, 1 corrupted
	// Threshold for 4 operators = ceil(2*4/3) = 3
	peers := make([]*peering.OperatorSetPeer, 4)

	for i := 0; i < 3; i++ {
		srv := createMockPubkeyServer(t, honestCommitments, &honestMPK)
		defer srv.Close()
		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress("0x" + string(rune('1'+i)) + "000000000000000000000000000000000000000"),
			SocketAddress:   srv.URL,
		}
	}

	// Corrupted operator returns different MPK
	corruptedSrv := createMockPubkeyServer(t, honestCommitments, &corruptedMPK)
	defer corruptedSrv.Close()
	peers[3] = &peering.OperatorSetPeer{
		OperatorAddress: common.HexToAddress("0x4000000000000000000000000000000000000000"),
		SocketAddress:   corruptedSrv.URL,
	}

	client := &Client{
		avsAddress:    "0x1234567890123456789012345678901234567890",
		operatorSetID: 0,
		logger:        logger,
		httpClient:    &http.Client{},
	}

	operators := &peering.OperatorSetPeers{Peers: peers}

	// Verify threshold: for 4 operators, threshold = 3
	require.Equal(t, 3, dkg.CalculateThreshold(4))

	mpk, err := client.GetMasterPublicKey(operators)
	require.NoError(t, err, "Should succeed with 3/4 honest operators (threshold=3)")
	require.NotNil(t, mpk)
	assert.True(t, mpk.IsEqual(&honestMPK), "MPK should match the honest value, not the corrupted one")
}

func TestGetMasterPublicKey_ThresholdAgreement_TooManyCorrupted(t *testing.T) {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	honestCommitments := []types.G2Point{crypto.G2Generator}
	honestMPK := crypto.G2Generator
	corruptedMPK := *types.ZeroG2Point()

	// 4 operators: 2 honest, 2 corrupted
	// Threshold for 4 operators = 3, so neither group meets threshold
	peers := make([]*peering.OperatorSetPeer, 4)

	for i := 0; i < 2; i++ {
		srv := createMockPubkeyServer(t, honestCommitments, &honestMPK)
		defer srv.Close()
		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress("0x" + string(rune('1'+i)) + "000000000000000000000000000000000000000"),
			SocketAddress:   srv.URL,
		}
	}

	for i := 2; i < 4; i++ {
		srv := createMockPubkeyServer(t, honestCommitments, &corruptedMPK)
		defer srv.Close()
		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress("0x" + string(rune('1'+i)) + "000000000000000000000000000000000000000"),
			SocketAddress:   srv.URL,
		}
	}

	client := &Client{
		avsAddress:    "0x1234567890123456789012345678901234567890",
		operatorSetID: 0,
		logger:        logger,
		httpClient:    &http.Client{},
	}

	operators := &peering.OperatorSetPeers{Peers: peers}
	mpk, err := client.GetMasterPublicKey(operators)
	require.Error(t, err, "Should fail when threshold agreement cannot be reached")
	assert.Nil(t, mpk)
	assert.Contains(t, err.Error(), "failed to reach threshold agreement")
}

func TestGetMasterPublicKey_FallbackToAggregation(t *testing.T) {
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	// Create servers that return commitments but NO masterPublicKey (simulating old nodes)
	commitments := []types.G2Point{crypto.G2Generator}

	peers := make([]*peering.OperatorSetPeer, 3)

	for i := 0; i < 3; i++ {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"operatorAddress": "0x0000000000000000000000000000000000000001",
				"commitments":     commitments,
				"version":         int64(1),
				"isActive":        true,
				// No masterPublicKey field - simulating old node
			}
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		}))
		defer srv.Close()
		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress("0x" + string(rune('1'+i)) + "000000000000000000000000000000000000000"),
			SocketAddress:   srv.URL,
		}
	}

	client := &Client{
		avsAddress:    "0x1234567890123456789012345678901234567890",
		operatorSetID: 0,
		logger:        logger,
		httpClient:    &http.Client{},
	}

	operators := &peering.OperatorSetPeers{Peers: peers}
	mpk, err := client.GetMasterPublicKey(operators)
	require.NoError(t, err, "Should fall back to aggregation when no MPK is returned")
	require.NotNil(t, mpk)
}
