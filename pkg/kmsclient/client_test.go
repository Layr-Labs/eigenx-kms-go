package kmsclient

import (
	"testing"

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
