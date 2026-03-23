package kmsClient

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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

func TestDecryptWithRetry_InvalidCiphertextFailsFast(t *testing.T) {
	appID := "test-fail-fast"
	threshold := 3

	// Generate valid partial signatures so the retry loop would have work to do
	partialSigs := generateTestPartialSigs(t, appID, 4, threshold)

	tests := []struct {
		name       string
		ciphertext []byte
		errContain string
	}{
		{
			name:       "nil ciphertext",
			ciphertext: nil,
			errContain: "ciphertext too short",
		},
		{
			name:       "empty ciphertext",
			ciphertext: []byte{},
			errContain: "ciphertext too short",
		},
		{
			name:       "wrong magic number",
			ciphertext: append([]byte("BAD\x01"), make([]byte, 200)...),
			errContain: "invalid ciphertext format",
		},
		{
			name:       "wrong version",
			ciphertext: append([]byte("IBE\xFF"), make([]byte, 200)...),
			errContain: "unsupported ciphertext version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decryptWithRetry(appID, partialSigs, threshold, tt.ciphertext)
			assert.Nil(t, result)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContain)
		})
	}
}

func TestDecryptWithRetry_ValidCiphertext(t *testing.T) {
	appID := "test-decrypt-retry-client"
	n, threshold := 5, 4
	plaintext := []byte("client-side retry test data")

	partialSigs := generateTestPartialSigs(t, appID, n, threshold)

	// Compute master public key and encrypt
	// Sum of all secrets = master secret; we need master pubkey for encryption
	// For simplicity, recover the app private key first, then encrypt with master pubkey
	masterSecret := new(fr.Element).SetInt64(0)
	// We can't easily get the master secret from partial sigs, so use the crypto package
	// to recover the app private key and verify round-trip through decryptWithRetry
	appPrivKey, err := crypto.RecoverAppPrivateKey(appID, partialSigs, threshold)
	require.NoError(t, err)

	// To encrypt, we need the master public key. Derive it from the app private key
	// by using the pairing relationship. Instead, generate a fresh DKG setup.
	_ = appPrivKey
	_ = masterSecret

	// Use a simpler approach: generate keys, encrypt, then test decryptWithRetry
	secret := new(fr.Element)
	_, err = secret.SetRandom()
	require.NoError(t, err)

	masterPubKey, err := crypto.ScalarMulG2(crypto.G2Generator, secret)
	require.NoError(t, err)

	ciphertext, err := crypto.EncryptForApp(appID, *masterPubKey, plaintext)
	require.NoError(t, err)

	// Generate proper partial sigs from the known secret
	sigs := generatePartialSigsFromSecret(t, appID, secret, n, threshold)

	result, err := decryptWithRetry(appID, sigs, threshold, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, result)
}

// generateTestPartialSigs creates partial signatures for testing.
// Returns a map of node ID -> partial signature.
func generateTestPartialSigs(t *testing.T, appID string, n, threshold int) map[int64]types.G1Point {
	t.Helper()
	secret := new(fr.Element)
	_, err := secret.SetRandom()
	require.NoError(t, err)
	return generatePartialSigsFromSecret(t, appID, secret, n, threshold)
}

// generatePartialSigsFromSecret creates partial signatures from a known master secret.
func generatePartialSigsFromSecret(t *testing.T, appID string, secret *fr.Element, n, threshold int) map[int64]types.G1Point {
	t.Helper()

	// Generate polynomial coefficients (secret is the constant term)
	coeffs := make([]*fr.Element, threshold)
	coeffs[0] = new(fr.Element).Set(secret)
	for i := 1; i < threshold; i++ {
		coeffs[i] = new(fr.Element)
		_, err := coeffs[i].SetRandom()
		require.NoError(t, err)
	}

	// Hash appID to G1
	qID, err := crypto.HashToG1(appID)
	require.NoError(t, err)

	// Generate shares and partial signatures
	partialSigs := make(map[int64]types.G1Point, n)
	for i := 1; i <= n; i++ {
		nodeID := int64(i)
		x := new(fr.Element).SetInt64(nodeID)

		// Evaluate polynomial at x
		share := new(fr.Element).Set(coeffs[threshold-1])
		for j := threshold - 2; j >= 0; j-- {
			share.Mul(share, x).Add(share, coeffs[j])
		}

		// Partial sig = share * H(appID)
		partialSig, err := crypto.ScalarMulG1(*qID, share)
		require.NoError(t, err)
		partialSigs[nodeID] = *partialSig
	}

	return partialSigs
}
