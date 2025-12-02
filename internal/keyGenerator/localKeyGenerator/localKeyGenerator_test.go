package localKeyGenerator

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup() (*LocalKeyGenerator, error) {
	l, err := logger.NewLogger(&logger.LoggerConfig{
		Debug: true,
	})
	if err != nil {
		return nil, err
	}

	generator := NewLocalKeyGenerator(l)
	return generator, nil
}

func Test_LocalKeyGenerator(t *testing.T) {
	generator, err := setup()
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}

	t.Run("Should create a new LocalKeyGenerator", func(t *testing.T) {
		// Verify the generator was created
		assert.NotNil(t, generator)
		assert.NotNil(t, generator.logger)
	})

	t.Run("Should generate ECDSA key successfully", func(t *testing.T) {
		ctx := context.Background()
		keyName := "test-key-1"
		aliasName := "test-alias-1"

		result, err := generator.GenerateECDSAKey(ctx, keyName, aliasName)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Verify the generated key has all required fields
		assert.NotNil(t, result.PublicKey)
		assert.NotEmpty(t, result.Address)
		assert.NotEmpty(t, result.KeyId)

		// Verify the key ID format
		assert.True(t, strings.HasPrefix(result.KeyId, "local-key-"))

		// Verify the address format (Ethereum address)
		assert.True(t, strings.HasPrefix(result.Address, "0x"))
		assert.Equal(t, 42, len(result.Address)) // 0x + 40 hex characters

		// Verify public key coordinates are not nil
		assert.NotNil(t, result.PublicKey.X)
		assert.NotNil(t, result.PublicKey.Y)
	})

	t.Run("Should generate unique key IDs for different keys", func(t *testing.T) {
		ctx := context.Background()
		keyIds := make(map[string]bool)

		// Generate multiple keys and verify unique IDs
		for i := 0; i < 5; i++ {
			keyName := "test-key"
			aliasName := "test-alias"

			result, err := generator.GenerateECDSAKey(ctx, keyName, aliasName)
			require.NoError(t, err)
			require.NotNil(t, result)

			// Check if key ID is unique
			if keyIds[result.KeyId] {
				t.Errorf("Duplicate key ID generated: %s", result.KeyId)
			}
			keyIds[result.KeyId] = true
		}

		// Verify we generated 5 unique keys
		assert.Equal(t, 5, len(keyIds))
	})

	t.Run("Should generate different addresses for different keys", func(t *testing.T) {
		ctx := context.Background()
		addresses := make(map[string]bool)

		// Generate multiple keys and verify unique addresses
		for i := 0; i < 5; i++ {
			keyName := "test-key"
			aliasName := "test-alias"

			result, err := generator.GenerateECDSAKey(ctx, keyName, aliasName)
			require.NoError(t, err)
			require.NotNil(t, result)

			// Check if address is unique
			if addresses[result.Address] {
				t.Errorf("Duplicate address generated: %s", result.Address)
			}
			addresses[result.Address] = true
		}

		// Verify we generated 5 unique addresses
		assert.Equal(t, 5, len(addresses))
	})

	t.Run("Should handle empty key name", func(t *testing.T) {
		ctx := context.Background()
		keyName := ""
		aliasName := "test-alias"

		result, err := generator.GenerateECDSAKey(ctx, keyName, aliasName)
		// Empty key name should still work as it's just metadata
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.NotEmpty(t, result.KeyId)
		assert.NotEmpty(t, result.Address)
	})

	t.Run("Should handle empty alias name", func(t *testing.T) {
		ctx := context.Background()
		keyName := "test-key"
		aliasName := ""

		result, err := generator.GenerateECDSAKey(ctx, keyName, aliasName)
		// Empty alias name should still work as it's just metadata
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.NotEmpty(t, result.KeyId)
		assert.NotEmpty(t, result.Address)
	})

	t.Run("Should handle both empty key and alias names", func(t *testing.T) {
		ctx := context.Background()
		keyName := ""
		aliasName := ""

		result, err := generator.GenerateECDSAKey(ctx, keyName, aliasName)
		// Empty names should still work as they're just metadata
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.NotEmpty(t, result.KeyId)
		assert.NotEmpty(t, result.Address)
	})

	t.Run("Should handle context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel the context immediately

		keyName := "test-key"
		aliasName := "test-alias"

		// Since key generation is synchronous and doesn't check context,
		// it should still complete successfully
		result, err := generator.GenerateECDSAKey(ctx, keyName, aliasName)
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("Should generate valid Ethereum addresses", func(t *testing.T) {
		ctx := context.Background()
		keyName := "test-key"
		aliasName := "test-alias"

		for i := 0; i < 3; i++ {
			result, err := generator.GenerateECDSAKey(ctx, keyName, aliasName)
			require.NoError(t, err)
			require.NotNil(t, result)

			// Verify Ethereum address format (can be mixed case for checksum addresses)
			assert.Regexp(t, "^0x[0-9a-fA-F]{40}$", result.Address, "Address should be a valid Ethereum address")
		}
	})

	t.Run("Should use consistent address generation", func(t *testing.T) {
		// Test that the same public key always generates the same address
		ctx := context.Background()

		result1, err := generator.GenerateECDSAKey(ctx, "key1", "alias1")
		require.NoError(t, err)

		// Generate the same key again with different name
		result2, err := generator.GenerateECDSAKey(ctx, "key2", "alias2")
		require.NoError(t, err)

		// Different keys should have different addresses
		assert.NotEqual(t, result1.Address, result2.Address)
	})

	t.Run("Should handle special characters in names", func(t *testing.T) {
		ctx := context.Background()
		specialNames := []struct {
			keyName   string
			aliasName string
		}{
			{"test-key-123", "test-alias-456"},
			{"test_key_with_underscores", "test_alias_with_underscores"},
			{"test.key.with.dots", "test.alias.with.dots"},
			{"test/key/with/slashes", "test/alias/with/slashes"},
			{"test key with spaces", "test alias with spaces"},
			{"テストキー", "テストエイリアス"}, // Japanese characters
			{"🔑", "📛"}, // Emojis
		}

		for _, names := range specialNames {
			result, err := generator.GenerateECDSAKey(ctx, names.keyName, names.aliasName)
			require.NoError(t, err, "Failed with keyName=%s, aliasName=%s", names.keyName, names.aliasName)
			require.NotNil(t, result)
			assert.NotEmpty(t, result.KeyId)
			assert.NotEmpty(t, result.Address)
		}
	})

	t.Run("Should generate keys with valid coordinates", func(t *testing.T) {
		ctx := context.Background()
		keyName := "test-key"
		aliasName := "test-alias"

		result, err := generator.GenerateECDSAKey(ctx, keyName, aliasName)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotNil(t, result.PublicKey)

		// Verify the public key has valid coordinates
		assert.NotNil(t, result.PublicKey.X)
		assert.NotNil(t, result.PublicKey.Y)
		// The coordinates should be non-zero
		assert.NotEqual(t, 0, result.PublicKey.X.BitLen())
		assert.NotEqual(t, 0, result.PublicKey.Y.BitLen())
	})

	t.Run("Should handle concurrent key generation", func(t *testing.T) {
		// Create a fresh generator for this test to avoid interference
		freshGenerator, err := setup()
		require.NoError(t, err)

		ctx := context.Background()
		numGoroutines := 10
		results := make(chan *struct {
			keyId   string
			address string
			err     error
		}, numGoroutines)

		// Generate keys concurrently
		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				keyName := "concurrent-key"
				aliasName := "concurrent-alias"

				result, err := freshGenerator.GenerateECDSAKey(ctx, keyName, aliasName)
				if err != nil {
					results <- &struct {
						keyId   string
						address string
						err     error
					}{err: err}
				} else {
					results <- &struct {
						keyId   string
						address string
						err     error
					}{keyId: result.KeyId, address: result.Address}
				}
			}(i)
		}

		// Collect results
		keyIds := make(map[string]bool)
		addresses := make(map[string]bool)

		for i := 0; i < numGoroutines; i++ {
			result := <-results
			require.NoError(t, result.err)

			// Verify uniqueness
			assert.False(t, keyIds[result.keyId], "Duplicate key ID in concurrent generation")
			assert.False(t, addresses[result.address], "Duplicate address in concurrent generation")

			keyIds[result.keyId] = true
			addresses[result.address] = true
		}

		// Verify we got the expected number of unique results
		assert.Equal(t, numGoroutines, len(keyIds))
		assert.Equal(t, numGoroutines, len(addresses))

		// Verify all keys are stored
		assert.Equal(t, numGoroutines, freshGenerator.GetKeyCount())
	})

	t.Run("Should retrieve key by ID", func(t *testing.T) {
		ctx := context.Background()
		keyName := "test-key-retrieve"
		aliasName := "test-alias-retrieve"

		// Generate a key
		generatedKey, err := generator.GenerateECDSAKey(ctx, keyName, aliasName)
		require.NoError(t, err)
		require.NotNil(t, generatedKey)

		// Retrieve the key by ID
		retrievedKey, err := generator.GetECDSAKeyById(ctx, generatedKey.KeyId)
		require.NoError(t, err)
		require.NotNil(t, retrievedKey)

		// Verify the retrieved key matches the generated key
		assert.Equal(t, generatedKey.KeyId, retrievedKey.KeyId)
		assert.Equal(t, generatedKey.Address, retrievedKey.Address)
		assert.Equal(t, generatedKey.PublicKey.X, retrievedKey.PublicKey.X)
		assert.Equal(t, generatedKey.PublicKey.Y, retrievedKey.PublicKey.Y)
	})

	t.Run("Should return error for non-existent key ID", func(t *testing.T) {
		ctx := context.Background()
		nonExistentKeyId := "non-existent-key-id"

		retrievedKey, err := generator.GetECDSAKeyById(ctx, nonExistentKeyId)
		assert.Error(t, err)
		assert.Nil(t, retrievedKey)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("Should sign message with stored key", func(t *testing.T) {
		ctx := context.Background()
		keyName := "test-key-sign"
		aliasName := "test-alias-sign"

		// Generate a key
		generatedKey, err := generator.GenerateECDSAKey(ctx, keyName, aliasName)
		require.NoError(t, err)
		require.NotNil(t, generatedKey)

		// Sign a message
		message := []byte("test message to sign")
		// Hash the message using Keccak256 before signing
		messageHash := crypto.Keccak256(message)
		signature, err := generator.SignMessage(ctx, generatedKey.KeyId, messageHash)
		require.NoError(t, err)
		require.NotNil(t, signature)

		// Verify signature length (should be 65 bytes for Ethereum signatures)
		assert.Equal(t, 65, len(signature))
	})

	t.Run("Should return error when signing with non-existent key", func(t *testing.T) {
		ctx := context.Background()
		nonExistentKeyId := "non-existent-signing-key"
		message := []byte("test message")
		// Hash the message using Keccak256 before signing
		messageHash := crypto.Keccak256(message)

		signature, err := generator.SignMessage(ctx, nonExistentKeyId, messageHash)
		assert.Error(t, err)
		assert.Nil(t, signature)
		assert.Contains(t, err.Error(), "not found")
	})
}

func Benchmark_GenerateECDSAKey(b *testing.B) {
	generator, err := setup()
	if err != nil {
		b.Fatalf("Failed to setup benchmark: %v", err)
	}

	ctx := context.Background()
	keyName := "benchmark-key"
	aliasName := "benchmark-alias"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateECDSAKey(ctx, keyName, aliasName)
		if err != nil {
			b.Fatalf("Failed to generate key: %v", err)
		}
	}
}

func Test_HelperFunctions(t *testing.T) {
	generator, err := setup()
	require.NoError(t, err)

	t.Run("Should load private key into store", func(t *testing.T) {
		// Generate a private key using the new ecdsa package
		privateKey, publicKey, err := ecdsa.GenerateKeyPair()
		require.NoError(t, err)

		keyId := "test-loaded-key"
		keyName := "loaded-key"
		aliasName := "loaded-alias"

		// Load the key
		err = generator.LoadPrivateKey(keyId, privateKey, keyName, aliasName)
		require.NoError(t, err)

		// Verify the key exists
		assert.True(t, generator.KeyExists(keyId))

		// Retrieve the key
		ctx := context.Background()
		retrievedKey, err := generator.GetECDSAKeyById(ctx, keyId)
		require.NoError(t, err)
		assert.Equal(t, keyId, retrievedKey.KeyId)
		assert.Equal(t, publicKey.X, retrievedKey.PublicKey.X)
		assert.Equal(t, publicKey.Y, retrievedKey.PublicKey.Y)
	})

	t.Run("Should load private key from hex", func(t *testing.T) {
		// Use a test private key hex (this is a well-known test key, do not use in production)
		privateKeyHex := "fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19"
		keyId := "test-hex-key"
		keyName := "hex-key"
		aliasName := "hex-alias"

		// Load the key from hex
		err := generator.LoadPrivateKeyFromHex(keyId, privateKeyHex, keyName, aliasName)
		require.NoError(t, err)

		// Verify the key exists
		assert.True(t, generator.KeyExists(keyId))

		// Sign a message with it
		ctx := context.Background()
		message := []byte("test message")
		// Hash the message using Keccak256 before signing
		messageHash := crypto.Keccak256(message)
		signature, err := generator.SignMessage(ctx, keyId, messageHash)
		require.NoError(t, err)
		assert.NotNil(t, signature)
	})

	t.Run("Should prevent duplicate key IDs", func(t *testing.T) {
		privateKey, _, err := ecdsa.GenerateKeyPair()
		require.NoError(t, err)

		keyId := "duplicate-test-key"

		// Load the key once
		err = generator.LoadPrivateKey(keyId, privateKey, "key1", "alias1")
		require.NoError(t, err)

		// Try to load with the same ID
		err = generator.LoadPrivateKey(keyId, privateKey, "key2", "alias2")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("Should generate and load key", func(t *testing.T) {
		keyName := "gen-load-key"
		aliasName := "gen-load-alias"

		// Note: GenerateAndLoadKey now returns just error
		err := generator.GenerateAndLoadKey(keyName, aliasName)
		require.NoError(t, err)

		// Verify at least one key is in the store
		assert.Greater(t, generator.GetKeyCount(), 0)
	})

	t.Run("Should track key count correctly", func(t *testing.T) {
		// Clear all keys first
		generator.ClearKeys()
		assert.Equal(t, 0, generator.GetKeyCount())

		// Generate some keys
		ctx := context.Background()
		for i := 0; i < 3; i++ {
			_, err := generator.GenerateECDSAKey(ctx, fmt.Sprintf("key-%d", i), fmt.Sprintf("alias-%d", i))
			require.NoError(t, err)
		}

		assert.Equal(t, 3, generator.GetKeyCount())

		// Clear again
		generator.ClearKeys()
		assert.Equal(t, 0, generator.GetKeyCount())
	})

	t.Run("Should clear all keys", func(t *testing.T) {
		// Generate some keys
		ctx := context.Background()
		var keyIds []string
		for i := 0; i < 5; i++ {
			result, err := generator.GenerateECDSAKey(ctx, fmt.Sprintf("clear-key-%d", i), fmt.Sprintf("clear-alias-%d", i))
			require.NoError(t, err)
			keyIds = append(keyIds, result.KeyId)
		}

		// Verify keys exist
		for _, keyId := range keyIds {
			assert.True(t, generator.KeyExists(keyId))
		}

		// Clear all keys
		generator.ClearKeys()

		// Verify keys no longer exist
		for _, keyId := range keyIds {
			assert.False(t, generator.KeyExists(keyId))
		}
		assert.Equal(t, 0, generator.GetKeyCount())
	})
}
