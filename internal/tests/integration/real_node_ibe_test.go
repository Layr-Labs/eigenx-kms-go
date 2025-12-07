package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
)

func Test_IBEIntegration(t *testing.T) {
	// Create cluster and wait for automatic DKG
	cluster := testutil.NewTestCluster(t, 3)
	defer cluster.Close()

	// Create logger for client
	clientLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	// Create KMS client with operator URLs (like a real application would)
	kmsClient := kmsClient.NewKMSClient(cluster.GetServerURLs(), clientLogger)

	// Test Identity-Based Encryption for an application
	appID := "test-app-ibe"
	plaintext := []byte("secret application configuration data")

	t.Logf("Testing IBE encryption/decryption for app: %s", appID)

	// Step 1: Get master public key from operators (via /pubkey endpoint)
	masterPubKey, err := kmsClient.GetMasterPublicKey()
	require.NoError(t, err, "Failed to get master public key")

	isZero, err := masterPubKey.IsZero()
	require.NoError(t, err, "Failed to check if master public key is zero")
	require.False(t, isZero, "Master public key should not be zero")

	t.Logf("  ✓ Retrieved master public key from operators via HTTP")

	// Step 2: Encrypt data using IBE
	ciphertext, err := kmsClient.EncryptForApp(appID, masterPubKey, plaintext)
	require.NoError(t, err, "Failed to encrypt data")

	require.NotEmpty(t, ciphertext, "Ciphertext should not be empty")

	t.Logf("  ✓ Encrypted %d bytes → %d bytes ciphertext", len(plaintext), len(ciphertext))

	// Step 3: Decrypt data (client collects partial signatures via /app/sign)
	decrypted, err := kmsClient.DecryptForApp(appID, ciphertext, 0)
	require.NoError(t, err, "Failed to decrypt data")

	// Step 4: Verify decrypted data matches original
	require.Equal(t, string(plaintext), string(decrypted), "Decryption mismatch")

	t.Logf("✓ IBE integration test passed")
	t.Logf("  - Client queried /pubkey endpoints for master public key")
	t.Logf("  - Encrypted with IBE using master public key")
	t.Logf("  - Client queried /app/sign endpoints for partial signatures")
	t.Logf("  - Recovered app private key from threshold signatures")
	t.Logf("  - Successfully decrypted: %q", string(decrypted))
	t.Logf("  - Full client-to-operator flow working correctly")
}
