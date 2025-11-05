package integration

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/client"
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
	kmsClient := client.NewKMSClient(cluster.GetServerURLs(), clientLogger)

	// Test Identity-Based Encryption for an application
	appID := "test-app-ibe"
	plaintext := []byte("secret application configuration data")

	t.Logf("Testing IBE encryption/decryption for app: %s", appID)

	// Step 1: Get master public key from operators (via /pubkey endpoint)
	masterPubKey, err := kmsClient.GetMasterPublicKey()
	if err != nil {
		t.Fatalf("Failed to get master public key: %v", err)
	}

	if masterPubKey.X.Sign() == 0 {
		t.Fatal("Master public key should not be zero")
	}

	t.Logf("  ✓ Retrieved master public key from operators via HTTP")

	// Step 2: Encrypt data using IBE
	ciphertext, err := kmsClient.EncryptForApp(appID, masterPubKey, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("Ciphertext should not be empty")
	}

	t.Logf("  ✓ Encrypted %d bytes → %d bytes ciphertext", len(plaintext), len(ciphertext))

	// Step 3: Decrypt data (client collects partial signatures via /app/sign)
	decrypted, err := kmsClient.DecryptForApp(appID, ciphertext, 0)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	// Step 4: Verify decrypted data matches original
	if string(decrypted) != string(plaintext) {
		t.Fatalf("Decryption mismatch: expected %q, got %q", string(plaintext), string(decrypted))
	}

	t.Logf("✓ IBE integration test passed")
	t.Logf("  - Client queried /pubkey endpoints for master public key")
	t.Logf("  - Encrypted with IBE using master public key")
	t.Logf("  - Client queried /app/sign endpoints for partial signatures")
	t.Logf("  - Recovered app private key from threshold signatures")
	t.Logf("  - Successfully decrypted: %q", string(decrypted))
	t.Logf("  - Full client-to-operator flow working correctly")
}
