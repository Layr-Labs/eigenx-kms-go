package integration

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/client"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/registry"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"time"
)

// Test_NodeIntegration tests complete node operations using real components
func Test_NodeIntegration(t *testing.T) {
	t.Run("ApplicationSecretsFlow", func(t *testing.T) {
		testApplicationSecretsFlow(t)
	})
}

// testApplicationSecretsFlow tests the complete end-to-end flow as specified in the design docs
func testApplicationSecretsFlow(t *testing.T) {
	// Use real test cluster instead of manual setup
	cluster := testutil.NewTestCluster(t, 3)
	defer cluster.Close()
	
	// Add test release to all nodes
	testRelease := &types.Release{
		ImageDigest:  "sha256:app123",
		EncryptedEnv: "encrypted-secrets-for-my-app",
		PublicEnv:    "NODE_ENV=production",
		Timestamp:    time.Now().Unix(),
	}
	
	for _, node := range cluster.Nodes {
		if stubRegistry, ok := node.GetReleaseRegistry().(*registry.StubClient); ok {
			stubRegistry.AddTestRelease("my-app", testRelease)
		}
	}
	
	// Use real KMS client for the application flow
	kmsClient := client.NewKMSClient(cluster.GetServerURLs())
	
	result, err := kmsClient.RetrieveSecrets("my-app", "sha256:app123")
	if err != nil {
		t.Fatalf("Application secret retrieval failed: %v", err)
	}
	
	// Verify we got threshold responses
	if result.ResponseCount < result.ThresholdNeeded {
		t.Fatalf("Insufficient responses: got %d, need %d", result.ResponseCount, result.ThresholdNeeded)
	}
	
	// Verify app private key is valid
	if result.AppPrivateKey.X.Sign() == 0 {
		t.Fatal("Recovered application private key should not be zero")
	}
	
	// Verify environment data consistency
	expectedEnv := "encrypted-secrets-for-my-app"
	if result.EncryptedEnv != expectedEnv {
		t.Errorf("Environment mismatch: expected %s, got %s", expectedEnv, result.EncryptedEnv)
	}
	
	t.Logf("✓ Application secrets flow integration test passed")
	t.Logf("  - Retrieved secrets from %d KMS servers", result.ResponseCount)
	t.Logf("  - Verified threshold agreement on environment data")
	t.Logf("  - Recovered application private key via threshold signatures")
	t.Logf("  - Used real Node instances with actual DKG key shares")
}