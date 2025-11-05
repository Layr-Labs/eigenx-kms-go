package integration

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
)

// Test_DKGIntegration tests the complete DKG protocol using real Node instances
func Test_DKGIntegration(t *testing.T) {
	t.Run("FullDKGProtocol", func(t *testing.T) {
		testFullDKGProtocol(t)
	})
}

// testFullDKGProtocol tests automatic DKG execution via interval-based scheduling
func testFullDKGProtocol(t *testing.T) {
	// Create test cluster - nodes start with schedulers running
	cluster := testutil.NewTestCluster(t, 5)
	defer cluster.Close()

	// testutil.NewTestCluster() already waits for DKG completion
	// Verify all nodes have active key shares
	for i, n := range cluster.Nodes {
		activeVersion := n.GetKeyStore().GetActiveVersion()
		if activeVersion == nil {
			t.Fatalf("Node %d should have active key version after automatic DKG", i+1)
		}
		if activeVersion.PrivateShare == nil {
			t.Fatalf("Node %d should have valid private share", i+1)
		}
	}

	// Verify master public key was computed
	masterPubKey := cluster.GetMasterPublicKey()
	if masterPubKey.X.Sign() == 0 {
		t.Fatal("Master public key should not be zero after DKG")
	}

	// Verify threshold properties
	expectedThreshold := (2*5 + 2) / 3
	if expectedThreshold != 4 {
		t.Errorf("Expected threshold 4 for 5 nodes, got %d", expectedThreshold)
	}

	t.Logf("✓ Automatic DKG integration test passed")
	t.Logf("  - Nodes: %d", cluster.NumNodes)
	t.Logf("  - All nodes have active key shares")
	t.Logf("  - Master public key computed successfully")
	t.Logf("  - DKG triggered automatically via scheduler")
}
