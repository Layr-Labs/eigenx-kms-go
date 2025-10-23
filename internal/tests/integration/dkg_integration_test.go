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

// testFullDKGProtocol tests a complete DKG protocol run using real Node instances
func testFullDKGProtocol(t *testing.T) {
	// Create test cluster with real Node instances
	cluster := testutil.NewTestCluster(t, 5)
	defer cluster.Close()
	
	// Verify DKG completed successfully
	masterPubKey := cluster.GetMasterPublicKey()
	if masterPubKey.X.Sign() == 0 {
		t.Fatal("Master public key should not be zero after DKG")
	}
	
	// Verify all nodes have active key shares
	for i, node := range cluster.Nodes {
		activeVersion := node.GetKeyStore().GetActiveVersion()
		if activeVersion == nil {
			t.Errorf("Node %d should have active key version", i+1)
			continue
		}
		if activeVersion.PrivateShare == nil {
			t.Errorf("Node %d should have valid private share", i+1)
		}
	}
	
	// Verify threshold properties
	if cluster.Threshold != (2*cluster.NumNodes+2)/3 {
		t.Errorf("Cluster should have correct threshold: expected %d, got %d", 
			(2*cluster.NumNodes+2)/3, cluster.Threshold)
	}
	
	t.Logf("✓ DKG protocol integration test passed with %d nodes", cluster.NumNodes)
}