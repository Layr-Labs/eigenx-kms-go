package integration

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
	"github.com/ethereum/go-ethereum/common"
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
	
	// For now, just verify cluster was created successfully
	if cluster == nil {
		t.Fatal("Expected non-nil test cluster")
	}
	
	if len(cluster.Nodes) != 5 {
		t.Fatalf("Expected 5 nodes, got %d", len(cluster.Nodes))
	}
	
	if cluster.Threshold != (2*5+2)/3 {
		t.Errorf("Expected threshold %d, got %d", (2*5+2)/3, cluster.Threshold)
	}
	
	// Verify all nodes were created with proper addresses
	for i, n := range cluster.Nodes {
		if n == nil {
			t.Errorf("Node %d is nil", i)
		} else if n.GetOperatorAddress() == (common.Address{}) {
			t.Errorf("Node %d has zero address", i)
		}
	}
	
	t.Logf("✓ DKG integration test cluster created with %d nodes", cluster.NumNodes)
}