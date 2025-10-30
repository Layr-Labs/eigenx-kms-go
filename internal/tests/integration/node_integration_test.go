package integration

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
)

func Test_NodeIntegration(t *testing.T) {
	// Basic node integration test
	cluster := testutil.NewTestCluster(t, 3)
	defer cluster.Close()

	// Verify cluster creation
	if len(cluster.Nodes) != 3 {
		t.Fatalf("Expected 3 nodes, got %d", len(cluster.Nodes))
	}

	// Verify all nodes are properly initialized
	for i, node := range cluster.Nodes {
		if node == nil {
			t.Errorf("Node %d is nil", i)
		}
	}

	t.Logf("✓ Node integration test passed with %d nodes", len(cluster.Nodes))
}
