package integration

import (
	"testing"
	
	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
)

func Test_IBEIntegration(t *testing.T) {
	// Basic IBE integration test
	cluster := testutil.NewTestCluster(t, 3)
	defer cluster.Close()
	
	// Verify cluster creation for IBE testing
	if len(cluster.Nodes) != 3 {
		t.Fatalf("Expected 3 nodes, got %d", len(cluster.Nodes))
	}
	
	t.Logf("✓ IBE integration test cluster created with %d nodes", len(cluster.Nodes))
}