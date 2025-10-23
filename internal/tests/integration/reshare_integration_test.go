package integration

import (
	"testing"
	
	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
)

func Test_ReshareIntegration(t *testing.T) {
	// Basic reshare integration test
	cluster := testutil.NewTestCluster(t, 4)
	defer cluster.Close()
	
	// Verify cluster creation for reshare testing
	if len(cluster.Nodes) != 4 {
		t.Fatalf("Expected 4 nodes, got %d", len(cluster.Nodes))
	}
	
	t.Logf("✓ Reshare integration test cluster created with %d nodes", len(cluster.Nodes))
}