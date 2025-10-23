package testutil

import (
	"net/http/httptest"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// TestCluster represents a cluster of KMS nodes for testing  
type TestCluster struct {
	Nodes       []*node.Node
	Servers     []*httptest.Server  
	ServerURLs  []string
	NumNodes    int
	Threshold   int
	MasterPubKey types.G2Point
}

// NewTestCluster creates a test cluster of KMS nodes with completed DKG
func NewTestCluster(t *testing.T, numNodes int) *TestCluster {
	// TODO: Implement test cluster with new authenticated system
	t.Skip("TestCluster disabled pending update to new authenticated message system")
	return nil
}

// GetMasterPublicKey returns the master public key
func (c *TestCluster) GetMasterPublicKey() types.G2Point {
	return c.MasterPubKey
}

// GetServerURLs returns the list of server URLs
func (c *TestCluster) GetServerURLs() []string {
	return c.ServerURLs
}

// Close shuts down all nodes in the cluster
func (c *TestCluster) Close() {
	if c == nil {
		return
	}
	
	for i, server := range c.Servers {
		if server != nil {
			server.Close()
		}
		if i < len(c.Nodes) && c.Nodes[i] != nil {
			_ = c.Nodes[i].Stop()
		}
	}
}