package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

const (
	totalNodes = 7
	basePort   = 8000
)

// generateStubPrivKey generates a stub private key for testing
func generateStubPrivKey(id int) []byte {
	return []byte(fmt.Sprintf("privkey_%d", id))
}

// generateStubPubKey generates a stub public key for testing
func generateStubPubKey(id int) []byte {
	return []byte(fmt.Sprintf("pubkey_%d", id))
}

func main() {
	fmt.Printf("=== Distributed KMS AVS Simulation ===\n")
	fmt.Printf("Initial nodes: %d\n", totalNodes)
	fmt.Printf("Threshold: %d-of-%d\n\n", dkg.CalculateThreshold(totalNodes), totalNodes)

	// Create operator info
	operators := make([]types.OperatorInfo, totalNodes)
	for i := 0; i < totalNodes; i++ {
		operators[i] = types.OperatorInfo{
			ID:           i + 1,
			P2PPubKey:    generateStubPubKey(i + 1),
			P2PNodeURL:   fmt.Sprintf("http://localhost:%d", basePort+i+1),
			KMSServerURL: fmt.Sprintf("http://localhost:%d", basePort+i+1),
		}
	}

	// Create nodes using the new modular architecture
	nodes := make([]*node.Node, totalNodes)
	for i := 0; i < totalNodes; i++ {
		cfg := node.Config{
			ID:         i + 1,
			Port:       basePort + i + 1,
			P2PPrivKey: generateStubPrivKey(i + 1),
			P2PPubKey:  generateStubPubKey(i + 1),
			Operators:  operators,
		}
		nodes[i] = node.NewNode(cfg)
	}

	// Start all nodes
	var wg sync.WaitGroup
	for _, n := range nodes {
		_ = n.Start()
	}

	time.Sleep(500 * time.Millisecond)

	// Run DKG
	fmt.Println("\n=== Running Initial DKG ===")
	for _, n := range nodes {
		wg.Add(1)
		go func(node *node.Node) {
			defer wg.Done()
			_ = node.RunDKG()
		}(n)
	}
	wg.Wait()

	// Test application signing
	fmt.Println("\n=== Testing Application Signing ===")
	appID := "test-app-123"
	attestationTime := time.Now().Unix()

	partialSigs := make(map[int]types.G1Point)
	threshold := dkg.CalculateThreshold(totalNodes)

	// Request signatures from threshold number of nodes
	for i := 1; i <= threshold; i++ {
		req := types.AppSignRequest{
			AppID:           appID,
			AttestationTime: attestationTime,
		}

		data, _ := json.Marshal(req)
		resp, err := http.Post(
			fmt.Sprintf("http://localhost:%d/app/sign", basePort+i),
			"application/json",
			bytes.NewReader(data),
		)

		if err == nil {
			var signResp types.AppSignResponse
			body, _ := io.ReadAll(resp.Body)
			_ = json.Unmarshal(body, &signResp)
			partialSigs[signResp.NodeID] = signResp.PartialSignature
			resp.Body.Close()
			fmt.Printf("Node %d: Received partial signature\n", i)
		}
	}

	// Recover the application private key
	appPrivateKey := crypto.RecoverAppPrivateKey(appID, partialSigs, threshold)
	fmt.Printf("✓ Recovered app_private_key for %s: %v\n", appID, appPrivateKey)

	// Test reshare
	fmt.Println("\n=== Testing Reshare ===")

	for _, n := range nodes {
		wg.Add(1)
		go func(node *node.Node) {
			defer wg.Done()
			_ = node.RunReshareWithTimeout()
		}(n)
	}
	wg.Wait()

	fmt.Println("\n✓ Reshare complete!")
	fmt.Println("\n=== Simulation Complete ===")

	// Cleanup
	for _, n := range nodes {
		_ = n.Stop()
	}
}