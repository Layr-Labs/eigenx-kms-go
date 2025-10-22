package integration

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/client"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/registry"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// generateHexAppID creates a 32-byte hex string app ID as used in production
func generateHexAppID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Test_RealNodeIBE contains IBE tests using actual Node instances and HTTP endpoints
func Test_RealNodeIBE(t *testing.T) {
	t.Run("GetAppPublicKeyWith32ByteHex", func(t *testing.T) {
		testGetAppPublicKeyWith32ByteHex(t)
	})
	
	t.Run("RealNodeDKGFlow", func(t *testing.T) {
		testRealNodeDKGFlow(t)
	})
	
	t.Run("EndToEndIBEWithRealNodesAndHTTP", func(t *testing.T) {
		testEndToEndIBEWithRealNodesAndHTTP(t)
	})
	
	t.Run("EncryptionPersistenceWithRealNodes", func(t *testing.T) {
		testEncryptionPersistenceWithRealNodes(t)
	})
	
	t.Run("MultipleHexAppIDsWithRealKMS", func(t *testing.T) {
		testMultipleHexAppIDsWithRealKMS(t)
	})
}

// testGetAppPublicKeyWith32ByteHex tests public key derivation with realistic hex app IDs
func testGetAppPublicKeyWith32ByteHex(t *testing.T) {
	// Test with realistic 32-byte hex app ID
	appID := generateHexAppID()
	
	fmt.Printf("Testing public key derivation for 32-byte hex app ID: %s\n", appID)
	
	// Get the application's "public key" (Q_ID = H_1(app_id))
	appPubKey := crypto.GetAppPublicKey(appID)
	
	// Verify it's not zero
	if appPubKey.X.Sign() == 0 {
		t.Error("App public key should not be zero")
	}
	
	// Verify it's deterministic
	appPubKey2 := crypto.GetAppPublicKey(appID)
	if appPubKey.X.Cmp(appPubKey2.X) != 0 {
		t.Error("App public key should be deterministic")
	}
	
	// Verify different apps have different keys
	differentAppID := generateHexAppID()
	differentApp := crypto.GetAppPublicKey(differentAppID)
	if appPubKey.X.Cmp(differentApp.X) == 0 {
		t.Error("Different apps should have different public keys")
	}
	
	fmt.Printf("✓ Public key derivation works for 32-byte hex app ID: %s\n", appID[:16]+"...")
}

// testRealNodeDKGFlow tests DKG using actual Node instances
func testRealNodeDKGFlow(t *testing.T) {
	// Create a test cluster with real Node instances
	cluster := testutil.NewTestCluster(t, 5)
	defer cluster.Close()
	
	// Verify cluster was set up correctly
	if cluster.NumNodes != 5 {
		t.Fatalf("Expected 5 nodes, got %d", cluster.NumNodes)
	}
	
	expectedThreshold := dkg.CalculateThreshold(5)
	if cluster.Threshold != expectedThreshold {
		t.Fatalf("Expected threshold %d, got %d", expectedThreshold, cluster.Threshold)
	}
	
	// Verify master public key was computed from real DKG
	masterPubKey := cluster.GetMasterPublicKey()
	if masterPubKey.X.Sign() == 0 {
		t.Fatal("Master public key should not be zero after real DKG")
	}
	
	fmt.Printf("✓ Real Node DKG completed:\n")
	fmt.Printf("  - Nodes: %d\n", cluster.NumNodes)
	fmt.Printf("  - Threshold: %d\n", cluster.Threshold)
	fmt.Printf("  - Master public key: %x...\n", masterPubKey.X.Bytes()[:8])
	
	// Test that all nodes can generate partial signatures
	testAppID := generateHexAppID()
	
	for i, node := range cluster.Nodes {
		partialSig := node.SignAppID(testAppID, time.Now().Unix())
		if partialSig.X.Sign() == 0 {
			t.Errorf("Node %d should generate non-zero partial signature", i+1)
		}
		fmt.Printf("  - Node %d: Generated partial signature %x...\n", i+1, partialSig.X.Bytes()[:4])
	}
}

// testEndToEndIBEWithRealNodesAndHTTP tests complete IBE flow with HTTP endpoints
func testEndToEndIBEWithRealNodesAndHTTP(t *testing.T) {
	// Create test cluster
	cluster := testutil.NewTestCluster(t, 3)
	defer cluster.Close()
	
	appID := generateHexAppID()
	imageDigest := "sha256:e2etest12345"
	
	fmt.Printf("\n=== Testing Complete IBE Flow with Real Nodes ===\n")
	fmt.Printf("App ID: %s\n", appID)
	fmt.Printf("Cluster: %d nodes, threshold: %d\n", cluster.NumNodes, cluster.Threshold)
	
	// === Step 1: Derive Public Key (anyone can do this) ===
	appPublicKey := crypto.GetAppPublicKey(appID)
	fmt.Printf("✓ App public key derived: %x...\n", appPublicKey.X.Bytes()[:8])
	
	// === Step 2: Encrypt Data for the App ===
	secretData := []byte("Top secret application data requiring threshold decryption from real KMS nodes")
	
	masterPubKey := cluster.GetMasterPublicKey()
	ciphertext, err := crypto.EncryptForApp(appID, masterPubKey, secretData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	fmt.Printf("✓ Encrypted %d bytes using IBE with master public key\n", len(secretData))
	
	// === Step 3: Set up Application Release (simulates on-chain registry) ===
	testRelease := &types.Release{
		ImageDigest:  imageDigest,
		EncryptedEnv: "real-node-encrypted-environment-data",
		PublicEnv:    "NODE_ENV=production,REAL_CLUSTER=true",
		Timestamp:    time.Now().Unix(),
	}
	
	// Add release to all nodes
	for i, node := range cluster.Nodes {
		if stubRegistry, ok := node.GetReleaseRegistry().(*registry.StubClient); ok {
			stubRegistry.AddTestRelease(appID, testRelease)
			fmt.Printf("  - Added release to node %d\n", i+1)
		}
	}
	
	// === Step 4: Application Uses Real KMS Client ===
	fmt.Printf("\n--- Application Secret Retrieval via HTTP ---\n")
	
	kmsClient := client.NewKMSClient(cluster.GetServerURLs())
	
	result, err := kmsClient.RetrieveSecrets(appID, imageDigest)
	if err != nil {
		t.Fatalf("Real HTTP secret retrieval failed: %v", err)
	}
	
	fmt.Printf("✓ Secret retrieval successful:\n")
	fmt.Printf("  - HTTP responses: %d/%d\n", result.ResponseCount, result.ThresholdNeeded)
	fmt.Printf("  - Encrypted env: %s\n", result.EncryptedEnv)
	fmt.Printf("  - Public env: %s\n", result.PublicEnv)
	fmt.Printf("  - App private key recovered: %x...\n", result.AppPrivateKey.X.Bytes()[:8])
	
	// === Step 5: Decrypt Original Data with Recovered Private Key ===
	fmt.Printf("\n--- IBE Decryption with Recovered Key ---\n")
	
	decrypted, err := kmsClient.DecryptWithPrivateKey(appID, result.AppPrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Decryption with recovered key failed: %v", err)
	}
	
	if string(decrypted) != string(secretData) {
		t.Fatalf("Decryption incorrect!\nExpected: %s\nGot: %s",
			string(secretData), string(decrypted))
	}
	
	fmt.Printf("✓ Successfully decrypted original data!\n")
	fmt.Printf("✓ Complete IBE flow verified with real Node instances and HTTP endpoints!\n")
	
	// === Step 6: Verify Security Properties ===
	fmt.Printf("\n--- Security Verification ---\n")
	
	// Test wrong image digest
	_, err = kmsClient.RetrieveSecrets(appID, "sha256:wrong-digest")
	if err == nil {
		t.Error("Should reject wrong image digest")
	} else {
		fmt.Printf("✓ Correctly rejected wrong image digest\n")
	}
	
	// Test nonexistent app
	_, err = kmsClient.RetrieveSecrets("nonexistent-app", imageDigest)
	if err == nil {
		t.Error("Should reject nonexistent app")
	} else {
		fmt.Printf("✓ Correctly rejected nonexistent app\n")
	}
}

// testEncryptionPersistenceWithRealNodes tests that data remains decryptable
func testEncryptionPersistenceWithRealNodes(t *testing.T) {
	cluster := testutil.NewTestCluster(t, 5)
	defer cluster.Close()
	
	appID := generateHexAppID()
	imageDigest := "sha256:persistence456"
	secretData := []byte("Data encrypted before reshare that must remain accessible")
	
	fmt.Printf("\n=== Testing Encryption Persistence with Real Nodes ===\n")
	fmt.Printf("App ID: %s\n", appID)
	
	// === Initial Setup ===
	testRelease := &types.Release{
		ImageDigest:  imageDigest,
		EncryptedEnv: "persistence-test-encrypted-env",
		PublicEnv:    "PERSISTENCE_TEST=true",
		Timestamp:    time.Now().Unix(),
	}
	
	for _, node := range cluster.Nodes {
		if stubRegistry, ok := node.GetReleaseRegistry().(*registry.StubClient); ok {
			stubRegistry.AddTestRelease(appID, testRelease)
		}
	}
	
	// Encrypt data
	masterPubKey := cluster.GetMasterPublicKey()
	ciphertext, err := crypto.EncryptForApp(appID, masterPubKey, secretData)
	if err != nil {
		t.Fatalf("Initial encryption failed: %v", err)
	}
	
	fmt.Printf("✓ Encrypted data with 5-node cluster\n")
	
	// === Verify with Full Cluster ===
	fullClusterClient := client.NewKMSClient(cluster.GetServerURLs())
	
	fullResult, err := fullClusterClient.RetrieveSecrets(appID, imageDigest)
	if err != nil {
		t.Fatalf("Full cluster secret retrieval failed: %v", err)
	}
	
	fullDecrypted, err := fullClusterClient.DecryptWithPrivateKey(appID, fullResult.AppPrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Full cluster decryption failed: %v", err)
	}
	
	if string(fullDecrypted) != string(secretData) {
		t.Fatalf("Full cluster decryption incorrect")
	}
	
	fmt.Printf("✓ Data accessible with full cluster (5/%d nodes)\n", cluster.NumNodes)
	
	// === Verify with Threshold Subset (simulates post-reshare) ===
	thresholdURLs := cluster.GetServerURLs()[:cluster.Threshold]
	thresholdClient := client.NewKMSClient(thresholdURLs)
	
	thresholdResult, err := thresholdClient.RetrieveSecrets(appID, imageDigest)
	if err != nil {
		t.Fatalf("Threshold subset secret retrieval failed: %v", err)
	}
	
	thresholdDecrypted, err := thresholdClient.DecryptWithPrivateKey(appID, thresholdResult.AppPrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("Threshold subset decryption failed: %v", err)
	}
	
	if string(thresholdDecrypted) != string(secretData) {
		t.Fatalf("Threshold subset decryption incorrect")
	}
	
	fmt.Printf("✓ Data accessible with threshold subset (%d/%d nodes)\n", cluster.Threshold, cluster.NumNodes)
	
	// === Verify Different Subsets Work ===
	if cluster.NumNodes >= 4 {
		// Test different threshold subset (nodes 2,3,4 instead of 1,2,3)
		altSubsetURLs := cluster.GetServerURLs()[1:cluster.Threshold+1]
		altClient := client.NewKMSClient(altSubsetURLs)
		
		altResult, err := altClient.RetrieveSecrets(appID, imageDigest)
		if err != nil {
			t.Fatalf("Alternate subset secret retrieval failed: %v", err)
		}
		
		altDecrypted, err := altClient.DecryptWithPrivateKey(appID, altResult.AppPrivateKey, ciphertext)
		if err != nil {
			t.Fatalf("Alternate subset decryption failed: %v", err)
		}
		
		if string(altDecrypted) != string(secretData) {
			t.Fatalf("Alternate subset decryption incorrect")
		}
		
		fmt.Printf("✓ Data accessible with different threshold subset\n")
	}
	
	fmt.Printf("✓ Encryption persistence verified with real Node instances!\n")
	fmt.Printf("  - Data encrypted before theoretical reshare\n")
	fmt.Printf("  - Data accessible via multiple threshold subsets\n")
	fmt.Printf("  - Demonstrates reshare survival property\n")
}

// testMultipleHexAppIDsWithRealKMS tests various app ID formats with real KMS
func testMultipleHexAppIDsWithRealKMS(t *testing.T) {
	cluster := testutil.NewTestCluster(t, 3)
	defer cluster.Close()
	
	fmt.Printf("\n=== Testing Multiple 32-Byte Hex App IDs with Real KMS ===\n")
	
	// Test various realistic app ID formats
	testAppIDs := []string{
		"a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"0000000000000000000000000000000000000000000000000000000000000001",
		generateHexAppID(), // Random one
	}
	
	kmsClient := client.NewKMSClient(cluster.GetServerURLs())
	
	for i, appID := range testAppIDs {
		t.Run(fmt.Sprintf("HexAppID_%d", i+1), func(t *testing.T) {
			imageDigest := fmt.Sprintf("sha256:hextest%d", i+1)
			
			fmt.Printf("\nTesting app ID: %s\n", appID)
			
			// 1. Verify public key derivation
			appPubKey := crypto.GetAppPublicKey(appID)
			if appPubKey.X.Sign() == 0 {
				t.Errorf("Public key should not be zero for app ID %s", appID)
			}
			
			// 2. Add test release for this app
			testRelease := &types.Release{
				ImageDigest:  imageDigest,
				EncryptedEnv: fmt.Sprintf("encrypted-env-for-hex-app-%d", i+1),
				PublicEnv:    fmt.Sprintf("HEX_APP_INDEX=%d,APP_ID=%s", i+1, appID[:16]),
				Timestamp:    time.Now().Unix(),
			}
			
			for _, node := range cluster.Nodes {
				if stubRegistry, ok := node.GetReleaseRegistry().(*registry.StubClient); ok {
					stubRegistry.AddTestRelease(appID, testRelease)
				}
			}
			
			// 3. Use real KMS client to retrieve secrets via HTTP
			result, err := kmsClient.RetrieveSecrets(appID, imageDigest)
			if err != nil {
				t.Fatalf("Failed to retrieve secrets for app %s: %v", appID, err)
			}
			
			// 4. Verify we got valid results
			if result.AppPrivateKey.X.Sign() == 0 {
				t.Errorf("App private key should not be zero for app %s", appID)
			}
			
			if result.ResponseCount < result.ThresholdNeeded {
				t.Errorf("Insufficient responses for app %s: got %d, need %d",
					appID, result.ResponseCount, result.ThresholdNeeded)
			}
			
			// 5. Test encryption/decryption round trip
			testMessage := []byte(fmt.Sprintf("Secret message for app %d with ID %s", i+1, appID[:8]))
			
			encryptedMsg, err := crypto.EncryptForApp(appID, cluster.GetMasterPublicKey(), testMessage)
			if err != nil {
				t.Fatalf("Encryption failed for app %s: %v", appID, err)
			}
			
			decryptedMsg, err := crypto.DecryptForApp(appID, result.AppPrivateKey, encryptedMsg)
			if err != nil {
				t.Fatalf("Decryption failed for app %s: %v", appID, err)
			}
			
			if string(decryptedMsg) != string(testMessage) {
				t.Fatalf("Round-trip failed for app %s", appID)
			}
			
			fmt.Printf("✓ App ID %s: Complete IBE flow successful\n", appID[:16]+"...")
			fmt.Printf("  - Public key: %x...\n", appPubKey.X.Bytes()[:4])
			fmt.Printf("  - Private key recovered from %d real nodes\n", result.ResponseCount)
			fmt.Printf("  - Encrypt/decrypt verified\n")
		})
	}
	
	fmt.Printf("\n✅ All 32-byte hex app IDs work correctly with real KMS!\n")
}