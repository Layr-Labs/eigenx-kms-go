package integration

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/kmsclient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
)

func Test_IBEIntegration(t *testing.T) {
	// Create cluster and wait for automatic DKG
	cluster := testutil.NewTestCluster(t, 3)
	defer cluster.Close()

	// Create logger for client
	clientLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	// Create mock ContractCaller that returns test cluster operators
	mockContractCaller := &mockContractCaller{
		serverURLs: cluster.GetServerURLs(),
	}

	// Create KMS client with mock contract caller for testing
	client, err := kmsclient.NewClient(&kmsclient.ClientConfig{
		AVSAddress:     "0x0000000000000000000000000000000000000000", // Mock address for test
		OperatorSetID:  0,
		Logger:         clientLogger,
		ContractCaller: mockContractCaller,
	})
	require.NoError(t, err)

	// Test Identity-Based Encryption for an application
	appID := "test-app-ibe"
	plaintext := []byte("secret application configuration data")

	t.Logf("Testing IBE encryption/decryption for app: %s", appID)

	// Step 1: Get operators and master public key (via /pubkey endpoint)
	operators, err := client.GetOperators()
	require.NoError(t, err, "Failed to get operators")

	masterPubKey, err := client.GetMasterPublicKey(operators)
	require.NoError(t, err, "Failed to get master public key")

	isZero, err := masterPubKey.IsZero()
	require.NoError(t, err, "Failed to check if master public key is zero")
	require.False(t, isZero, "Master public key should not be zero")

	t.Logf("  ✓ Retrieved master public key from operators via HTTP")

	// Step 2: Encrypt data using IBE
	ciphertext, err := client.Encrypt(appID, plaintext, operators)
	require.NoError(t, err, "Failed to encrypt data")

	require.NotEmpty(t, ciphertext, "Ciphertext should not be empty")

	t.Logf("  ✓ Encrypted %d bytes → %d bytes ciphertext", len(plaintext), len(ciphertext))

	// Step 3: Decrypt data (client collects partial signatures via /app/sign)
	decrypted, err := client.Decrypt(appID, ciphertext, operators, 0)
	require.NoError(t, err, "Failed to decrypt data")

	// Step 4: Verify decrypted data matches original
	require.Equal(t, string(plaintext), string(decrypted), "Decryption mismatch")

	t.Logf("✓ IBE integration test passed")
	t.Logf("  - Client queried /pubkey endpoints for master public key")
	t.Logf("  - Encrypted with IBE using master public key")
	t.Logf("  - Client queried /app/sign endpoints for partial signatures")
	t.Logf("  - Recovered app private key from threshold signatures")
	t.Logf("  - Successfully decrypted: %q", string(decrypted))
	t.Logf("  - Full client-to-operator flow working correctly")
}

// mockContractCaller provides a test implementation that returns mock operators
type mockContractCaller struct {
	serverURLs []string
}

func (m *mockContractCaller) GetOperatorSetMembersWithPeering(avsAddress string, operatorSetID uint32) (*peering.OperatorSetPeers, error) {
	var peers []*peering.OperatorSetPeer
	for i, url := range m.serverURLs {
		peers = append(peers, &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress(fmt.Sprintf("0x%040d", i+1)),
			SocketAddress:   url,
		})
	}
	return &peering.OperatorSetPeers{
		OperatorSetId: operatorSetID,
		AVSAddress:    common.HexToAddress(avsAddress),
		Peers:         peers,
	}, nil
}
