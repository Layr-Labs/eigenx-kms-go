package integration

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/testutil"
)

// Test_Decrypt_AfterReshare guards the production-critical path that no other
// test covered: encrypt under the genesis master key, trigger one or more
// reshares, then decrypt. Decryption recovers the app private key from threshold
// partial signatures produced by the *resharded* key shares. If a reshare leaves
// the shares inconsistent with the (preserved) master public key, decryption
// fails with "failed to recover valid app private key: all combinations
// exhausted" — exactly the failure observed on the long-running preprod cluster,
// which existing tests missed because they only:
//   - decrypt on genesis shares (Test_IBEIntegration), or
//   - assert the master *public* key is unchanged after reshare (reshare tests),
//
// but never decrypt *after* a reshare.
func Test_Decrypt_AfterReshare(t *testing.T) {
	cluster := testutil.NewTestCluster(t, 3)
	defer cluster.Close()

	clientLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	operatorAddresses := make([]common.Address, 0, len(cluster.Nodes))
	for _, n := range cluster.Nodes {
		operatorAddresses = append(operatorAddresses, n.GetOperatorAddress())
	}
	client, err := kmsClient.NewClient(&kmsClient.ClientConfig{
		AVSAddress:    "0x0000000000000000000000000000000000000000",
		OperatorSetID: 0,
		Logger:        clientLogger,
		ContractCaller: &mockContractCaller{
			serverURLs:        cluster.GetServerURLs(),
			operatorAddresses: operatorAddresses,
		},
	})
	require.NoError(t, err)

	appID := "reshare-decrypt-app"
	plaintext := []byte("secret that must survive a reshare")

	operators, err := client.GetOperators()
	require.NoError(t, err)

	// Encrypt under the genesis master public key.
	ciphertext, err := client.Encrypt(appID, plaintext, operators)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	// Sanity: it decrypts BEFORE any reshare (genesis shares).
	pre, err := client.Decrypt(appID, ciphertext, operators, 0)
	require.NoError(t, err, "decrypt should work on genesis shares")
	require.Equal(t, plaintext, pre)

	// Trigger reshares and decrypt after each. Two rounds catches both the
	// first rotation and a subsequent one (cumulative share drift).
	for round := 1; round <= 2; round++ {
		versions := make(map[int]int64, len(cluster.Nodes))
		for i, n := range cluster.Nodes {
			av := n.GetKeyStore().GetActiveVersion()
			require.NotNilf(t, av, "node %d missing active version before reshare round %d", i, round)
			versions[i] = av.Version
		}

		require.Truef(t, testutil.WaitForReshare(cluster, versions, 45*time.Second),
			"reshare round %d did not occur within timeout", round)

		// The master public key must be preserved across reshare — encryption
		// used it, so decryption must still resolve to a matching private key.
		decrypted, err := client.Decrypt(appID, ciphertext, operators, 0)
		require.NoErrorf(t, err, "decrypt failed after reshare round %d (share/masterkey inconsistency)", round)
		require.Equalf(t, plaintext, decrypted, "plaintext mismatch after reshare round %d", round)
		t.Logf("✓ decrypt succeeded after reshare round %d", round)
	}
}
