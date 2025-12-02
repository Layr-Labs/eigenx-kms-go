package transactionSigner

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/web3signer"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

const (
	TestL2RpcUrl = "http://127.0.0.1:9545"
)

// Test_Web3TransactionSigner_SendTransaction tests sending a simple transaction via web3signer
func Test_Web3TransactionSigner_SendTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create logger
	l, err := logger.NewLogger(&logger.LoggerConfig{
		Debug: true,
	})
	require.NoError(t, err)

	// Get project root and chain config
	root := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(root)
	require.NoError(t, err)

	t.Logf("Starting L2 Anvil for transaction test...")

	// Start L2 Anvil
	l2Anvil, err := tests.StartL2Anvil(root, ctx)
	require.NoError(t, err)
	defer func() {
		t.Log("Cleaning up L2 Anvil...")
		if err := tests.KillAnvil(l2Anvil); err != nil {
			t.Logf("Warning: failed to kill L2 Anvil: %v", err)
		}
	}()

	// Wait for L2 to be ready
	l2Client := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   TestL2RpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, l)

	time.Sleep(3 * time.Second) // Give anvil time to start

	// Verify anvil is running
	block, err := l2Client.GetLatestBlock(ctx)
	require.NoError(t, err)
	t.Logf("L2 Anvil is running, latest block: %v", block)

	l2EthClient, err := l2Client.GetEthereumContractCaller()
	require.NoError(t, err)

	// Create web3signer client for operator 1
	web3SignerClient, err := web3signer.NewWeb3SignerClientFromRemoteSignerConfig(
		&config.RemoteSignerConfig{
			Url:         tests.L2Web3SignerUrl,
			FromAddress: chainConfig.OperatorAccountAddress1,
			PublicKey:   chainConfig.OperatorAccountPublicKey1,
		},
		l,
	)
	require.NoError(t, err)

	// Create transaction signer
	fromAddress := common.HexToAddress(chainConfig.OperatorAccountAddress1)
	txSigner, err := NewWeb3TransactionSigner(web3SignerClient, fromAddress, l2EthClient, l)
	require.NoError(t, err)

	t.Logf("Created Web3TransactionSigner for address: %s", fromAddress.Hex())

	// Check initial balance
	balance, err := l2EthClient.BalanceAt(ctx, fromAddress, nil)
	require.NoError(t, err)
	t.Logf("Initial balance: %s", balance.String())

	// Create a simple transaction - send 1 wei to operator 2
	// This is a simple ETH transfer that should always succeed
	toAddress := common.HexToAddress(chainConfig.OperatorAccountAddress2)

	// Get initial nonce
	nonce, err := l2EthClient.PendingNonceAt(ctx, fromAddress)
	require.NoError(t, err)
	t.Logf("Initial nonce: %d", nonce)

	// Create a simple transaction with minimal data
	tx := types.NewTransaction(
		nonce,
		toAddress,
		big.NewInt(1), // 1 wei
		21000,         // gas limit (will be re-estimated)
		big.NewInt(0), // gas price (will be set by signer)
		[]byte{},      // empty data
	)

	t.Logf("Sending transaction to %s (1 wei)...", toAddress.Hex())

	// Sign and send the transaction
	receipt, err := txSigner.SignAndSendTransaction(ctx, tx)
	require.NoError(t, err)
	require.NotNil(t, receipt)

	t.Logf("✓ Transaction mined successfully!")
	t.Logf("  TxHash: %s", receipt.TxHash.Hex())
	t.Logf("  Block: %d", receipt.BlockNumber.Uint64())
	t.Logf("  Gas Used: %d", receipt.GasUsed)
	t.Logf("  Status: %d", receipt.Status)

	require.Equal(t, uint64(1), receipt.Status, "Transaction should succeed")

	// Verify nonce increased
	newNonce, err := l2EthClient.PendingNonceAt(ctx, fromAddress)
	require.NoError(t, err)
	t.Logf("New nonce: %d", newNonce)
	require.Equal(t, nonce+1, newNonce, "Nonce should have increased by 1")

	t.Log("✅ Test passed!")
}
