package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	chainPoller "github.com/Layr-Labs/chain-indexer/pkg/chainPollers"
	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/blockHandler"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering/peeringDataFetcher"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/inMemoryTransportSigner"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

const (
	L1RpcUrl = "http://127.0.0.1:8545"
)

//nolint:unused // Used in skipped test, will be needed when test is re-enabled
func createNode(
	operatorAddress string,
	privateKeyHexString string,
	avsAddress string,
	chainID config.ChainId,
	port int,
	cc contractCaller.IContractCaller,
	bh blockHandler.IBlockHandler,
	cp chainPoller.IChainPoller,
	l *zap.Logger,
) *node.Node {
	pdf := peeringDataFetcher.NewPeeringDataFetcher(cc, l)
	pkBytes, err := hexutil.Decode(privateKeyHexString)
	if err != nil {
		l.Sugar().Fatalf("failed to decode private key: %v", err)
	}
	imts, err := inMemoryTransportSigner.NewBn254InMemoryTransportSigner(pkBytes, l)
	if err != nil {
		l.Sugar().Fatalf("failed to create in-memory transport signer: %v", err)
	}

	return node.NewNode(node.Config{
		OperatorAddress: operatorAddress,
		Port:            port,
		BN254PrivateKey: privateKeyHexString,
		ChainID:         chainID,
		AVSAddress:      avsAddress,
		OperatorSetId:   0,
	}, pdf, bh, cp, imts, l)
}

func Test_OnChainIntegration(t *testing.T) {
	// TODO: Update this test to use MockChainPoller and BlockHandler
	// See pkg/testutil/test_cluster.go for reference implementation
	t.Skip()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l, err := logger.NewLogger(&logger.LoggerConfig{
		Debug: false,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	root := tests.GetProjectRootPath()
	t.Logf("Project root path: %s", root)

	chainConfig, err := tests.ReadChainConfig(root)
	if err != nil {
		t.Fatalf("Failed to read chain config: %v", err)
	}
	_ = chainConfig

	l1EthereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   L1RpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, l)

	ethClient, err := l1EthereumClient.GetEthereumContractCaller()
	if err != nil {
		l.Sugar().Fatalf("failed to get Ethereum contract caller: %v", err)
	}
	_ = ethClient

	// ------------------------------------------------------------------------
	// Setup anvil
	// ------------------------------------------------------------------------
	anvilWg := &sync.WaitGroup{}
	anvilWg.Add(1)
	startErrorsChan := make(chan error, 1)

	anvilCtx, anvilCancel := context.WithDeadline(ctx, time.Now().Add(30*time.Second))
	defer anvilCancel()

	_ = tests.KillallAnvils()

	t.Logf("Starting anvil with RPC URL: %s", L1RpcUrl)
	l1Anvil, err := tests.StartL1Anvil(root, ctx)
	if err != nil {
		t.Fatalf("Failed to start L1 Anvil: %v", err)
	}
	go tests.WaitForAnvil(anvilWg, anvilCtx, t, l1EthereumClient, startErrorsChan)

	anvilWg.Wait()
	close(startErrorsChan)
	for err := range startErrorsChan {
		if err != nil {
			t.Errorf("Failed to start Anvil: %v", err)
		}
	}
	anvilCancel()
	t.Logf("Anvil is running")

	hasErrors := false

	_, err = caller.NewContractCaller(ethClient, nil, l)
	if err != nil {
		t.Fatalf("Failed to create contract caller: %v", err)
	}
	// ------------------------------------------------------------------------
	// Create nodes
	// ------------------------------------------------------------------------
	// TODO: Update these calls to include chainID, blockHandler, and chainPoller
	// _ = createNode(chainConfig.OperatorAccountAddress1, chainConfig.OperatorAccountPrivateKey1, chainConfig.AVSAccountAddress, config.ChainId_EthereumAnvil, 7501, cc, bh, poller, l)
	// _ = createNode(chainConfig.OperatorAccountAddress2, chainConfig.OperatorAccountPrivateKey2, chainConfig.AVSAccountAddress, config.ChainId_EthereumAnvil, 7502, cc, bh, poller, l)
	// _ = createNode(chainConfig.OperatorAccountAddress3, chainConfig.OperatorAccountPrivateKey3, chainConfig.AVSAccountAddress, config.ChainId_EthereumAnvil, 7503, cc, bh, poller, l)

	// ------------------------------------------------------------------------
	// Wait and cleanup
	// ------------------------------------------------------------------------
	select {
	case <-time.After(240 * time.Second):
		cancel()
		t.Errorf("Test timed out after 240 seconds")
	case <-ctx.Done():
		t.Logf("Test completed")
	}

	assert.False(t, hasErrors)
	_ = tests.KillAnvil(l1Anvil)
}
