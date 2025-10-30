package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering/peeringDataFetcher"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

const (
	L1RpcUrl = "http://127.0.0.1:8545"
)

func createNode(
	operatorAddress string,
	privateKey string,
	avsAddress string,
	port int,
	cc contractCaller.IContractCaller,
	l *zap.Logger,
) *node.Node {
	pdf := peeringDataFetcher.NewPeeringDataFetcher(cc, l)

	return node.NewNode(node.Config{
		OperatorAddress: operatorAddress,
		Port:            port,
		BN254PrivateKey: privateKey,
		AVSAddress:      avsAddress,
		OperatorSetId:   0,
		Logger:          l,
	}, pdf)
}

func Test_OnChainIntegration(t *testing.T) {
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

	cc, err := caller.NewContractCaller(ethClient, nil, l)
	if err != nil {
		t.Fatalf("Failed to create contract caller: %v", err)
	}
	// ------------------------------------------------------------------------
	// Create nodes
	// ------------------------------------------------------------------------
	_ = createNode(chainConfig.OperatorAccountAddress1, chainConfig.OperatorAccountPrivateKey1, chainConfig.AVSAccountAddress, 7501, cc, l)
	_ = createNode(chainConfig.OperatorAccountAddress2, chainConfig.OperatorAccountPrivateKey2, chainConfig.AVSAccountAddress, 7502, cc, l)
	_ = createNode(chainConfig.OperatorAccountAddress3, chainConfig.OperatorAccountPrivateKey3, chainConfig.AVSAccountAddress, 7503, cc, l)

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
