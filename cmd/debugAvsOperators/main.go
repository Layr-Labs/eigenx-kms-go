package main

import (
	"fmt"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
)

const (
	rpcUrl = "http://localhost:8545"
)

func main() {
	l, err := logger.NewLogger(&logger.LoggerConfig{Debug: true})
	if err != nil {
		panic(err)
	}

	projectRoot := tests.GetProjectRootPath()

	chainConfig, err := tests.ReadChainConfig(projectRoot)
	if err != nil {
		l.Sugar().Fatalf("Failed to read chain config: %v", err)
	}
	fmt.Printf("Chain Config: %+v\n", chainConfig)

	l1EthereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   rpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, l)

	l1EthClient, err := l1EthereumClient.GetEthereumContractCaller()
	if err != nil {
		l.Sugar().Fatalf("Failed to get L1 Ethereum contract caller: %v", err)
	}

	cc, err := caller.NewContractCaller(l1EthClient, nil, l)
	if err != nil {
		l.Sugar().Fatalf("Failed to create contract caller: %v", err)
	}

	peers, err := cc.GetOperatorSetMembersWithPeering(chainConfig.AVSAccountAddress, 0)
	if err != nil {
		l.Sugar().Fatalf("Failed to get operator set members with peering: %v", err)
	}
	for _, peer := range peers.Peers {
		fmt.Printf("Operator Peer: %+v\n", peer)
	}
}
