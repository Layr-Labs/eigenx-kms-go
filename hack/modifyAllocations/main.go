package main

import (
	"context"
	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/web3signer"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transactionSigner"
	"github.com/ethereum/go-ethereum/common"
	"os"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	rpcUrl := os.Getenv(config.EnvKMSRPCURL)
	if rpcUrl == "" {
		l.Sugar().Fatalf("Environment variable %s is not set", config.EnvKMSRPCURL)
	}

	const (
		fromAddress = ""
		publicKey   = ""
	)

	cfg := &config.RemoteSignerConfig{
		Url:         "http://localhost:9000",
		FromAddress: fromAddress,
		PublicKey:   publicKey,
	}

	web3SignerClient, err := web3signer.NewWeb3SignerClientFromRemoteSignerConfig(cfg, l)
	if err != nil {
		l.Sugar().Fatalf("Failed to create Web3Signer client: %v", err)
	}

	ethereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl: rpcUrl,
	}, l)

	ethClient, err := ethereumClient.GetEthereumContractCaller()
	if err != nil {
		l.Sugar().Fatalf("Failed to get Ethereum contract caller: %v", err)
	}

	web3SignerTx, err := transactionSigner.NewWeb3TransactionSigner(web3SignerClient, common.HexToAddress(fromAddress), ethClient, l)
	if err != nil {
		l.Sugar().Fatalf("Failed to create Web3Signer: %v", err)
	}
	_ = web3SignerTx

	cc, err := caller.NewContractCaller(ethClient, web3SignerTx, l)
	if err != nil {
		l.Sugar().Fatalf("Failed to create contract caller: %v", err)
	}

	operatorAddress := common.HexToAddress("")
	avsAddress := common.HexToAddress("")
	strategyAddress := common.HexToAddress("")

	_, err = cc.ModifyAllocations(ctx,
		operatorAddress,
		avsAddress,
		0,
		strategyAddress,
		5e17,
	)
	if err != nil {
		l.Sugar().Fatalf("Failed to modify allocation: %v", err)
	}
	_, err = cc.ModifyAllocations(ctx,
		common.HexToAddress("0x7c3522f9d3f4d1e0f24a133899945caa9be7c405"),
		common.HexToAddress("0x1896C8B9e1AbAD2eC40C51f30E2876dfe2FFC4e0"),
		1,
		common.HexToAddress("0x8E93249a6C37a32024756aaBd813E6139b17D1d5"),
		5e17,
	)
	if err != nil {
		l.Sugar().Fatalf("Failed to modify allocation: %v", err)
	}

}
