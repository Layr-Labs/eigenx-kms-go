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
		fromAddress = "0x7BAf9d6D4b347ae8f9a4826315d904DE9e4b8FD6"
		publicKey   = "0xb6b4d44a178b5a33e5dbb3e60fc415f14e81555e47f7a73d0945a34f81bdeda71deee7f71e20944d3fbf7e15b5b3487fbaa68f479d14694ff3333a1bdf239533"
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

	signer, err := transactionSigner.NewPrivateKeySigner("<key>", ethClient, l)
	if err != nil {
		l.Sugar().Fatalf("failed to create transaction signer: %v", err)
	}
	web3SignerTx, err := transactionSigner.NewWeb3TransactionSigner(web3SignerClient, common.HexToAddress(fromAddress), ethClient, l)
	if err != nil {
		l.Sugar().Fatalf("Failed to create Web3Signer: %v", err)
	}
	_ = web3SignerTx

	cc, err := caller.NewContractCaller(ethClient, signer, l)
	if err != nil {
		l.Sugar().Fatalf("Failed to create contract caller: %v", err)
	}

	_, err = cc.UpdateOperatorSocketForAvs(
		ctx,
		common.HexToAddress("0x7c3522f9d3f4d1e0f24a133899945caa9be7c405"),
		common.HexToAddress("0x1896C8B9e1AbAD2eC40C51f30E2876dfe2FFC4e0"),
		"executor:9000",
	)
	if err != nil {
		l.Sugar().Fatalf("Failed to update operator socket for AVS: %v", err)
	}

}
