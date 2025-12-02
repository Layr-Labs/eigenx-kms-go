package main

import (
	"context"
	"os"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/web3signer"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transactionSigner"
	"github.com/ethereum/go-ethereum/common"
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

	// signer, err := transactionSigner.NewPrivateKeySigner("<key>", ethClient, l)
	// if err != nil {
	//	l.Sugar().Fatalf("failed to create transaction signer: %v", err)
	//}

	web3SignerTx, err := transactionSigner.NewWeb3TransactionSigner(web3SignerClient, common.HexToAddress(fromAddress), ethClient, l)
	if err != nil {
		l.Sugar().Fatalf("Failed to create Web3Signer: %v", err)
	}

	cc, err := caller.NewContractCaller(ethClient, web3SignerTx, l)
	if err != nil {
		l.Sugar().Fatalf("Failed to create contract caller: %v", err)
	}

	_, err = cc.DeRegisterKey(
		ctx,
		common.HexToAddress(""), // operator address
		common.HexToAddress(""), // avs address
		0,
	)
	if err != nil {
		l.Sugar().Fatalf("Failed to update operator socket for AVS: %v", err)
	}

}
