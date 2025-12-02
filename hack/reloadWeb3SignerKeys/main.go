package main

import (
	"context"

	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/web3signer"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
)

func main() {
	l, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	rootPath := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(rootPath)
	if err != nil {
		l.Sugar().Fatalf("failed to read chain config: %v", err)
	}
	_ = chainConfig

	//keyGen := awsKms.NewAWSKMSKeyGenerator(awsCfg, "us-east-1", cfg, l)
	//
	//ethereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
	//	// BaseUrl: "https://practical-serene-mound.ethereum-sepolia.quiknode.pro/3aaa48bd95f3d6aed60e89a1a466ed1e2a440b61/",
	//	BaseUrl: "http://localhost:8545",
	//}, l)
	//
	//ethClient, err := ethereumClient.GetEthereumContractCaller()
	//if err != nil {
	//	l.Sugar().Fatalf("failed to get Ethereum contract caller: %v", err)
	//}

	signerCfg := &config.RemoteSignerConfig{
		Url:         "http://localhost:9000",
		FromAddress: "0x144c70563952f6f60E3ee94608d70352D7b8b99c",
		PublicKey:   "0x5a3c1497b80dac15e83684b10afcbf14c0de553ee0e6baddad881c9b772da20fc758fe89d5be1ed907179d1770bbf91b5d1972ba6faab75c8ffe2133bff836f8",
	}

	web3SignerClient, err := web3signer.NewWeb3SignerClientFromRemoteSignerConfig(signerCfg, l)
	if err != nil {
		l.Sugar().Fatalw("failed to create Web3Signer client", "error", err)
	}

	if err := web3SignerClient.ReloadKeysAndWaitForPublicKey(context.Background(), signerCfg.PublicKey); err != nil {
		l.Sugar().Fatalw("failed to reload Web3Signer keys", "error", err)
	}
	l.Sugar().Info("Successfully reloaded Web3Signer keys")

}
