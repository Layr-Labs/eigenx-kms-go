package main

import (
	"context"
	"fmt"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	"github.com/Layr-Labs/eigenx-kms-go/internal/aws"
	"github.com/Layr-Labs/eigenx-kms-go/internal/keyGenerator/awsKms"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/web3signer"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transactionSigner"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func main() {
	l, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	awsCfg, err := aws.LoadAWSConfig(context.Background(), "")
	if err != nil {
		panic(err)
	}

	cfg := &config.KMSServerConfig{
		ChainName: "sepolia",
	}

	rootPath := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(rootPath)
	if err != nil {
		l.Sugar().Fatalf("failed to read chain config: %v", err)
	}
	_ = chainConfig

	keyGen := awsKms.NewAWSKMSKeyGenerator(awsCfg, "us-east-1", cfg, l)

	ethereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		// BaseUrl: "https://practical-serene-mound.ethereum-sepolia.quiknode.pro/3aaa48bd95f3d6aed60e89a1a466ed1e2a440b61/",
		BaseUrl: "http://localhost:8545",
	}, l)

	ethClient, err := ethereumClient.GetEthereumContractCaller()
	if err != nil {
		l.Sugar().Fatalf("failed to get Ethereum contract caller: %v", err)
	}

	web3SignerClient, err := web3signer.NewWeb3SignerClientFromRemoteSignerConfig(&config.RemoteSignerConfig{
		Url:         "http://localhost:9000",
		FromAddress: "0x7BAf9d6D4b347ae8f9a4826315d904DE9e4b8FD6",
		PublicKey:   "0xb6b4d44a178b5a33e5dbb3e60fc415f14e81555e47f7a73d0945a34f81bdeda71deee7f71e20944d3fbf7e15b5b3487fbaa68f479d14694ff3333a1bdf239533",
	}, l)
	if err != nil {
		l.Sugar().Fatalw("failed to create Web3Signer client", "error", err)
	}

	web3SignerTx, err := transactionSigner.NewWeb3TransactionSigner(web3SignerClient, common.HexToAddress("0x7BAf9d6D4b347ae8f9a4826315d904DE9e4b8FD6"), ethClient, l)
	if err != nil {
		l.Sugar().Fatalf("Failed to create Web3Signer: %v", err)
	}

	// signer, err := transactionSigner.NewPrivateKeySigner("<key>", ethClient, l)
	// if err != nil {
	// 	l.Sugar().Fatalf("failed to create transaction signer: %v", err)
	// }

	cc, err := caller.NewContractCaller(ethClient, web3SignerTx, l)
	if err != nil {
		l.Sugar().Fatalf("failed to create contract caller: %v", err)
	}

	generatedKey, err := keyGen.GetECDSAKeyById(context.Background(), "726ee168-0094-4b4e-ac73-bf6453e4c239")
	if err != nil {
		l.Sugar().Fatalw("failed to generate ECDSA key", "error", err)
	}

	pubKeyHex, err := generatedKey.GetPublicKeyHex()
	if err != nil {
		l.Sugar().Fatalw("failed to get public key hex", "error", err)
	}
	l.Sugar().Infow("Generated Key",
		"keyId", generatedKey.KeyId,
		"publicKeyHex", pubKeyHex,
		"address", generatedKey.Address,
	)

	messageHash, err := cc.GetOperatorECDSAKeyRegistrationMessageHash(
		context.Background(),
		common.HexToAddress("0x7c3522F9d3f4D1e0F24A133899945CAa9be7c405"),
		common.HexToAddress("0x1896C8B9e1AbAD2eC40C51f30E2876dfe2FFC4e0"),
		1,
		common.HexToAddress("0x8256A5EC1EC823E1cD1C20C0f2D6C09D95144D55"),
	)
	if err != nil {
		l.Sugar().Fatalw("failed to get operator ECDSA key registration message hash", "error", err)
	}

	fmt.Printf("\nMessage hash: %+v\n", hexutil.Encode(messageHash[:]))
	sigBytes, err := keyGen.SignMessage(context.Background(), generatedKey.KeyId, messageHash[:])
	if err != nil {
		l.Sugar().Fatalw("failed to sign message", "error", err)
	}

	sig, err := ecdsa.NewSignatureFromBytes(sigBytes)
	if err != nil {
		l.Sugar().Fatalw("failed to create signature from bytes", "error", err)
	}
	valid, err := sig.VerifyWithAddress(messageHash[:], common.HexToAddress(generatedKey.Address))
	if err != nil {
		l.Sugar().Fatalw("failed to verify signature", "error", err)
	}
	l.Sugar().Infow("Is valid?", "valid", valid)

	_, err = cc.RegisterKeyWithOperatorSet(
		context.Background(),
		common.HexToAddress("0x7c3522F9d3f4D1e0F24A133899945CAa9be7c405"),
		common.HexToAddress("0x1896C8B9e1AbAD2eC40C51f30E2876dfe2FFC4e0"),
		1,
		common.HexToAddress("0x8256A5EC1EC823E1cD1C20C0f2D6C09D95144D55").Bytes(),
		sigBytes,
	)
	if err != nil {
		l.Sugar().Fatalw("failed to register key with operator set", "error", err)
	}
	l.Sugar().Infow("Successfully registered key with operator set")
}
