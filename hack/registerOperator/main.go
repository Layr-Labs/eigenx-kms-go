package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/eigenx-kms-go/internal/aws"
	"github.com/Layr-Labs/eigenx-kms-go/internal/keyGenerator/awsKms"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/web3signer"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transactionSigner"
	"github.com/ethereum/go-ethereum/common"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func main() {
	app := &cli.App{
		Name:  "registerOperator",
		Usage: "Register an operator with the EigenKMS AVS using AWS KMS for signing",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "rpc-url",
				Usage:    "Ethereum RPC URL",
				EnvVars:  []string{"RPC_URL"},
				Value:    "http://localhost:8545",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "operator-address",
				Usage:    "Operator Ethereum address",
				EnvVars:  []string{"OPERATOR_ADDRESS"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "kms-key-id",
				Usage:    "AWS KMS key ID for signing",
				EnvVars:  []string{"KMS_KEY_ID"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "avs-address",
				Usage:    "AVS contract address",
				EnvVars:  []string{"AVS_ADDRESS"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "operator-public-key",
				Usage:    "Operator public key (hex string)",
				EnvVars:  []string{"OPERATOR_PUBLIC_KEY"},
				Required: true,
			},
			&cli.Uint64Flag{
				Name:     "operator-set-id",
				Usage:    "Operator set ID to join",
				EnvVars:  []string{"OPERATOR_SET_ID"},
				Value:    0,
				Required: false,
			},
			&cli.StringFlag{
				Name:     "socket",
				Usage:    "Socket address for P2P communication",
				EnvVars:  []string{"SOCKET"},
				Value:    "http://localhost:1111",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "metadata-uri",
				Usage:    "Operator metadata URI",
				EnvVars:  []string{"METADATA_URI"},
				Value:    "",
				Required: false,
			},
			&cli.Uint64Flag{
				Name:     "allocation-delay",
				Usage:    "Allocation delay for the operator",
				EnvVars:  []string{"ALLOCATION_DELAY"},
				Value:    0,
				Required: false,
			},
			&cli.StringFlag{
				Name:     "web3signer-url",
				Usage:    "Web3Signer URL for transaction signing",
				EnvVars:  []string{"WEB3SIGNER_URL"},
				Value:    "http://localhost:9000",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "aws-region",
				Usage:    "AWS region for KMS",
				EnvVars:  []string{"AWS_REGION"},
				Value:    "us-east-1",
				Required: false,
			},
			&cli.StringFlag{
				Name:    "chain-name",
				Usage:   "Chain name for configuration",
				EnvVars: []string{"CHAIN_NAME"},
				Value:   "preprod-sepolia",
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Usage:   "Enable verbose logging",
				EnvVars: []string{"VERBOSE"},
			},
		},
		Action: runRegisterOperator,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

func runRegisterOperator(c *cli.Context) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l, err := logger.NewLogger(&logger.LoggerConfig{Debug: c.Bool("verbose")})
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	// Parse inputs
	rpcUrl := c.String("rpc-url")
	operatorAddress := common.HexToAddress(c.String("operator-address"))
	kmsKeyId := c.String("kms-key-id")
	avsAddress := common.HexToAddress(c.String("avs-address"))
	operatorPublicKey := c.String("operator-public-key")
	operatorSetIds := []uint32{uint32(c.Uint64("operator-set-id"))}
	socket := c.String("socket")
	metadataUri := c.String("metadata-uri")
	allocationDelay := uint32(c.Uint64("allocation-delay"))
	web3signerUrl := c.String("web3signer-url")
	awsRegion := c.String("aws-region")
	chainName := c.String("chain-name")

	// Load AWS config
	awsCfg, err := aws.LoadAWSConfig(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	keygenConfig := &config.KMSServerConfig{
		ChainName: config.ChainName(chainName),
	}

	keyGen := awsKms.NewAWSKMSKeyGenerator(awsCfg, awsRegion, keygenConfig, l)

	cfg := &config.RemoteSignerConfig{
		Url:         web3signerUrl,
		FromAddress: operatorAddress.String(),
		PublicKey:   operatorPublicKey,
	}

	web3SignerClient, err := web3signer.NewWeb3SignerClientFromRemoteSignerConfig(cfg, l)
	if err != nil {
		return fmt.Errorf("failed to create Web3Signer client: %w", err)
	}

	ethereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl: rpcUrl,
	}, l)

	ethClient, err := ethereumClient.GetEthereumContractCaller()
	if err != nil {
		return fmt.Errorf("failed to get Ethereum contract caller: %w", err)
	}

	web3SignerTx, err := transactionSigner.NewWeb3TransactionSigner(web3SignerClient, operatorAddress, ethClient, l)
	if err != nil {
		return fmt.Errorf("failed to create Web3Signer transaction signer: %w", err)
	}

	cc, err := caller.NewContractCaller(ethClient, web3SignerTx, l)
	if err != nil {
		return fmt.Errorf("failed to create contract caller: %w", err)
	}

	// Registration
	l.Sugar().Infow("Registering operator to AVS operator sets",
		zap.String("avsAddress", avsAddress.String()),
		zap.String("operatorAddress", operatorAddress.String()),
		zap.Uint32s("operatorSetIds", operatorSetIds),
		zap.String("curve", config.CurveTypeECDSA.String()),
	)

	messageHash, err := cc.GetOperatorECDSAKeyRegistrationMessageHash(ctx, operatorAddress, avsAddress, operatorSetIds[0], operatorAddress)
	if err != nil {
		return fmt.Errorf("failed to get operator registration message hash: %w", err)
	}

	sigBytes, err := keyGen.SignMessage(ctx, kmsKeyId, messageHash[:])
	if err != nil {
		return fmt.Errorf("failed to sign operator registration message: %w", err)
	}

	_, err = cc.CreateOperator(ctx, operatorAddress, allocationDelay, metadataUri)
	if err != nil {
		return fmt.Errorf("failed to create operator: %w", err)
	}
	l.Sugar().Infow("Successfully created operator",
		zap.String("operatorAddress", operatorAddress.String()),
	)

	_, err = cc.RegisterKeyWithOperatorSet(
		ctx,
		operatorAddress,
		avsAddress,
		operatorSetIds[0],
		operatorAddress.Bytes(),
		sigBytes,
	)
	if err != nil {
		return fmt.Errorf("failed to register ECDSA key for operator AVS operator set: %w", err)
	}
	l.Sugar().Infow("Successfully registered ECDSA key for operator AVS operator set",
		zap.String("avsAddress", avsAddress.String()),
		zap.String("operatorAddress", operatorAddress.String()),
		zap.Uint32("operatorSetId", operatorSetIds[0]),
	)

	_, err = cc.RegisterOperatorWithAvs(
		ctx,
		operatorAddress,
		avsAddress,
		operatorSetIds,
		socket,
	)
	if err != nil {
		return fmt.Errorf("failed to register with AVS: %w", err)
	}
	l.Sugar().Infow("Created operator and registered with AVS operator sets",
		zap.String("avsAddress", avsAddress.String()),
		zap.String("operatorAddress", operatorAddress.String()),
		zap.Uint32s("operatorSetIds", operatorSetIds),
	)

	return nil
}
