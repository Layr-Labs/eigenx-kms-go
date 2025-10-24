package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	
	ethereum "github.com/Layr-Labs/eigenx-kms-go/pkg/clients"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering/peeringDataFetcher"
)

func main() {
	app := &cli.App{
		Name:  "kms-server",
		Usage: "EigenX KMS AVS Node Server",
		Description: `A distributed key management server that participates in threshold cryptography protocols.
		
This server implements:
- Distributed Key Generation (DKG) protocol  
- Automatic key resharing for operator set changes
- TEE application secret retrieval via HTTP endpoints
- Identity-Based Encryption (IBE) for application secrets`,
		Version: "1.0.0",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "operator-address",
				Aliases:  []string{"addr"},
				Usage:    "Ethereum address of the operator",
				EnvVars:  []string{"KMS_OPERATOR_ADDRESS"},
				Required: true,
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Value:   8000,
				Usage:   "HTTP server port",
				EnvVars: []string{"KMS_PORT"},
			},
			&cli.Uint64Flag{
				Name:     "chain-id",
				Aliases:  []string{"chain"},
				Usage:    fmt.Sprintf("Ethereum chain ID: %s", config.GetSupportedChainIDsString()),
				EnvVars:  []string{"KMS_CHAIN_ID"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "bn254-private-key",
				Aliases:  []string{"bn254"},
				Usage:    "BN254 private key (hex string) for threshold cryptography and P2P authentication",
				EnvVars:  []string{"KMS_BN254_PRIVATE_KEY"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "rpc-url",
				Aliases: []string{"rpc"},
				Usage:   "Ethereum RPC endpoint URL",
				Value:   "http://localhost:8545",
				EnvVars: []string{"KMS_RPC_URL"},
			},
			&cli.StringFlag{
				Name:     "avs-address",
				Aliases:  []string{"avs"},
				Usage:    "AVS contract address for operator discovery",
				EnvVars:  []string{"KMS_AVS_ADDRESS"},
				Required: true,
			},
			&cli.UintFlag{
				Name:    "operator-set-id",
				Aliases: []string{"set-id"},
				Usage:   "Operator set ID",
				Value:   0,
				EnvVars: []string{"KMS_OPERATOR_SET_ID"},
			},
			&cli.Int64Flag{
				Name:    "dkg-at",
				Usage:   "Unix timestamp to run DKG at (for coordinated testing). Use 0 for immediate execution.",
				EnvVars: []string{"KMS_DKG_AT"},
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Usage:   "Enable verbose logging",
				EnvVars: []string{"KMS_VERBOSE"},
			},
		},
		Action: runKMSServer,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

func runKMSServer(c *cli.Context) error {
	// Create logger
	loggerConfig := &logger.LoggerConfig{
		Debug: c.Bool("verbose"),
	}
	appLogger, err := logger.NewLogger(loggerConfig)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	defer func() { _ = appLogger.Sync() }()

	// Parse configuration from flags/environment
	kmsConfig, err := parseKMSConfig(c)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	// Validate configuration
	if err := kmsConfig.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	appLogger.Sugar().Infow("Using chain", "name", kmsConfig.ChainName, "chain_id", kmsConfig.ChainID)

	// Convert DKGAt timestamp to time.Time if provided
	var dkgAt *time.Time
	if kmsConfig.DKGAt > 0 {
		t := time.Unix(kmsConfig.DKGAt, 0)
		dkgAt = &t
	} else if kmsConfig.DKGAt == 0 && c.IsSet("dkg-at") {
		// Immediate execution
		t := time.Now()
		dkgAt = &t
	}

	// Create node config from KMS config (operators fetched dynamically when needed)
	nodeConfig := node.Config{
		OperatorAddress: kmsConfig.OperatorAddress,
		Port:            kmsConfig.Port,
		BN254PrivateKey: kmsConfig.BN254PrivateKey,
		ChainID:         kmsConfig.ChainID,
		AVSAddress:      kmsConfig.AVSAddress,
		OperatorSetId:   kmsConfig.OperatorSetId,
		DKGAt:           dkgAt,
		Logger:          appLogger,
	}

	// Create peering data fetcher for dynamic operator fetching
	peeringDataFetcher := createPeeringDataFetcher(kmsConfig, appLogger)
	
	// Create and configure the node
	n := node.NewNode(nodeConfig, peeringDataFetcher)

	if c.Bool("verbose") {
		appLogger.Sugar().Infow("KMS Server Configuration", 
			"operator_address", kmsConfig.OperatorAddress,
			"port", kmsConfig.Port,
			"dkg_at", kmsConfig.DKGAt,
			"chain", kmsConfig.ChainName)
	}

	// Start the node server
	appLogger.Sugar().Infow("Starting KMS Server", "operator_address", kmsConfig.OperatorAddress, "port", kmsConfig.Port)

	if err := n.Start(); err != nil {
		return fmt.Errorf("failed to start node: %w", err)
	}

	// Node scheduler handles DKG and reshare automatically based on config
	appLogger.Sugar().Infow("KMS Server running", "operator_address", kmsConfig.OperatorAddress, "port", kmsConfig.Port)
	appLogger.Sugar().Infow("Available endpoints", 
		"secrets", "POST /secrets",
		"app_sign", "POST /app/sign",
		"dkg", "POST /dkg/*",
		"reshare", "POST /reshare/*")
	appLogger.Sugar().Info("Press Ctrl+C to stop")

	// Keep the server running
	select {}
}

func parseKMSConfig(c *cli.Context) (*config.KMSServerConfig, error) {
	return &config.KMSServerConfig{
		OperatorAddress: c.String("operator-address"),
		Port:            c.Int("port"),
		ChainID:         config.ChainId(c.Uint64("chain-id")),
		BN254PrivateKey: c.String("bn254-private-key"),
		RpcUrl:          c.String("rpc-url"),
		AVSAddress:      c.String("avs-address"),
		OperatorSetId:   uint32(c.Uint("operator-set-id")),
		DKGAt:           c.Int64("dkg-at"),
		Debug:           c.Bool("verbose"),
		Verbose:         c.Bool("verbose"),
	}, nil
}

// Note: Operator fetching now handled dynamically by peering data fetcher

// createPeeringDataFetcher creates a peering data fetcher that queries the blockchain
func createPeeringDataFetcher(kmsConfig *config.KMSServerConfig, logger *zap.Logger) peering.IPeeringDataFetcher {
	logger.Sugar().Infow("Creating peering data fetcher", 
		"chain_id", kmsConfig.ChainID,
		"rpc_url", kmsConfig.RpcUrl,
		"avs_address", kmsConfig.AVSAddress)
	
	// Create Ethereum client
	ethClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   kmsConfig.RpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, logger)

	// Get contract caller
	l1Client, err := ethClient.GetEthereumContractCaller()
	if err != nil {
		logger.Sugar().Errorw("Failed to get Ethereum contract caller, falling back to stub", "error", err)
		return peering.NewStubPeeringDataFetcher(createStubOperatorSetPeers(3))
	}

	// Create contract caller (no signer needed for read operations)
	contractCaller, err := caller.NewContractCaller(l1Client, nil, logger)
	if err != nil {
		logger.Sugar().Errorw("Failed to create contract caller, falling back to stub", "error", err)
		return peering.NewStubPeeringDataFetcher(createStubOperatorSetPeers(3))
	}

	// Return the existing peeringDataFetcher implementation
	return peeringDataFetcher.NewPeeringDataFetcher(contractCaller, logger)
}

// createStubOperatorSetPeers creates stub operator set peers for testing
func createStubOperatorSetPeers(numOperators int) *peering.OperatorSetPeers {
	peers := make([]*peering.OperatorSetPeer, numOperators)
	
	for i := 0; i < numOperators; i++ {
		peers[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress(fmt.Sprintf("0x%040d", i+1)),
			SocketAddress:   fmt.Sprintf("http://localhost:%d", 8000+i+1),
		}
	}
	
	return &peering.OperatorSetPeers{
		OperatorSetId: 1,
		AVSAddress:    common.HexToAddress("0x1234567890123456789012345678901234567890"),
		Peers:         peers,
	}
}