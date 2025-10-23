package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
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
			&cli.IntFlag{
				Name:    "node-id",
				Aliases: []string{"id"},
				Value:   1,
				Usage:   "Unique node ID (1-based)",
				EnvVars: []string{"KMS_NODE_ID"},
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
				Name:    "p2p-private-key",
				Aliases: []string{"p2p-priv"},
				Usage:   "Base64-encoded ed25519 private key for P2P authentication",
				EnvVars: []string{"KMS_P2P_PRIVATE_KEY"},
				Value:   "dGVzdC1wcml2YXRlLWtleQ==", // "test-private-key" in base64
			},
			&cli.StringFlag{
				Name:    "p2p-public-key",
				Aliases: []string{"p2p-pub"},
				Usage:   "Base64-encoded ed25519 public key for P2P authentication",
				EnvVars: []string{"KMS_P2P_PUBLIC_KEY"},
				Value:   "dGVzdC1wdWJsaWMta2V5", // "test-public-key" in base64
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
	defer appLogger.Sync()

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

	// Create node config from KMS config (operators fetched dynamically when needed)
	nodeConfig := node.Config{
		ID:         kmsConfig.NodeID,
		Port:       kmsConfig.Port,
		P2PPrivKey: kmsConfig.P2PPrivateKey,
		P2PPubKey:  kmsConfig.P2PPublicKey,
		Logger:     appLogger,
	}

	// Create peering data fetcher for dynamic operator fetching
	peeringDataFetcher := createPeeringDataFetcher(kmsConfig.ChainID, appLogger)
	
	// Create and configure the node
	n := node.NewNode(nodeConfig, peeringDataFetcher)

	if c.Bool("verbose") {
		appLogger.Sugar().Infow("KMS Server Configuration", 
			"node_id", kmsConfig.NodeID,
			"port", kmsConfig.Port,
			"dkg_at", kmsConfig.DKGAt,
			"chain", kmsConfig.ChainName)
	}

	// Start the node server
	appLogger.Sugar().Infow("Starting KMS Server", "node_id", kmsConfig.NodeID, "port", kmsConfig.Port)
	
	if err := n.Start(); err != nil {
		return fmt.Errorf("failed to start node: %w", err)
	}

	// Schedule DKG execution if timestamp provided
	if kmsConfig.DKGAt > 0 {
		scheduleDKG(n, kmsConfig.DKGAt, appLogger)
	} else if kmsConfig.DKGAt == 0 && c.IsSet("dkg-at") {
		// Immediate execution if explicitly set to 0
		appLogger.Sugar().Infow("Running DKG immediately", "node_id", kmsConfig.NodeID)
		go func() {
			if err := n.RunDKG(); err != nil {
				appLogger.Sugar().Errorw("DKG failed", "node_id", kmsConfig.NodeID, "error", err)
			} else {
				appLogger.Sugar().Infow("DKG completed successfully", "node_id", kmsConfig.NodeID)
			}
		}()
	}

	appLogger.Sugar().Infow("KMS Server running", "node_id", kmsConfig.NodeID, "port", kmsConfig.Port)
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
		NodeID:        c.Int("node-id"),
		Port:          c.Int("port"),
		ChainID:       config.ChainId(c.Uint64("chain-id")),
		P2PPrivateKey: []byte(c.String("p2p-private-key")),
		P2PPublicKey:  []byte(c.String("p2p-public-key")),
		DKGAt:         c.Int64("dkg-at"),
		Debug:         c.Bool("verbose"),
		Verbose:       c.Bool("verbose"),
	}, nil
}

// Note: Operator fetching now handled dynamically by peering data fetcher

// createPeeringDataFetcher creates a peering data fetcher for the specified chain
func createPeeringDataFetcher(chainID config.ChainId, logger *zap.Logger) peering.IPeeringDataFetcher {
	// For now, use stub for testing. In production, this would create the appropriate
	// peering data fetcher based on the chain ID that queries the real on-chain contracts
	
	logger.Sugar().Debugw("Creating peering data fetcher", "chain_id", chainID)
	
	// TODO: Implement real chain-specific peering data fetcher that:
	// 1. Uses the chain ID to determine which contracts to query
	// 2. Calls IKmsAvsRegistry.getNodeInfos() for current operator set
	// 3. Parses operator addresses, socket addresses, and public keys
	// 4. Returns properly formatted OperatorSetPeers
	
	switch chainID {
	case config.ChainId_EthereumMainnet:
		// TODO: Return mainnet peering data fetcher
		return peering.NewStubPeeringDataFetcher(createStubOperatorSetPeers(20))
	case config.ChainId_EthereumSepolia:
		// TODO: Return sepolia peering data fetcher  
		return peering.NewStubPeeringDataFetcher(createStubOperatorSetPeers(5))
	case config.ChainId_EthereumAnvil:
		// TODO: Return anvil peering data fetcher
		return peering.NewStubPeeringDataFetcher(createStubOperatorSetPeers(3))
	default:
		logger.Sugar().Warnw("Unknown chain ID, using default stub", "chain_id", chainID)
		return peering.NewStubPeeringDataFetcher(createStubOperatorSetPeers(3))
	}
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

// scheduleDKG schedules DKG execution at a specific timestamp
func scheduleDKG(n *node.Node, dkgTimestamp int64, logger *zap.Logger) {
	targetTime := time.Unix(dkgTimestamp, 0)
	now := time.Now()
	
	if targetTime.Before(now) {
		logger.Sugar().Warnw("DKG timestamp is in the past, running immediately", "target", targetTime, "now", now)
		go runDKGAsync(n, logger)
		return
	}
	
	delay := targetTime.Sub(now)
	logger.Sugar().Infow("DKG scheduled", "target_time", targetTime, "delay", delay)
	
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		
		select {
		case <-timer.C:
			logger.Sugar().Infow("Starting scheduled DKG", "target_time", targetTime)
			runDKGAsync(n, logger)
		}
	}()
}

// runDKGAsync runs DKG in a goroutine with proper error handling
func runDKGAsync(n *node.Node, logger *zap.Logger) {
	if err := n.RunDKG(); err != nil {
		logger.Sugar().Errorw("Scheduled DKG failed", "error", err)
	} else {
		logger.Sugar().Infow("Scheduled DKG completed successfully")
	}
}