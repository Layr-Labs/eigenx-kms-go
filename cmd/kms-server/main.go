package main

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
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
				Usage:    "Ethereum chain ID: 1 (mainnet), 11155111 (sepolia), 31337 (anvil)",
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
			&cli.BoolFlag{
				Name:    "auto-dkg",
				Usage:   "Automatically run DKG on startup (for testing)",
				EnvVars: []string{"KMS_AUTO_DKG"},
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
	config, err := parseConfig(c, appLogger)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	// Create peering data fetcher
	peeringDataFetcher := createPeeringDataFetcher(config.Operators, appLogger)
	
	// Create and configure the node
	n := node.NewNode(config, peeringDataFetcher)

	if c.Bool("verbose") {
		appLogger.Sugar().Infow("KMS Server Configuration", 
			"node_id", config.ID,
			"port", config.Port,
			"operators", len(config.Operators),
			"auto_dkg", c.Bool("auto-dkg"))
	}

	// Start the node server
	appLogger.Sugar().Infow("Starting KMS Server", "node_id", config.ID, "port", config.Port)
	
	if err := n.Start(); err != nil {
		return fmt.Errorf("failed to start node: %w", err)
	}

	// Optionally run DKG automatically
	if c.Bool("auto-dkg") {
		appLogger.Sugar().Infow("Running DKG automatically", "node_id", config.ID)
		if err := n.RunDKG(); err != nil {
			appLogger.Sugar().Errorw("DKG failed", "node_id", config.ID, "error", err)
		} else {
			appLogger.Sugar().Infow("DKG completed successfully", "node_id", config.ID)
		}
	}

	appLogger.Sugar().Infow("KMS Server running", "node_id", config.ID, "port", config.Port)
	appLogger.Sugar().Infow("Available endpoints", 
		"secrets", "POST /secrets",
		"app_sign", "POST /app/sign",
		"dkg", "POST /dkg/*",
		"reshare", "POST /reshare/*")
	appLogger.Sugar().Info("Press Ctrl+C to stop")

	// Keep the server running
	select {}
}

func parseConfig(c *cli.Context, logger *zap.Logger) (node.Config, error) {
	nodeID := c.Int("node-id")
	port := c.Int("port")
	chainID := c.Uint64("chain-id")
	
	// Validate chain ID
	validChainIDs := map[uint64]string{
		1:        "mainnet",
		11155111: "sepolia", 
		31337:    "anvil",
	}
	
	chainName, valid := validChainIDs[chainID]
	if !valid {
		return node.Config{}, fmt.Errorf("invalid chain ID %d. Supported: 1 (mainnet), 11155111 (sepolia), 31337 (anvil)", chainID)
	}
	
	logger.Sugar().Infow("Using chain", "name", chainName, "chain_id", chainID)
	
	// Get operators from on-chain registry (stubbed for now)
	operators, err := getOperatorsFromChain(chainID, nodeID)
	if err != nil {
		return node.Config{}, fmt.Errorf("failed to get operators from chain: %w", err)
	}

	// Decode keys (for now, using base64 - in production would be more secure)
	p2pPrivKey := []byte(c.String("p2p-private-key"))
	p2pPubKey := []byte(c.String("p2p-public-key"))

	return node.Config{
		ID:         nodeID,
		Port:       port,
		P2PPrivKey: p2pPrivKey,
		P2PPubKey:  p2pPubKey,
		Operators:  operators,
		Logger:     logger,
	}, nil
}

// getOperatorsFromChain retrieves operator set from on-chain AVS registry
func getOperatorsFromChain(chainID uint64, nodeID int) ([]types.OperatorInfo, error) {
	// STUB: In production, this would:
	// 1. Connect to Ethereum RPC for the specified chain
	// 2. Call IKmsAvsRegistry.getNodeInfos() 
	// 3. Parse the returned OperatorInfo[] array
	// 4. Verify this node is in the operator set
	
	switch chainID {
	case 1: // mainnet
		return getMainnetOperators(nodeID)
	case 11155111: // sepolia
		return getSepoliaOperators(nodeID) 
	case 31337: // anvil
		return getAnvilOperators(nodeID)
	default:
		return nil, fmt.Errorf("unsupported chain ID: %d", chainID)
	}
}

// getMainnetOperators returns mainnet operator set (stub)
func getMainnetOperators(nodeID int) ([]types.OperatorInfo, error) {
	// STUB: Query mainnet contract
	return createTestOperatorSet(nodeID, 20), nil // 20 mainnet operators
}

// getSepoliaOperators returns sepolia testnet operator set (stub) 
func getSepoliaOperators(nodeID int) ([]types.OperatorInfo, error) {
	// STUB: Query sepolia contract
	return createTestOperatorSet(nodeID, 5), nil // 5 sepolia test operators
}

// getAnvilOperators returns local anvil operator set (stub)
func getAnvilOperators(nodeID int) ([]types.OperatorInfo, error) {
	// STUB: Query local anvil contract  
	return createTestOperatorSet(nodeID, 3), nil // 3 local operators
}

// createTestOperatorSet creates a test operator set including the specified node
func createTestOperatorSet(nodeID int, totalNodes int) []types.OperatorInfo {
	operators := make([]types.OperatorInfo, totalNodes)
	
	for i := 0; i < totalNodes; i++ {
		id := i + 1
		operators[i] = types.OperatorInfo{
			ID:           id,
			P2PPubKey:    []byte(fmt.Sprintf("pubkey-%d", id)),
			P2PNodeURL:   fmt.Sprintf("http://localhost:%d", 8000+id),
			KMSServerURL: fmt.Sprintf("http://localhost:%d", 8000+id),
		}
	}
	
	// Verify the requested nodeID is in the set
	found := false
	for _, op := range operators {
		if op.ID == nodeID {
			found = true
			break
		}
	}
	
	if !found {
		// Add the node to the operator set if not found (for testing)
		operators = append(operators, types.OperatorInfo{
			ID:           nodeID,
			P2PPubKey:    []byte(fmt.Sprintf("pubkey-%d", nodeID)),
			P2PNodeURL:   fmt.Sprintf("http://localhost:%d", 8000+nodeID),
			KMSServerURL: fmt.Sprintf("http://localhost:%d", 8000+nodeID),
		})
	}
	
	return operators
}

// createPeeringDataFetcher creates a peering data fetcher
func createPeeringDataFetcher(operators []types.OperatorInfo, logger *zap.Logger) peering.IPeeringDataFetcher {
	// For now, use stub for testing. In production, this would use the real peeringDataFetcher
	// that queries the on-chain contract based on chainID
	
	// TODO: Implement real on-chain peering data fetcher that calls:
	// - IKmsAvsRegistry.getNodeInfos() for operator set
	// - Parses operator addresses, socket addresses, and public keys
	// - Returns properly formatted OperatorSetPeers
	
	return peering.NewStubPeeringDataFetcher(nil)
}