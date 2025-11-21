package main

import (
	"fmt"
	"log"
	"os"

	EVMChainPoller "github.com/Layr-Labs/chain-indexer/pkg/chainPollers/evm"
	"github.com/Layr-Labs/chain-indexer/pkg/chainPollers/persistence/memory"
	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	chainIndexerConfig "github.com/Layr-Labs/chain-indexer/pkg/config"
	"github.com/Layr-Labs/chain-indexer/pkg/contractStore/inMemoryContractStore"
	"github.com/Layr-Labs/chain-indexer/pkg/transactionLogParser"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/blockHandler"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering/peeringDataFetcher"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/inMemoryTransportSigner"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/urfave/cli/v2"
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
				EnvVars:  []string{config.EnvKMSOperatorAddress},
				Required: true,
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Value:   8000,
				Usage:   "HTTP server port",
				EnvVars: []string{config.EnvKMSPort},
			},
			&cli.Uint64Flag{
				Name:     "chain-id",
				Aliases:  []string{"chain"},
				Usage:    fmt.Sprintf("Ethereum chain ID: %s", config.GetSupportedChainIDsString()),
				EnvVars:  []string{config.EnvKMSChainID},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "bn254-private-key",
				Aliases:  []string{"bn254"},
				Usage:    "BN254 private key (hex string) for threshold cryptography and P2P authentication",
				EnvVars:  []string{config.EnvKMSBN254PrivateKey},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "rpc-url",
				Aliases: []string{"rpc"},
				Usage:   "Ethereum RPC endpoint URL",
				Value:   "http://localhost:8545",
				EnvVars: []string{config.EnvKMSRPCURL},
			},
			&cli.StringFlag{
				Name:     "avs-address",
				Aliases:  []string{"avs"},
				Usage:    "AVS contract address for operator discovery",
				EnvVars:  []string{config.EnvKMSAVSAddress},
				Required: true,
			},
			&cli.UintFlag{
				Name:    "operator-set-id",
				Aliases: []string{"set-id"},
				Usage:   "Operator set ID",
				Value:   0,
				EnvVars: []string{config.EnvKMSOperatorSetID},
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Usage:   "Enable verbose logging",
				EnvVars: []string{config.EnvKMSVerbose},
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
	l, err := logger.NewLogger(loggerConfig)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	defer func() { _ = l.Sync() }()

	// Parse configuration from flags/environment
	kmsConfig, err := parseKMSConfig(c)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	// Validate configuration
	if err := kmsConfig.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	l.Sugar().Infow("Using chain", "name", kmsConfig.ChainName, "chain_id", kmsConfig.ChainID)

	// Create node config from KMS config (operators fetched dynamically when needed)
	nodeConfig := node.Config{
		OperatorAddress: kmsConfig.OperatorAddress,
		Port:            kmsConfig.Port,
		BN254PrivateKey: kmsConfig.BN254PrivateKey,
		ChainID:         kmsConfig.ChainID,
		AVSAddress:      kmsConfig.AVSAddress,
		OperatorSetId:   kmsConfig.OperatorSetId,
	}

	// Create Ethereum client
	ethClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   kmsConfig.RpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, l)

	// Get contract caller
	l1Client, err := ethClient.GetEthereumContractCaller()
	if err != nil {
		l.Sugar().Fatalw("Failed to get Ethereum contract caller", "error", err)
	}

	// Create contract caller (no signer needed for read operations)
	contractCaller, err := caller.NewContractCaller(l1Client, nil, l)
	if err != nil {
		l.Sugar().Fatalw("Failed to create contract caller", "error", err)
	}

	bh := blockHandler.NewBlockHandler(l)

	// we're not going to parse logs, but these are required for the chain poller
	cs := inMemoryContractStore.NewInMemoryContractStore(nil, l)
	logParser := transactionLogParser.NewTransactionLogParser(cs, l)

	// TODO(seanmcgary): This persistence should be swapped out for a more permanent solution that will also hold the node's state
	pollerStore := memory.NewInMemoryChainPollerPersistence()

	poller, err := EVMChainPoller.NewEVMChainPoller(
		ethClient,
		logParser,
		&EVMChainPoller.EVMChainPollerConfig{
			ChainId: chainIndexerConfig.ChainId(kmsConfig.ChainID),
		},
		pollerStore, bh, l)
	if err != nil {
		l.Sugar().Fatalw("Failed to create EVM chain poller", "error", err)
	}

	pdf := peeringDataFetcher.NewPeeringDataFetcher(contractCaller, l)

	pkBytes, err := hexutil.Decode(kmsConfig.BN254PrivateKey)
	if err != nil {
		l.Sugar().Fatalw("Failed to decode private key", "error", err)
	}
	imts, err := inMemoryTransportSigner.NewBn254InMemoryTransportSigner(pkBytes, l)
	if err != nil {
		l.Sugar().Fatalw("Failed to create in-memory transport signer", "error", err)
	}

	// Create and configure the node
	// TODO: Initialize production attestation verifier here when ready for production
	// For now, using nil defaults to StubVerifier
	n := node.NewNode(nodeConfig, pdf, bh, poller, imts, nil, l)

	if c.Bool("verbose") {
		l.Sugar().Infow("KMS Server Configuration",
			"operator_address", kmsConfig.OperatorAddress,
			"port", kmsConfig.Port,
			"chain", kmsConfig.ChainName,
			"reshare_block_interval", config.GetReshareBlockIntervalForChain(kmsConfig.ChainID),
			"protocol_timeout", config.GetProtocolTimeoutForChain(kmsConfig.ChainID))
	}

	// Start the node server
	l.Sugar().Infow("Starting KMS Server", "operator_address", kmsConfig.OperatorAddress, "port", kmsConfig.Port)

	if err := n.Start(); err != nil {
		return fmt.Errorf("failed to start node: %w", err)
	}

	// Node scheduler handles DKG and reshare automatically based on config
	l.Sugar().Infow("KMS Server running", "operator_address", kmsConfig.OperatorAddress, "port", kmsConfig.Port)
	l.Sugar().Infow("Available endpoints",
		"secrets", "POST /secrets",
		"app_sign", "POST /app/sign",
		"dkg", "POST /dkg/*",
		"reshare", "POST /reshare/*")
	l.Sugar().Info("Press Ctrl+C to stop")

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
		Debug:           c.Bool("verbose"),
		Verbose:         c.Bool("verbose"),
	}, nil
}
