package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	EVMChainPoller "github.com/Layr-Labs/chain-indexer/pkg/chainPollers/evm"
	"github.com/Layr-Labs/chain-indexer/pkg/chainPollers/persistence/memory"
	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	chainIndexerConfig "github.com/Layr-Labs/chain-indexer/pkg/config"
	"github.com/Layr-Labs/chain-indexer/pkg/contractStore/inMemoryContractStore"
	"github.com/Layr-Labs/chain-indexer/pkg/transactionLogParser"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/blockHandler"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/web3signer"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/node"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering/peeringDataFetcher"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
	persistenceBadger "github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/badger"
	persistenceMemory "github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/memory"
	persistenceRedis "github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/redis"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transactionSigner"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/inMemoryTransportSigner"
	web3TransportSigner "github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/web3TransportSigner"
	"github.com/ethereum/go-ethereum/common"
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
			// ECDSA Operator Signing Configuration
			&cli.StringFlag{
				Name:    "ecdsa-private-key",
				Aliases: []string{"ecdsa"},
				Usage:   "ECDSA private key (hex string) for P2P authentication and transaction signing",
				EnvVars: []string{config.EnvKMSECDSAPrivateKey},
			},
			&cli.BoolFlag{
				Name:    "use-remote-signer",
				Usage:   "Use Web3Signer for remote signing instead of local private key",
				EnvVars: []string{config.EnvKMSUseRemoteSigner},
			},
			&cli.StringFlag{
				Name:    "web3signer-url",
				Usage:   "Web3Signer URL (required if --use-remote-signer is true)",
				EnvVars: []string{config.EnvKMSWeb3SignerURL},
			},
			&cli.StringFlag{
				Name:    "web3signer-ca-cert",
				Usage:   "Web3Signer CA certificate path (for TLS)",
				EnvVars: []string{config.EnvKMSWeb3SignerCACert},
			},
			&cli.StringFlag{
				Name:    "web3signer-cert",
				Usage:   "Web3Signer client certificate path (for mTLS)",
				EnvVars: []string{config.EnvKMSWeb3SignerCert},
			},
			&cli.StringFlag{
				Name:    "web3signer-key",
				Usage:   "Web3Signer client key path (for mTLS)",
				EnvVars: []string{config.EnvKMSWeb3SignerKey},
			},
			&cli.StringFlag{
				Name:    "web3signer-from-address",
				Usage:   "Ethereum address to use for Web3Signer signing (required if --use-remote-signer is true)",
				EnvVars: []string{config.EnvKMSWeb3SignerFromAddress},
			},
			&cli.StringFlag{
				Name:    "web3signer-public-key",
				Usage:   "ECDSA public key for Web3Signer (required if --use-remote-signer is true)",
				EnvVars: []string{config.EnvKMSWeb3SignerPublicKey},
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
			&cli.StringFlag{
				Name:     "base-rpc-url",
				Usage:    "Base chain RPC endpoint URL for commitment registry",
				EnvVars:  []string{config.EnvKMSBaseRPCURL},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "commitment-registry-address",
				Aliases:  []string{"registry"},
				Usage:    "EigenKMS Commitment Registry contract address (on Base)",
				EnvVars:  []string{config.EnvKMSCommitmentRegistryAddr},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "persistence-type",
				Usage:   "Persistence backend: 'memory' (testing only), 'badger' (local disk), or 'redis' (distributed)",
				Value:   "badger",
				EnvVars: []string{config.EnvKMSPersistenceType},
			},
			&cli.StringFlag{
				Name:    "persistence-data-path",
				Usage:   "Data directory for Badger persistence",
				Value:   "./kms-data",
				EnvVars: []string{config.EnvKMSPersistenceDataPath},
			},
			&cli.StringFlag{
				Name:    "redis-address",
				Usage:   "Redis server address (host:port) for Redis persistence",
				Value:   "localhost:6379",
				EnvVars: []string{config.EnvKMSRedisAddress},
			},
			&cli.StringFlag{
				Name:    "redis-password",
				Usage:   "Redis password (optional)",
				EnvVars: []string{config.EnvKMSRedisPassword},
			},
			&cli.IntFlag{
				Name:    "redis-db",
				Usage:   "Redis database number (0-15)",
				Value:   0,
				EnvVars: []string{config.EnvKMSRedisDB},
			},
			&cli.StringFlag{
				Name:    "redis-key-prefix",
				Usage:   "Custom prefix for Redis keys (for multi-tenant setups)",
				EnvVars: []string{config.EnvKMSRedisKeyPrefix},
			},
			// Attestation configuration
			&cli.StringFlag{
				Name:    "gcp-project-id",
				Usage:   "GCP project ID for Google Confidential Space attestation verification",
				EnvVars: []string{config.EnvKMSGCPProjectID},
			},
			&cli.StringFlag{
				Name:    "attestation-provider",
				Usage:   "Default attestation provider: 'google' or 'intel' (for GCP method)",
				Value:   "google",
				EnvVars: []string{config.EnvKMSAttestationProvider},
			},
			&cli.BoolFlag{
				Name:    "attestation-debug-mode",
				Usage:   "Enable debug mode for attestation (skips some security checks)",
				EnvVars: []string{config.EnvKMSAttestationDebugMode},
			},
			&cli.BoolFlag{
				Name:    "enable-gcp-attestation",
				Usage:   "Enable Google Confidential Space / Intel Trust Authority attestation",
				Value:   true,
				EnvVars: []string{config.EnvKMSEnableGCPAttestation},
			},
			&cli.BoolFlag{
				Name:    "enable-ecdsa-attestation",
				Usage:   "Enable ECDSA signature-based attestation (for development/testing)",
				Value:   false,
				EnvVars: []string{config.EnvKMSEnableECDSAAttestation},
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

	// Create Base Ethereum client for commitment registry
	baseClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   kmsConfig.BaseRpcUrl,
		BlockType: ethereum.BlockType_Latest,
	}, l)

	l2Client, err := baseClient.GetEthereumContractCaller()
	if err != nil {
		l.Sugar().Fatalw("Failed to get Base contract caller", "error", err)
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
			ChainId:         chainIndexerConfig.ChainId(kmsConfig.ChainID),
			PollingInterval: config.GetDefaultPollerIntervalForChainId(kmsConfig.ChainID),
		},
		pollerStore, bh, l)
	if err != nil {
		l.Sugar().Fatalw("Failed to create EVM chain poller", "error", err)
	}

	// Create transport signer based on OperatorConfig
	var transportSignerInstance transportSigner.ITransportSigner
	var transactionSignerInstance transactionSigner.ITransactionSigner
	if kmsConfig.OperatorConfig.SigningConfig.UseRemoteSigner {
		// Create Web3Signer client
		web3SignerClient, err := web3signer.NewWeb3SignerClientFromRemoteSignerConfig(
			kmsConfig.OperatorConfig.SigningConfig.RemoteSignerConfig,
			l,
		)
		if err != nil {
			l.Sugar().Fatalw("Failed to create Web3Signer client", "error", err)
		}

		// Create Web3Signer transport signer
		fromAddr := common.HexToAddress(kmsConfig.OperatorConfig.SigningConfig.RemoteSignerConfig.FromAddress)
		transportSignerInstance, err = web3TransportSigner.NewWeb3TransportSigner(
			web3SignerClient,
			fromAddr,
			kmsConfig.OperatorConfig.SigningConfig.RemoteSignerConfig.PublicKey,
			config.CurveTypeECDSA,
			l,
		)
		if err != nil {
			l.Sugar().Fatalw("Failed to create Web3Signer transport signer", "error", err)
		}

		transactionSignerInstance, err = transactionSigner.NewWeb3TransactionSigner(web3SignerClient, fromAddr, l2Client, l)
		if err != nil {
			l.Sugar().Fatalw("Failed to create Web3Signer transaction signer", "error", err)
		}

		l.Sugar().Infow("Using Web3Signer for P2P authentication",
			"from_address", fromAddr.Hex(),
			"public_key", kmsConfig.OperatorConfig.SigningConfig.RemoteSignerConfig.PublicKey,
			"url", kmsConfig.OperatorConfig.SigningConfig.RemoteSignerConfig.Url)
	} else {
		// Use local ECDSA private key
		pkBytes, err := hexutil.Decode(kmsConfig.OperatorConfig.SigningConfig.PrivateKey)
		if err != nil {
			l.Sugar().Fatalw("Failed to decode ECDSA private key", "error", err)
		}

		transportSignerInstance, err = inMemoryTransportSigner.NewECDSAInMemoryTransportSigner(pkBytes, l)
		if err != nil {
			l.Sugar().Fatalw("Failed to create ECDSA in-memory transport signer", "error", err)
		}

		transactionSignerInstance, err = transactionSigner.NewPrivateKeySigner(kmsConfig.OperatorConfig.SigningConfig.PrivateKey, l2Client, l)
		if err != nil {
			l.Sugar().Fatalw("Failed to create private key transaction signer", "error", err)
		}

		l.Sugar().Infow("Using local ECDSA private key for P2P authentication",
			"operator_address", kmsConfig.OperatorAddress)
	}

	// Create attestation manager with enabled methods
	enableGCP := c.Bool("enable-gcp-attestation")
	enableECDSA := c.Bool("enable-ecdsa-attestation")

	// Validate at least one method is enabled
	if !enableGCP && !enableECDSA {
		return fmt.Errorf("at least one attestation method must be enabled (--enable-gcp-attestation or --enable-ecdsa-attestation)")
	}

	// Create slog logger for attestation
	slogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	if c.Bool("verbose") {
		slogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	// Create attestation manager
	attestationManager := attestation.NewAttestationManager(slogger)

	ctx := context.Background()

	// Register GCP attestation if enabled
	if enableGCP {
		gcpProjectID := c.String("gcp-project-id")
		providerStr := c.String("attestation-provider")
		debugMode := c.Bool("attestation-debug-mode")

		// Parse attestation provider
		var provider attestation.AttestationProvider
		switch providerStr {
		case "google":
			provider = attestation.GoogleConfidentialSpace
		case "intel":
			provider = attestation.IntelTrustAuthority
		default:
			return fmt.Errorf("invalid attestation provider: %s (must be 'google' or 'intel')", providerStr)
		}

		// Initialize production attestation verifier
		attestationVerifierCore, err := attestation.NewAttestationVerifier(
			ctx,
			slogger,
			gcpProjectID,
			time.Hour, // JWK cache refresh interval
			debugMode,
		)
		if err != nil {
			return fmt.Errorf("failed to create attestation verifier: %w", err)
		}

		// Create GCP method and register
		gcpMethod := attestation.NewGCPAttestationMethod(attestationVerifierCore, provider)
		if err := attestationManager.RegisterMethod(gcpMethod); err != nil {
			return fmt.Errorf("failed to register GCP attestation method: %w", err)
		}

		l.Sugar().Infow("GCP attestation method enabled",
			"method_name", gcpMethod.Name(),
			"gcp_project_id", gcpProjectID,
			"provider", providerStr,
			"debug_mode", debugMode)
	}

	// Register ECDSA attestation if enabled
	if enableECDSA {
		ecdsaMethod := attestation.NewECDSAAttestationMethodDefault()
		if err := attestationManager.RegisterMethod(ecdsaMethod); err != nil {
			return fmt.Errorf("failed to register ECDSA attestation method: %w", err)
		}

		l.Sugar().Infow("ECDSA attestation method enabled",
			"method_name", ecdsaMethod.Name(),
			"challenge_window", attestation.DefaultChallengeTimeWindow)
	}

	// Log summary of enabled methods
	enabledMethods := attestationManager.ListMethods()
	l.Sugar().Infow("Attestation manager initialized",
		"enabled_methods", enabledMethods,
		"method_count", len(enabledMethods))

	baseContractCaller, err := caller.NewContractCaller(l2Client, transactionSignerInstance, l)
	if err != nil {
		l.Sugar().Fatalw("Failed to create Base contract caller", "error", err)
	}

	// Create contract caller (no signer needed for read operations)
	l1ContractCaller, err := caller.NewContractCaller(l1Client, nil, l)
	if err != nil {
		l.Sugar().Fatalw("Failed to create contract caller", "error", err)
	}

	pdf := peeringDataFetcher.NewPeeringDataFetcher(l1ContractCaller, l)

	// Parse commitment registry address
	commitmentRegistryAddr := common.HexToAddress(kmsConfig.CommitmentRegistryAddress)

	l.Sugar().Infow("Base chain configuration",
		"base_rpc_url", kmsConfig.BaseRpcUrl,
		"commitment_registry_address", commitmentRegistryAddr.Hex())

	// Create node persistence layer based on configuration
	var nodePersistence persistence.INodePersistence
	switch kmsConfig.PersistenceConfig.Type {
	case "badger":
		var err error
		nodePersistence, err = persistenceBadger.NewBadgerPersistence(
			kmsConfig.PersistenceConfig.DataPath,
			l,
		)
		if err != nil {
			l.Sugar().Fatalw("Failed to create Badger persistence", "error", err)
		}
		l.Sugar().Infow("Using Badger persistence",
			"path", kmsConfig.PersistenceConfig.DataPath)
	case "redis":
		var err error
		nodePersistence, err = persistenceRedis.NewRedisPersistence(
			&persistenceRedis.RedisConfig{
				Address:   kmsConfig.PersistenceConfig.RedisConfig.Address,
				Password:  kmsConfig.PersistenceConfig.RedisConfig.Password,
				DB:        kmsConfig.PersistenceConfig.RedisConfig.DB,
				KeyPrefix: kmsConfig.PersistenceConfig.RedisConfig.KeyPrefix,
			},
			l,
		)
		if err != nil {
			l.Sugar().Fatalw("Failed to create Redis persistence", "error", err)
		}
		logFields := []interface{}{
			"address", kmsConfig.PersistenceConfig.RedisConfig.Address,
			"db", kmsConfig.PersistenceConfig.RedisConfig.DB,
		}
		if kmsConfig.PersistenceConfig.RedisConfig.KeyPrefix != "" {
			logFields = append(logFields, "key_prefix", kmsConfig.PersistenceConfig.RedisConfig.KeyPrefix)
		}
		l.Sugar().Infow("Using Redis persistence", logFields...)
	default:
		nodePersistence = persistenceMemory.NewMemoryPersistence()
		l.Sugar().Warn("⚠️  Using in-memory persistence - data will be lost on restart")
	}

	defer func() { _ = nodePersistence.Close() }()

	// Health check persistence
	if err := nodePersistence.HealthCheck(); err != nil {
		l.Sugar().Fatalw("Persistence health check failed", "error", err)
	}

	// Create and configure the node with attestation manager
	n, err := node.NewNodeWithManager(
		nodeConfig,
		pdf,
		bh,
		poller,
		transportSignerInstance,
		attestationManager,
		baseContractCaller,
		commitmentRegistryAddr,
		nodePersistence,
		l,
	)
	if err != nil {
		l.Sugar().Fatalw("Failed to create node", "error", err)
	}

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
	// Build OperatorConfig based on whether remote signer is used
	var operatorConfig *config.OperatorConfig
	useRemoteSigner := c.Bool("use-remote-signer")

	if useRemoteSigner {
		// Web3Signer configuration
		operatorConfig = &config.OperatorConfig{
			Address: c.String("operator-address"),
			SigningConfig: &config.ECDSAKeyConfig{
				UseRemoteSigner: true,
				RemoteSignerConfig: &config.RemoteSignerConfig{
					Url:         c.String("web3signer-url"),
					CACert:      c.String("web3signer-ca-cert"),
					Cert:        c.String("web3signer-cert"),
					Key:         c.String("web3signer-key"),
					FromAddress: c.String("web3signer-from-address"),
					PublicKey:   c.String("web3signer-public-key"),
				},
			},
		}
	} else {
		// Local private key configuration
		operatorConfig = &config.OperatorConfig{
			Address: c.String("operator-address"),
			SigningConfig: &config.ECDSAKeyConfig{
				UseRemoteSigner: false,
				PrivateKey:      c.String("ecdsa-private-key"),
			},
		}
	}

	// Build persistence config
	persistenceConfig := config.PersistenceConfig{
		Type:     c.String("persistence-type"),
		DataPath: c.String("persistence-data-path"),
	}

	// Add Redis config if using Redis persistence
	if persistenceConfig.Type == "redis" {
		persistenceConfig.RedisConfig = &config.RedisConfig{
			Address:   c.String("redis-address"),
			Password:  c.String("redis-password"),
			DB:        c.Int("redis-db"),
			KeyPrefix: c.String("redis-key-prefix"),
		}
	}

	return &config.KMSServerConfig{
		OperatorAddress:           c.String("operator-address"),
		Port:                      c.Int("port"),
		ChainID:                   config.ChainId(c.Uint64("chain-id")),
		RpcUrl:                    c.String("rpc-url"),
		AVSAddress:                c.String("avs-address"),
		OperatorSetId:             uint32(c.Uint("operator-set-id")),
		Debug:                     c.Bool("verbose"),
		Verbose:                   c.Bool("verbose"),
		BaseRpcUrl:                c.String("base-rpc-url"),
		CommitmentRegistryAddress: c.String("commitment-registry-address"),
		OperatorConfig:            operatorConfig,
		PersistenceConfig:         persistenceConfig,
	}, nil
}
