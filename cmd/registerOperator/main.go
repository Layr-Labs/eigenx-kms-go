package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	"github.com/Layr-Labs/eigenx-kms-go/internal/operator"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/web3signer"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transactionSigner"
	"github.com/ethereum/go-ethereum/common"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
)

func main() {
	app := &cli.App{
		Name:  "registerOperator",
		Usage: "Register an operator with the EigenKMS AVS",
		Description: `Register an operator with the EigenKMS AVS registry contract.

This command handles:
- Operator registration with the AVS registry
- Setting up operator's socket address for P2P communication
- Configuring BN254 public key for threshold cryptography
- Managing operator set membership`,
		Version: "1.0.0",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "avs-address",
				Aliases:  []string{"avs"},
				Usage:    "EigenKMS AVS registry contract address",
				EnvVars:  []string{"EIGENKMS_AVS_ADDRESS"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "operator-address",
				Aliases:  []string{"addr"},
				Usage:    "Ethereum address of the operator",
				EnvVars:  []string{"EIGENKMS_OPERATOR_ADDRESS"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "operator-private-key",
				Aliases: []string{"priv"},
				Usage:   "ECDSA private key (hex string) for signing transactions (not required if using remote signer)",
				EnvVars: []string{"EIGENKMS_OPERATOR_PRIVATE_KEY"},
			},
			// Operator Web3Signer configuration
			&cli.BoolFlag{
				Name:    "operator-use-remote-signer",
				Usage:   "Use Web3Signer for operator transaction signing instead of local private key",
				EnvVars: []string{"EIGENKMS_OPERATOR_USE_REMOTE_SIGNER"},
			},
			&cli.StringFlag{
				Name:    "operator-web3signer-url",
				Usage:   "Web3Signer URL for operator signing (required if --operator-use-remote-signer is true)",
				EnvVars: []string{"EIGENKMS_OPERATOR_WEB3SIGNER_URL"},
			},
			&cli.StringFlag{
				Name:    "operator-web3signer-ca-cert",
				Usage:   "Web3Signer CA certificate path for operator (for TLS)",
				EnvVars: []string{"EIGENKMS_OPERATOR_WEB3SIGNER_CA_CERT"},
			},
			&cli.StringFlag{
				Name:    "operator-web3signer-cert",
				Usage:   "Web3Signer client certificate path for operator (for mTLS)",
				EnvVars: []string{"EIGENKMS_OPERATOR_WEB3SIGNER_CERT"},
			},
			&cli.StringFlag{
				Name:    "operator-web3signer-key",
				Usage:   "Web3Signer client key path for operator (for mTLS)",
				EnvVars: []string{"EIGENKMS_OPERATOR_WEB3SIGNER_KEY"},
			},
			&cli.StringFlag{
				Name:     "bn254-private-key",
				Aliases:  []string{"bn254"},
				Usage:    "BN254 private key (hex string) for threshold cryptography",
				EnvVars:  []string{"EIGENKMS_BN254_PRIVATE_KEY"},
				Required: false,
			},
			&cli.StringFlag{
				Name:     "ecdsa-private-key",
				Aliases:  []string{"ecdsa"},
				Usage:    "ECDSA private key (hex string) for threshold cryptography (alternative to BN254 key, not required if using ECDSA Web3Signer)",
				EnvVars:  []string{"EIGENKMS_ECDSA_PRIVATE_KEY"},
				Required: false,
			},
			// ECDSA Web3Signer configuration (for key registration signing)
			&cli.BoolFlag{
				Name:    "ecdsa-use-remote-signer",
				Usage:   "Use Web3Signer for ECDSA key registration signing instead of local private key",
				EnvVars: []string{"EIGENKMS_ECDSA_USE_REMOTE_SIGNER"},
			},
			&cli.StringFlag{
				Name:    "ecdsa-web3signer-url",
				Usage:   "Web3Signer URL for ECDSA key registration signing (required if --ecdsa-use-remote-signer is true)",
				EnvVars: []string{"EIGENKMS_ECDSA_WEB3SIGNER_URL"},
			},
			&cli.StringFlag{
				Name:    "ecdsa-web3signer-ca-cert",
				Usage:   "Web3Signer CA certificate path for ECDSA signing (for TLS)",
				EnvVars: []string{"EIGENKMS_ECDSA_WEB3SIGNER_CA_CERT"},
			},
			&cli.StringFlag{
				Name:    "ecdsa-web3signer-cert",
				Usage:   "Web3Signer client certificate path for ECDSA signing (for mTLS)",
				EnvVars: []string{"EIGENKMS_ECDSA_WEB3SIGNER_CERT"},
			},
			&cli.StringFlag{
				Name:    "ecdsa-web3signer-key",
				Usage:   "Web3Signer client key path for ECDSA signing (for mTLS)",
				EnvVars: []string{"EIGENKMS_ECDSA_WEB3SIGNER_KEY"},
			},
			&cli.StringFlag{
				Name:    "ecdsa-web3signer-public-key",
				Usage:   "Public key (hex string) to identify the signing key in Web3Signer (required if --ecdsa-use-remote-signer is true)",
				EnvVars: []string{"EIGENKMS_ECDSA_WEB3SIGNER_PUBLIC_KEY"},
			},
			&cli.StringFlag{
				Name:    "ecdsa-signing-address",
				Usage:   "Ethereum address corresponding to the ECDSA signing key (required if --ecdsa-use-remote-signer is true)",
				EnvVars: []string{"EIGENKMS_ECDSA_SIGNING_ADDRESS"},
			},
			&cli.StringFlag{
				Name:     "socket",
				Aliases:  []string{"sock"},
				Usage:    "Socket address for P2P communication (e.g., http://operator.example.com:8001)",
				EnvVars:  []string{"EIGENKMS_SOCKET"},
				Required: true,
			},
			&cli.Uint64Flag{
				Name:     "operator-set-id",
				Aliases:  []string{"set-id"},
				Usage:    "Operator set ID to join",
				EnvVars:  []string{"EIGENKMS_OPERATOR_SET_ID"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "rpc-url",
				Aliases:  []string{"rpc"},
				Usage:    "Ethereum RPC URL (e.g., http://localhost:8545, https://mainnet.infura.io/v3/...)",
				EnvVars:  []string{"EIGENKMS_RPC_URL"},
				Required: true,
			},
			&cli.Uint64Flag{
				Name:    "chain-id",
				Aliases: []string{"chain"},
				Usage:   fmt.Sprintf("Ethereum chain ID: %s", config.GetSupportedChainIDsString()),
				EnvVars: []string{"EIGENKMS_CHAIN_ID"},
				Value:   uint64(config.ChainId_EthereumAnvil), // Default to anvil for testing
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Usage:   "Enable verbose logging",
				EnvVars: []string{"EIGENKMS_VERBOSE"},
			},
			&cli.BoolFlag{
				Name:    "dry-run",
				Usage:   "Validate parameters without executing registration",
				EnvVars: []string{"EIGENKMS_DRY_RUN"},
			},
		},
		Action: registerOperator,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

func registerOperator(c *cli.Context) error {
	// Create logger
	loggerConfig := &logger.LoggerConfig{
		Debug: c.Bool("verbose"),
	}
	appLogger, err := logger.NewLogger(loggerConfig)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	defer func() { _ = appLogger.Sync() }()

	// Parse and validate configuration
	operatorConfig, err := parseOperatorConfig(c)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	if err := operatorConfig.Validate(); err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	// Log configuration (without private keys)
	appLogger.Sugar().Infow("Operator Registration Configuration",
		"avs_address", operatorConfig.AVSAddress.Hex(),
		"operator_address", operatorConfig.OperatorAddress.Hex(),
		"socket", operatorConfig.Socket,
		"operator_set_id", operatorConfig.OperatorSetID,
		"chain_id", operatorConfig.ChainID,
		"dry_run", operatorConfig.DryRun)

	if operatorConfig.DryRun {
		appLogger.Sugar().Info("Dry run mode - parameters validated successfully")
		return nil
	}

	// Execute registration
	if err := executeRegistration(operatorConfig, appLogger); err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	appLogger.Sugar().Infow("Operator registration completed successfully")
	return nil
}

// RemoteSignerConfig holds Web3Signer configuration
type RemoteSignerConfig struct {
	Url         string
	CACert      string
	Cert        string
	Key         string
	FromAddress string
}

// OperatorConfig holds the operator registration configuration
type OperatorConfig struct {
	AVSAddress         common.Address
	OperatorAddress    common.Address
	OperatorPrivateKey string
	BN254PrivateKey    string
	ECDSAPrivateKey    string
	Socket             string
	OperatorSetID      uint32
	RPCUrl             string
	ChainID            config.ChainId
	DryRun             bool

	// Operator remote signer configuration (for transaction signing)
	OperatorUseRemoteSigner    bool
	OperatorRemoteSignerConfig *RemoteSignerConfig

	// ECDSA remote signer configuration (for key registration signing)
	ECDSAUseRemoteSigner    bool
	ECDSARemoteSignerConfig *RemoteSignerConfig
	ECDSASigningPublicKey   string
	ECDSASigningAddress     common.Address
}

// Validate validates the operator configuration
func (c *OperatorConfig) Validate() error {
	// Validate AVS address
	if c.AVSAddress == (common.Address{}) {
		return fmt.Errorf("AVS address cannot be empty")
	}

	// Validate operator address
	if c.OperatorAddress == (common.Address{}) {
		return fmt.Errorf("operator address cannot be empty")
	}

	// Validate operator signing configuration
	if c.OperatorUseRemoteSigner {
		if c.OperatorRemoteSignerConfig == nil {
			return fmt.Errorf("operator remote signer config is required when using remote signer")
		}
		if c.OperatorRemoteSignerConfig.Url == "" {
			return fmt.Errorf("operator Web3Signer URL is required when using remote signer")
		}
		// FromAddress for operator comes from OperatorAddress
	} else {
		// Validate operator private key format (basic hex validation)
		if c.OperatorPrivateKey == "" {
			return fmt.Errorf("operator private key is required when not using remote signer")
		}
		if !strings.HasPrefix(c.OperatorPrivateKey, "0x") {
			c.OperatorPrivateKey = "0x" + c.OperatorPrivateKey
		}
		if len(c.OperatorPrivateKey) != 66 { // 0x + 64 hex chars
			return fmt.Errorf("operator ECDSA private key must be 32 bytes (64 hex chars), got %d chars", len(c.OperatorPrivateKey)-2)
		}
	}

	// Validate signing key configuration - need either BN254 key, ECDSA key, or ECDSA Web3Signer
	if c.BN254PrivateKey == "" && c.ECDSAPrivateKey == "" && !c.ECDSAUseRemoteSigner {
		return fmt.Errorf("either BN254 private key, ECDSA private key, or ECDSA Web3Signer must be configured")
	}

	if c.BN254PrivateKey != "" {
		if !strings.HasPrefix(c.BN254PrivateKey, "0x") {
			c.BN254PrivateKey = "0x" + c.BN254PrivateKey
		}
		if len(c.BN254PrivateKey) != 66 { // 0x + 64 hex chars
			return fmt.Errorf("BN254 private key must be 32 bytes (64 hex chars), got %d chars", len(c.BN254PrivateKey)-2)
		}
	}

	// Validate ECDSA configuration
	if c.ECDSAUseRemoteSigner {
		if c.ECDSARemoteSignerConfig == nil {
			return fmt.Errorf("ECDSA remote signer config is required when using ECDSA remote signer")
		}
		if c.ECDSARemoteSignerConfig.Url == "" {
			return fmt.Errorf("ECDSA Web3Signer URL is required when using ECDSA remote signer")
		}
		if c.ECDSASigningPublicKey == "" {
			return fmt.Errorf("ECDSA signing public key is required when using ECDSA remote signer")
		}
		if c.ECDSASigningAddress == (common.Address{}) {
			return fmt.Errorf("ECDSA signing address is required when using ECDSA remote signer")
		}
	} else if c.ECDSAPrivateKey != "" {
		if !strings.HasPrefix(c.ECDSAPrivateKey, "0x") {
			c.ECDSAPrivateKey = "0x" + c.ECDSAPrivateKey
		}
	}

	// Validate socket address format
	if c.Socket == "" {
		return fmt.Errorf("socket address cannot be empty")
	}
	if !strings.HasPrefix(c.Socket, "http://") && !strings.HasPrefix(c.Socket, "https://") {
		return fmt.Errorf("socket address must start with http:// or https://")
	}

	// Validate RPC URL format
	if c.RPCUrl == "" {
		return fmt.Errorf("RPC URL cannot be empty")
	}
	if !strings.HasPrefix(c.RPCUrl, "http://") && !strings.HasPrefix(c.RPCUrl, "https://") && !strings.HasPrefix(c.RPCUrl, "ws://") && !strings.HasPrefix(c.RPCUrl, "wss://") {
		return fmt.Errorf("RPC URL must start with http://, https://, ws://, or wss://")
	}

	// Validate chain ID
	supportedChains := config.GetSupportedChainIDs()
	supported := false
	for _, chainID := range supportedChains {
		if c.ChainID == chainID {
			supported = true
			break
		}
	}
	if !supported {
		return fmt.Errorf("unsupported chain ID %d. Supported: %s", c.ChainID, config.GetSupportedChainIDsString())
	}

	return nil
}

func parseOperatorConfig(c *cli.Context) (*OperatorConfig, error) {
	// Parse addresses
	avsAddress := common.HexToAddress(c.String("avs-address"))
	operatorAddress := common.HexToAddress(c.String("operator-address"))

	cfg := &OperatorConfig{
		AVSAddress:         avsAddress,
		OperatorAddress:    operatorAddress,
		OperatorPrivateKey: c.String("operator-private-key"),
		BN254PrivateKey:    c.String("bn254-private-key"),
		ECDSAPrivateKey:    c.String("ecdsa-private-key"),
		Socket:             c.String("socket"),
		OperatorSetID:      uint32(c.Uint64("operator-set-id")),
		RPCUrl:             c.String("rpc-url"),
		ChainID:            config.ChainId(c.Uint64("chain-id")),
		DryRun:             c.Bool("dry-run"),

		// Remote signer configuration
		OperatorUseRemoteSigner: c.Bool("operator-use-remote-signer"),
		ECDSAUseRemoteSigner:    c.Bool("ecdsa-use-remote-signer"),
		ECDSASigningPublicKey:   c.String("ecdsa-web3signer-public-key"),
		ECDSASigningAddress:     common.HexToAddress(c.String("ecdsa-signing-address")),
	}

	// Parse operator remote signer config if enabled
	if cfg.OperatorUseRemoteSigner {
		cfg.OperatorRemoteSignerConfig = &RemoteSignerConfig{
			Url:         c.String("operator-web3signer-url"),
			CACert:      c.String("operator-web3signer-ca-cert"),
			Cert:        c.String("operator-web3signer-cert"),
			Key:         c.String("operator-web3signer-key"),
			FromAddress: operatorAddress.Hex(), // Use operator address as from address
		}
	}

	// Parse ECDSA remote signer config if enabled
	if cfg.ECDSAUseRemoteSigner {
		cfg.ECDSARemoteSignerConfig = &RemoteSignerConfig{
			Url:    c.String("ecdsa-web3signer-url"),
			CACert: c.String("ecdsa-web3signer-ca-cert"),
			Cert:   c.String("ecdsa-web3signer-cert"),
			Key:    c.String("ecdsa-web3signer-key"),
		}
	}

	return cfg, nil
}

func executeRegistration(cfg *OperatorConfig, l *zap.Logger) error {
	sugar := l.Sugar()

	sugar.Infow("Starting operator registration",
		"avs_address", cfg.AVSAddress.Hex(),
		"operator_address", cfg.OperatorAddress.Hex(),
		"operator_set_id", cfg.OperatorSetID,
		"operator_use_remote_signer", cfg.OperatorUseRemoteSigner,
	)

	l1EthereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   cfg.RPCUrl,
		BlockType: ethereum.BlockType_Latest,
	}, l)

	l1EthClient, err := l1EthereumClient.GetEthereumContractCaller()
	if err != nil {
		return fmt.Errorf("failed to get Ethereum contract caller: %v", err)
	}

	// Create operator signer (either Web3Signer or local private key)
	var operatorSigner transactionSigner.ITransactionSigner
	if cfg.OperatorUseRemoteSigner {
		// Create Web3Signer client for operator
		web3SignerConfig := web3signer.NewConfigWithTLS(
			cfg.OperatorRemoteSignerConfig.Url,
			cfg.OperatorRemoteSignerConfig.CACert,
			cfg.OperatorRemoteSignerConfig.Cert,
			cfg.OperatorRemoteSignerConfig.Key,
		)
		web3SignerClient, err := web3signer.NewClient(web3SignerConfig, l)
		if err != nil {
			return fmt.Errorf("failed to create operator Web3Signer client: %v", err)
		}

		operatorSigner, err = transactionSigner.NewWeb3TransactionSigner(web3SignerClient, cfg.OperatorAddress, l1EthClient, l)
		if err != nil {
			return fmt.Errorf("failed to create operator Web3Signer transaction signer: %v", err)
		}

		sugar.Infow("Using Web3Signer for operator signing",
			"url", cfg.OperatorRemoteSignerConfig.Url,
			"from_address", cfg.OperatorAddress.Hex())
	} else {
		operatorSigner, err = transactionSigner.NewPrivateKeySigner(cfg.OperatorPrivateKey, l1EthClient, l)
		if err != nil {
			return fmt.Errorf("failed to create operator signer: %v", err)
		}
		sugar.Info("Using local private key for operator signing")
	}

	operatorContractCaller, err := caller.NewContractCaller(l1EthClient, operatorSigner, l)
	if err != nil {
		return fmt.Errorf("failed to create operator contract caller: %v", err)
	}

	// Build operator configuration
	op := &operator.Operator{
		TransactionPrivateKey: cfg.OperatorPrivateKey,
		TransactionAddress:    cfg.OperatorAddress,
		UseRemoteSigner:       cfg.OperatorUseRemoteSigner,
		OperatorSetIds:        []uint32{cfg.OperatorSetID},
	}

	// Determine curve type and configure signing
	if cfg.ECDSAPrivateKey != "" || cfg.ECDSAUseRemoteSigner {
		op.Curve = config.CurveTypeECDSA

		if cfg.ECDSAUseRemoteSigner {
			// Use Web3Signer for ECDSA key registration signing
			ecdsaWeb3SignerConfig := web3signer.NewConfigWithTLS(
				cfg.ECDSARemoteSignerConfig.Url,
				cfg.ECDSARemoteSignerConfig.CACert,
				cfg.ECDSARemoteSignerConfig.Cert,
				cfg.ECDSARemoteSignerConfig.Key,
			)
			ecdsaWeb3SignerClient, err := web3signer.NewClient(ecdsaWeb3SignerConfig, l)
			if err != nil {
				return fmt.Errorf("failed to create ECDSA Web3Signer client: %v", err)
			}

			op.ECDSAWeb3SignerClient = ecdsaWeb3SignerClient
			op.ECDSASigningPublicKey = cfg.ECDSASigningPublicKey
			op.SigningAddress = &cfg.ECDSASigningAddress

			sugar.Infow("Using Web3Signer for ECDSA key registration signing",
				"url", cfg.ECDSARemoteSignerConfig.Url,
				"signing_address", cfg.ECDSASigningAddress.Hex(),
				"public_key", cfg.ECDSASigningPublicKey)
		} else {
			// Use local ECDSA private key
			ecdsaPrivateKey, err := ecdsa.NewPrivateKeyFromHexString(cfg.ECDSAPrivateKey)
			if err != nil {
				return fmt.Errorf("failed to parse ECDSA private key: %v", err)
			}
			op.SigningPrivateKey = ecdsaPrivateKey
			sugar.Info("Using local private key for ECDSA key registration signing")
		}
	} else {
		// Use BN254 signing
		op.Curve = config.CurveTypeBN254
		bn254PrivateKey, err := bn254.NewPrivateKeyFromHexString(cfg.BN254PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to parse BN254 private key: %v", err)
		}
		op.SigningPrivateKey = bn254PrivateKey
		sugar.Info("Using BN254 for key registration signing")
	}

	receipt, err := operator.RegisterOperatorToOperatorSets(
		context.Background(),
		operatorContractCaller,
		cfg.AVSAddress,
		[]uint32{cfg.OperatorSetID},
		op,
		&operator.RegistrationConfig{
			AllocationDelay: 0,
			MetadataUri:     "",
			Socket:          cfg.Socket,
		},
		l,
	)
	if err != nil {
		return fmt.Errorf("failed to register operator: %w", err)
	}
	sugar.Infow("Operator registered successfully", "transaction_receipt", receipt)

	return nil
}
