package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/internal/operator"
	ethereum "github.com/Layr-Labs/eigenx-kms-go/pkg/clients"
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
				Name:     "operator-private-key",
				Aliases:  []string{"priv"},
				Usage:    "ECDSA private key (hex string) for signing transactions",
				EnvVars:  []string{"EIGENKMS_OPERATOR_PRIVATE_KEY"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "avs-private-key",
				Aliases:  []string{"avs-priv"},
				Usage:    "AVS ECDSA private key (hex string) for AVS operations",
				EnvVars:  []string{"EIGENKMS_AVS_PRIVATE_KEY"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "bn254-private-key",
				Aliases:  []string{"bn254"},
				Usage:    "BN254 private key (hex string) for threshold cryptography",
				EnvVars:  []string{"EIGENKMS_BN254_PRIVATE_KEY"},
				Required: true,
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
	defer appLogger.Sync()

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

// OperatorConfig holds the operator registration configuration
type OperatorConfig struct {
	AVSAddress         common.Address
	OperatorAddress    common.Address
	OperatorPrivateKey string
	AVSPrivateKey      string
	BN254PrivateKey    string
	Socket             string
	OperatorSetID      uint32
	RPCUrl             string
	ChainID            config.ChainId
	DryRun             bool
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

	// Validate private keys format (basic hex validation)
	if !strings.HasPrefix(c.OperatorPrivateKey, "0x") {
		c.OperatorPrivateKey = "0x" + c.OperatorPrivateKey
	}
	if len(c.OperatorPrivateKey) != 66 { // 0x + 64 hex chars
		return fmt.Errorf("operator ECDSA private key must be 32 bytes (64 hex chars), got %d chars", len(c.OperatorPrivateKey)-2)
	}

	if !strings.HasPrefix(c.AVSPrivateKey, "0x") {
		c.AVSPrivateKey = "0x" + c.AVSPrivateKey
	}
	if len(c.AVSPrivateKey) != 66 { // 0x + 64 hex chars
		return fmt.Errorf("AVS ECDSA private key must be 32 bytes (64 hex chars), got %d chars", len(c.AVSPrivateKey)-2)
	}

	if !strings.HasPrefix(c.BN254PrivateKey, "0x") {
		c.BN254PrivateKey = "0x" + c.BN254PrivateKey
	}
	if len(c.BN254PrivateKey) != 66 { // 0x + 64 hex chars
		return fmt.Errorf("BN254 private key must be 32 bytes (64 hex chars), got %d chars", len(c.BN254PrivateKey)-2)
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

	// Validate operator set ID
	if c.OperatorSetID == 0 {
		return fmt.Errorf("operator set ID must be greater than 0")
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

	return &OperatorConfig{
		AVSAddress:         avsAddress,
		OperatorAddress:    operatorAddress,
		OperatorPrivateKey: c.String("operator-private-key"),
		AVSPrivateKey:      c.String("avs-private-key"),
		BN254PrivateKey:    c.String("bn254-private-key"),
		Socket:             c.String("socket"),
		OperatorSetID:      uint32(c.Uint64("operator-set-id")),
		RPCUrl:             c.String("rpc-url"),
		ChainID:            config.ChainId(c.Uint64("chain-id")),
		DryRun:             c.Bool("dry-run"),
	}, nil
}

func executeRegistration(cfg *OperatorConfig, l *zap.Logger) error {
	sugar := l.Sugar()

	sugar.Infow("Starting operator registration",
		"avs_address", cfg.AVSAddress.Hex(),
		"operator_address", cfg.OperatorAddress.Hex(),
		"operator_set_id", cfg.OperatorSetID,
	)

	l1EthereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   cfg.RPCUrl,
		BlockType: ethereum.BlockType_Latest,
	}, l)

	l1EthClient, err := l1EthereumClient.GetEthereumContractCaller()
	if err != nil {
		return fmt.Errorf("failed to get Ethereum contract caller: %v", err)
	}

	avsSigner, err := transactionSigner.NewPrivateKeySigner(cfg.AVSPrivateKey, l1EthClient, l)
	if err != nil {
		return fmt.Errorf("failed to create AVS signer: %v", err)
	}

	avsCaller, err := caller.NewContractCaller(l1EthClient, avsSigner, l)
	if err != nil {
		return fmt.Errorf("failed to create AVS caller: %v", err)
	}

	operatorSigner, err := transactionSigner.NewPrivateKeySigner(cfg.OperatorPrivateKey, l1EthClient, l)
	if err != nil {
		return fmt.Errorf("failed to create operator signer: %v", err)
	}

	operatorContractCaller, err := caller.NewContractCaller(l1EthClient, operatorSigner, l)
	if err != nil {
		return fmt.Errorf("failed to create operator contract caller: %v", err)
	}

	operatorPrivateKey, err := bn254.NewPrivateKeyFromHexString(cfg.BN254PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse BN254 private key: %v", err)
	}

	receipt, err := operator.RegisterOperatorToOperatorSets(
		context.Background(),
		avsCaller,
		operatorContractCaller,
		cfg.AVSAddress,
		[]uint32{cfg.OperatorSetID},
		&operator.Operator{
			TransactionPrivateKey: cfg.OperatorPrivateKey,
			SigningPrivateKey:     operatorPrivateKey,
			Curve:                 config.CurveTypeBN254,
			OperatorSetIds:        []uint32{cfg.OperatorSetID},
		},
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
