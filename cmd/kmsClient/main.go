package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/urfave/cli/v2"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
)

func main() {
	app := &cli.App{
		Name:  "kms-client",
		Usage: "EigenX KMS Client for encrypting/decrypting application data",
		Description: `A client for interacting with EigenX KMS operators to encrypt and decrypt application data.

This client can:
- Encrypt data using the master public key derived from operator commitments
- Decrypt data by collecting threshold partial signatures from operators
- Interact with distributed KMS operator network securely`,
		Version: "1.0.0",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "rpc-url",
				Usage: "Ethereum RPC URL",
				Value: "http://localhost:8545",
			},
			&cli.StringFlag{
				Name:     "avs-address",
				Usage:    "AVS contract address",
				Required: true,
			},
			&cli.UintFlag{
				Name:  "operator-set-id",
				Usage: "Operator set ID",
				Value: 0,
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "encrypt",
				Usage: "Encrypt data for an application using IBE",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "app-id",
						Usage:    "Application ID for encryption",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "data",
						Usage:    "Data to encrypt (as string)",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "output",
						Usage: "Output file for encrypted data",
						Value: "",
					},
				},
				Action: encryptCommand,
			},
			{
				Name:  "decrypt",
				Usage: "Decrypt data by collecting partial signatures",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "app-id",
						Usage:    "Application ID for decryption",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "encrypted-data",
						Usage:    "Encrypted data (hex string) or path to file",
						Required: true,
					},
					&cli.IntFlag{
						Name:  "threshold",
						Usage: "Number of signatures needed (default: calculated from operators)",
						Value: 0,
					},
					&cli.StringFlag{
						Name:  "output",
						Usage: "Output file for decrypted data",
						Value: "",
					},
				},
				Action: decryptCommand,
			},
			{
				Name:  "get-pubkey",
				Usage: "Get master public key for an application",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "app-id",
						Usage:    "Application ID",
						Required: true,
					},
				},
				Action: getPubkeyCommand,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// createClient creates a new KMS client from CLI context
func createClient(c *cli.Context) (*kmsClient.Client, error) {
	// Create logger
	zapLogger, err := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Create Ethereum client
	rpcURL := c.String("rpc-url")
	ethClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   rpcURL,
		BlockType: ethereum.BlockType_Latest,
	}, zapLogger)

	// Get contract caller
	l1Client, err := ethClient.GetEthereumContractCaller()
	if err != nil {
		return nil, fmt.Errorf("failed to get Ethereum contract caller: %w", err)
	}

	// Create contract caller (no signer needed for read operations)
	contractCaller, err := caller.NewContractCaller(l1Client, nil, zapLogger)
	if err != nil {
		return nil, fmt.Errorf("failed to create contract caller: %w", err)
	}

	// Create KMS client with injected dependencies
	config := &kmsClient.ClientConfig{
		AVSAddress:     c.String("avs-address"),
		OperatorSetID:  uint32(c.Uint("operator-set-id")),
		Logger:         zapLogger,
		ContractCaller: contractCaller,
	}

	client, err := kmsClient.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %w", err)
	}

	return client, nil
}

// encryptCommand handles the encrypt subcommand
func encryptCommand(c *cli.Context) error {
	appID := c.String("app-id")
	data := c.String("data")
	outputFile := c.String("output")

	fmt.Printf("🔐 Encrypting data for app: %s\n", appID)

	// Create KMS client
	client, err := createClient(c)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Get operators from chain
	operators, err := client.GetOperators()
	if err != nil {
		return fmt.Errorf("failed to get operators: %w", err)
	}

	// Encrypt data using IBE
	encryptedData, err := client.Encrypt(appID, []byte(data), operators)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Output result
	encryptedHex := hexutil.Encode(encryptedData)
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(encryptedHex), 0644); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		fmt.Printf("✅ Encrypted data written to: %s\n", outputFile)
	} else {
		fmt.Printf("✅ Encrypted data: %s\n", encryptedHex)
	}

	return nil
}

// decryptCommand handles the decrypt subcommand
func decryptCommand(c *cli.Context) error {
	appID := c.String("app-id")
	encryptedInput := c.String("encrypted-data")
	threshold := c.Int("threshold")
	outputFile := c.String("output")

	fmt.Printf("🔓 Decrypting data for app: %s\n", appID)

	// Create KMS client
	client, err := createClient(c)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Get operators from chain
	operators, err := client.GetOperators()
	if err != nil {
		return fmt.Errorf("failed to get operators: %w", err)
	}

	// Parse encrypted data (hex string or file)
	var encryptedData []byte
	if _, statErr := os.Stat(encryptedInput); statErr == nil {
		// It's a file
		fileData, readErr := os.ReadFile(encryptedInput)
		if readErr != nil {
			return fmt.Errorf("failed to read encrypted data file: %w", readErr)
		}
		var decodeErr error
		encryptedData, decodeErr = hex.DecodeString(string(fileData))
		if decodeErr != nil {
			return fmt.Errorf("failed to decode hex data from file: %w", decodeErr)
		}
	} else {
		// It's a hex string
		var decodeErr error
		fmt.Printf("Using encrypted input %s\n", encryptedInput)
		encryptedData, decodeErr = hexutil.Decode(encryptedInput)
		if decodeErr != nil {
			return fmt.Errorf("failed to decode hex data: %w", decodeErr)
		}
	}

	// Decrypt data
	decryptedData, err := client.Decrypt(appID, encryptedData, operators, threshold)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Output result
	if outputFile != "" {
		if err := os.WriteFile(outputFile, decryptedData, 0644); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		fmt.Printf("✅ Decrypted data written to: %s\n", outputFile)
	} else {
		fmt.Printf("✅ Decrypted data: %s\n", string(decryptedData))
	}

	return nil
}

// getPubkeyCommand handles the get-pubkey subcommand
func getPubkeyCommand(c *cli.Context) error {
	appID := c.String("app-id")

	fmt.Printf("🔑 Getting master public key for app: %s\n", appID)

	// Create KMS client
	client, err := createClient(c)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Get operators from chain
	operators, err := client.GetOperators()
	if err != nil {
		return fmt.Errorf("failed to get operators: %w", err)
	}

	// Get master public key
	masterPubKey, err := client.GetMasterPublicKey(operators)
	if err != nil {
		return fmt.Errorf("failed to get master public key: %w", err)
	}

	fmt.Printf("✅ Master Public Key:\n")
	fmt.Printf("  %s\n", hex.EncodeToString(masterPubKey.CompressedBytes))

	return nil
}
