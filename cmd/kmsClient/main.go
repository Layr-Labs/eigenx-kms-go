package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/ethereum"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/urfave/cli/v2"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
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

// getOperatorsFromChain fetches operator information from the blockchain
func getOperatorsFromChain(c *cli.Context) (*peering.OperatorSetPeers, error) {
	rpcURL := c.String("rpc-url")
	avsAddress := c.String("avs-address")
	operatorSetID := uint32(c.Uint("operator-set-id"))

	fmt.Printf("📡 Fetching operators from chain...\n")
	fmt.Printf("   RPC: %s\n", rpcURL)
	fmt.Printf("   AVS: %s\n", avsAddress)
	fmt.Printf("   Operator Set ID: %d\n", operatorSetID)

	// Create logger
	l, err := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Create Ethereum client
	ethClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
		BaseUrl:   rpcURL,
		BlockType: ethereum.BlockType_Latest,
	}, l)

	// Get contract caller
	l1Client, err := ethClient.GetEthereumContractCaller()
	if err != nil {
		return nil, fmt.Errorf("failed to get Ethereum contract caller: %w", err)
	}

	// Create contract caller (no signer needed for read operations)
	contractCaller, err := caller.NewContractCaller(l1Client, nil, l)
	if err != nil {
		return nil, fmt.Errorf("failed to create contract caller: %w", err)
	}

	// Get operator set with peering data
	operators, err := contractCaller.GetOperatorSetMembersWithPeering(avsAddress, operatorSetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get operators from chain: %w", err)
	}

	if len(operators.Peers) == 0 {
		return nil, fmt.Errorf("no operators found for AVS %s operator set %d", avsAddress, operatorSetID)
	}

	fmt.Printf("✅ Found %d operators on-chain\n", len(operators.Peers))
	for i, op := range operators.Peers {
		fmt.Printf("   Operator %d: %s (%s)\n", i+1, op.OperatorAddress.Hex(), op.SocketAddress)
	}

	return operators, nil
}

// encryptCommand handles the encrypt subcommand
func encryptCommand(c *cli.Context) error {
	appID := c.String("app-id")
	data := c.String("data")
	outputFile := c.String("output")

	fmt.Printf("🔐 Encrypting data for app: %s\n", appID)

	// Step 1: Get operators from chain
	operators, err := getOperatorsFromChain(c)
	if err != nil {
		return fmt.Errorf("failed to get operators: %w", err)
	}

	// Step 2: Get master public key from operators
	masterPubKey, err := getMasterPublicKey(appID, operators)
	if err != nil {
		return fmt.Errorf("failed to get master public key: %w", err)
	}

	fmt.Printf("📡 Retrieved master public key from operators\n")

	// Step 2: Encrypt data using IBE
	encryptedData, err := crypto.EncryptForApp(appID, masterPubKey, []byte(data))
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Step 3: Output result
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

	// Step 1: Get operators from chain
	operators, err := getOperatorsFromChain(c)
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

	// Calculate threshold if not provided
	if threshold == 0 {
		threshold = (2*len(operators.Peers) + 2) / 3
	}

	fmt.Printf("📡 Collecting %d partial signatures from %d operators...\n", threshold, len(operators.Peers))

	// Step 2: Collect partial signatures from operators
	partialSigs, err := collectPartialSignatures(appID, operators, threshold)
	if err != nil {
		return fmt.Errorf("failed to collect partial signatures: %w", err)
	}

	// Step 2: Recover application private key
	appPrivateKey := crypto.RecoverAppPrivateKey(appID, partialSigs, threshold)

	// Step 3: Decrypt data
	decryptedData, err := crypto.DecryptForApp(appID, appPrivateKey, encryptedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Step 4: Output result
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

	// Get operators from chain
	operators, err := getOperatorsFromChain(c)
	if err != nil {
		return fmt.Errorf("failed to get operators: %w", err)
	}

	masterPubKey, err := getMasterPublicKey(appID, operators)
	if err != nil {
		return fmt.Errorf("failed to get master public key: %w", err)
	}

	fmt.Printf("✅ Master Public Key:\n")
	fmt.Printf("  X: %s\n", masterPubKey.X.String())
	fmt.Printf("  Y: %s\n", masterPubKey.Y.String())

	return nil
}

// getMasterPublicKey fetches the master public key from operators
func getMasterPublicKey(appID string, operators *peering.OperatorSetPeers) (types.G2Point, error) {
	if len(operators.Peers) == 0 {
		return types.G2Point{}, fmt.Errorf("no operators provided")
	}

	fmt.Printf("📡 Collecting commitments from %d operators...\n", len(operators.Peers))

	// Step 1: Collect commitments from all operators
	var allCommitments [][]types.G2Point
	successful := 0

	for i, operator := range operators.Peers {
		resp, err := http.Get(operator.SocketAddress + "/pubkey")
		if err != nil {
			fmt.Printf("⚠️  Failed to contact operator %d at %s: %v\n", i, operator.SocketAddress, err)
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("⚠️  Operator %d returned error %d: %s\n", i, resp.StatusCode, string(body))
			continue
		}

		var response struct {
			OperatorAddress string          `json:"operatorAddress"`
			Commitments     []types.G2Point `json:"commitments"`
			Version         int64           `json:"version"`
			IsActive        bool            `json:"isActive"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			fmt.Printf("⚠️  Failed to decode response from operator %d: %v\n", i, err)
			continue
		}

		if !response.IsActive {
			fmt.Printf("⚠️  Operator %d does not have active key version\n", i)
			continue
		}

		if len(response.Commitments) == 0 {
			fmt.Printf("⚠️  Operator %d has no commitments\n", i)
			continue
		}

		allCommitments = append(allCommitments, response.Commitments)
		successful++
		fmt.Printf("✅ Collected commitments from operator %d (%s)\n", i, response.OperatorAddress)
	}

	if successful == 0 {
		return types.G2Point{}, fmt.Errorf("failed to collect commitments from any operator")
	}

	// Step 2: Compute master public key from commitments
	fmt.Printf("🔑 Computing master public key from %d operator commitments...\n", successful)
	masterPubKey := crypto.ComputeMasterPublicKey(allCommitments)

	return masterPubKey, nil
}

// collectPartialSignatures collects partial signatures from threshold number of operators
func collectPartialSignatures(appID string, operators *peering.OperatorSetPeers, threshold int) (map[int]types.G1Point, error) {
	partialSigs := make(map[int]types.G1Point)

	// Generate a random attestation time for signature requests
	attestationTime := int64(0) // Use current active key version

	collected := 0
	for i, operator := range operators.Peers {
		if collected >= threshold {
			break
		}

		// Request partial signature from operator
		req := types.AppSignRequest{
			AppID:           appID,
			AttestationTime: attestationTime,
		}

		reqBody, err := json.Marshal(req)
		if err != nil {
			fmt.Printf("⚠️  Failed to marshal request for operator %d: %v\n", i, err)
			continue
		}

		resp, err := http.Post(operator.SocketAddress+"/app/sign", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			fmt.Printf("⚠️  Failed to contact operator %d at %s: %v\n", i, operator.SocketAddress, err)
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("⚠️  Operator %d returned error %d: %s\n", i, resp.StatusCode, string(body))
			continue
		}

		var response types.AppSignResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			fmt.Printf("⚠️  Failed to decode response from operator %d: %v\n", i, err)
			continue
		}

		// Use operator index as node ID for collection
		// In real implementation, this would use the actual node ID from the operator
		partialSigs[i] = response.PartialSignature
		collected++

		fmt.Printf("📝 Collected partial signature from operator %d\n", i)
	}

	if collected < threshold {
		return nil, fmt.Errorf("insufficient partial signatures: collected %d, needed %d", collected, threshold)
	}

	fmt.Printf("✅ Collected %d partial signatures (threshold: %d)\n", collected, threshold)
	return partialSigs, nil
}
