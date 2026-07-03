package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/urfave/cli/v2"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
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
				Name:    "environment",
				Aliases: []string{"e"},
				Usage:   "Named connection preset that fills --avs-address and --operator-set-id (e.g. \"sepolia\"). Explicit flags override the preset. The RPC URL is never part of a preset.",
				Value:   "",
			},
			&cli.StringFlag{
				Name:  "rpc-url",
				Usage: "Ethereum RPC URL",
				Value: "http://localhost:8545",
			},
			&cli.StringFlag{
				Name:  "avs-address",
				Usage: "AVS contract address (required unless provided by --environment)",
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
					&cli.StringFlag{
						Name:  "attestation",
						Usage: "Attestation method. Empty (default) uses the unauthenticated /app/sign endpoint; \"ecdsa\" uses ECDSA challenge-response attestation against /secrets.",
						Value: "",
					},
					&cli.StringFlag{
						Name:  "ecdsa-private-key",
						Usage: "Hex-encoded secp256k1 private key for ECDSA attestation (takes priority over --ecdsa-private-key-file). Required when --attestation ecdsa.",
						Value: "",
					},
					&cli.StringFlag{
						Name:  "ecdsa-private-key-file",
						Usage: "Path to a file holding a hex-encoded secp256k1 private key for ECDSA attestation. Used when --ecdsa-private-key is not set.",
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
	// Resolve connection details from the --environment preset and any
	// explicitly-set flags (explicit flags win over the preset). Done first so
	// a config error (e.g. missing avs-address) fails fast without depending on
	// a reachable RPC endpoint.
	avsAddress, operatorSetID, err := resolveConnection(
		c.String("environment"),
		c.String("avs-address"),
		c.IsSet("avs-address"),
		uint32(c.Uint("operator-set-id")),
		c.IsSet("operator-set-id"),
	)
	if err != nil {
		return nil, err
	}

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
		AVSAddress:     avsAddress,
		OperatorSetID:  operatorSetID,
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
		cleanPath, pathErr := prepareOutputPath(outputFile)
		if pathErr != nil {
			return fmt.Errorf("invalid --output path: %w", pathErr)
		}
		if err := writeSecretFile(cleanPath, []byte(encryptedHex)); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		fmt.Printf("✅ Encrypted data written to: %s\n", cleanPath)
		fmt.Fprintf(os.Stderr, "note: output file written with mode 0600 (owner read/write only); verify perms if you chmod it wider\n")
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
	attestationMethod := c.String("attestation")

	// Validate the attestation method up front so a typo fails fast before any
	// file or network work. Empty selects the legacy no-attestation /app/sign
	// flow; "ecdsa" is the only attested method meaningful from a CLI
	// (GCP/Intel/SNP require running inside a TEE).
	switch attestationMethod {
	case "", "ecdsa":
		// supported
	default:
		return fmt.Errorf("unsupported --attestation %q: supported values are \"\" (none) and \"ecdsa\"", attestationMethod)
	}

	fmt.Printf("🔓 Decrypting data for app: %s\n", appID)

	// Create KMS client
	client, err := createClient(c)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Parse encrypted data (hex string or file) up front — independent of the
	// attestation path and cheap to fail on.
	encryptedData, err := parseEncryptedInput(encryptedInput)
	if err != nil {
		return err
	}

	// Recover the plaintext via the selected path.
	var decryptedData []byte
	if attestationMethod == "ecdsa" {
		decryptedData, err = decryptWithECDSAAttestation(c, client, appID, encryptedData)
	} else {
		decryptedData, err = decryptWithoutAttestation(client, appID, encryptedData, threshold)
	}
	if err != nil {
		return err
	}

	// Output result (shared by both paths)
	if outputFile != "" {
		cleanPath, pathErr := prepareOutputPath(outputFile)
		if pathErr != nil {
			return fmt.Errorf("invalid --output path: %w", pathErr)
		}
		if err := writeSecretFile(cleanPath, decryptedData); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		fmt.Printf("✅ Decrypted data written to: %s\n", cleanPath)
		fmt.Fprintf(os.Stderr, "note: output file written with mode 0600 (owner read/write only); verify perms if you chmod it wider\n")
	} else {
		fmt.Printf("✅ Decrypted data: %s\n", string(decryptedData))
	}

	return nil
}

// parseEncryptedInput resolves the --encrypted-data value, which may be either
// a path to a file containing hex or a hex string directly. It accepts the
// 0x-prefixed output that `encrypt --output` writes; TrimSpace handles trailing
// newlines from editors or `echo`.
func parseEncryptedInput(input string) ([]byte, error) {
	if _, statErr := os.Stat(input); statErr == nil {
		fileData, readErr := os.ReadFile(input)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read encrypted data file: %w", readErr)
		}
		data, decodeErr := hexutil.Decode(strings.TrimSpace(string(fileData)))
		if decodeErr != nil {
			return nil, fmt.Errorf("failed to decode hex data from file: %w", decodeErr)
		}
		return data, nil
	}

	fmt.Printf("Using encrypted input %s\n", input)
	data, decodeErr := hexutil.Decode(strings.TrimSpace(input))
	if decodeErr != nil {
		return nil, fmt.Errorf("failed to decode hex data: %w", decodeErr)
	}
	return data, nil
}

// decryptWithoutAttestation recovers the plaintext via the unauthenticated
// /app/sign endpoint — the CLI's original behavior.
func decryptWithoutAttestation(client *kmsClient.Client, appID string, encryptedData []byte, threshold int) ([]byte, error) {
	operators, err := client.GetOperators()
	if err != nil {
		return nil, fmt.Errorf("failed to get operators: %w", err)
	}

	decryptedData, err := client.Decrypt(appID, encryptedData, operators, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	return decryptedData, nil
}

// decryptWithECDSAAttestation recovers the application private key from the
// attested /secrets endpoint using ECDSA challenge-response attestation, then
// decrypts the user-supplied ciphertext with it. Unlike the no-attestation
// path, this requires the operators to have ECDSA attestation enabled and the
// app to exist on-chain (the operator fetches the app's release while serving
// the request).
func decryptWithECDSAAttestation(c *cli.Context, client *kmsClient.Client, appID string, encryptedData []byte) ([]byte, error) {
	key, err := loadECDSAKey(c.String("ecdsa-private-key"), c.String("ecdsa-private-key-file"))
	if err != nil {
		return nil, err
	}

	// The /secrets endpoint encrypts each partial signature to a per-request
	// RSA public key. This keypair is transport-level only and never leaves
	// this process, so we generate an ephemeral one per invocation.
	rsaPrivPEM, rsaPubPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral RSA key pair: %w", err)
	}

	result, err := client.RetrieveSecretsWithOptions(appID, &kmsClient.SecretsOptions{
		AttestationMethod: "ecdsa",
		ECDSAPrivateKey:   key,
		RSAPrivateKeyPEM:  rsaPrivPEM,
		RSAPublicKeyPEM:   rsaPubPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve secrets: %w", err)
	}

	decryptedData, err := crypto.DecryptForApp(appID, result.AppPrivateKey, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	return decryptedData, nil
}

// getPubkeyCommand handles the get-pubkey subcommand
func getPubkeyCommand(c *cli.Context) error {
	appID := c.String("app-id")

	fmt.Printf("🔑 Getting public key for app: %s\n", appID)

	// Create KMS client
	client, err := createClient(c)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	appPubKey, masterPubKey, err := client.GetPublicKeyForApp(appID)
	if err != nil {
		return fmt.Errorf("failed to get public key for app: %w", err)
	}

	fmt.Printf("✅ App Public Key (H_1(appID)):\n")
	fmt.Printf("  %s\n", hex.EncodeToString(appPubKey.CompressedBytes))
	fmt.Printf("✅ Master Public Key:\n")
	fmt.Printf("  %s\n", hex.EncodeToString(masterPubKey.CompressedBytes))

	return nil
}

// writeSecretFile writes sensitive data to path with mode 0600, enforcing
// the permission even if the file already exists with broader permissions.
//
// os.WriteFile only applies the permission mask on file creation; if the
// target already exists (e.g. a prior 0644 file, or an attacker-planted
// file), the content would otherwise be written under the existing mode.
// We open-then-chmod-then-write so the secret is never on disk under the
// wrong mode: after OpenFile the file is opened for writing but still
// zero-byte, so the window between OpenFile and Chmod exposes nothing.
//
// Uses a named return so the deferred Close can surface flush/close errors
// (e.g. EIO on some filesystems) without a double-close.
func writeSecretFile(path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("secure file permissions: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return nil
}

// prepareOutputPath cleans and absolutizes a user-supplied output path. It
// rejects empty paths and paths that resolve to a directory (no file name).
// The path root is intentionally not restricted: this is a CLI, the user
// chooses where to write. Callers should write via writeSecretFile to get
// the 0600 enforcement; this helper does not touch permissions.
func prepareOutputPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("output path is empty")
	}
	// Reject trailing separator before Clean strips it — a trailing slash is
	// an explicit "this is a directory" signal from the user.
	if os.IsPathSeparator(p[len(p)-1]) {
		return "", fmt.Errorf("output path %q is a directory, not a file", p)
	}
	cleaned := filepath.Clean(p)
	if !filepath.IsAbs(cleaned) {
		abs, err := filepath.Abs(cleaned)
		if err != nil {
			return "", fmt.Errorf("resolve absolute path: %w", err)
		}
		cleaned = abs
	}
	base := filepath.Base(cleaned)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return "", fmt.Errorf("output path %q has no file name", p)
	}
	return cleaned, nil
}

// loadECDSAKey resolves the ECDSA attestation private key from the two decrypt
// flags. keyHex (--ecdsa-private-key) takes priority over keyFile
// (--ecdsa-private-key-file); at least one must be non-empty. The key is a
// hex-encoded secp256k1 private key. An optional 0x/0X prefix and surrounding
// whitespace are tolerated — a trailing newline is common when the key is read
// from a file.
func loadECDSAKey(keyHex, keyFile string) (*ecdsa.PrivateKey, error) {
	var raw string
	switch {
	case keyHex != "":
		raw = keyHex
	case keyFile != "":
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read ECDSA private key file: %w", err)
		}
		raw = string(b)
	default:
		return nil, fmt.Errorf("an ECDSA private key is required for --attestation ecdsa: set --ecdsa-private-key or --ecdsa-private-key-file")
	}

	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "0x")
	raw = strings.TrimPrefix(raw, "0X")

	key, err := ethcrypto.HexToECDSA(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDSA private key: %w", err)
	}
	return key, nil
}
