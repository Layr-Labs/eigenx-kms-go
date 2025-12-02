package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/Layr-Labs/eigenx-kms-go/internal/aws"
	"github.com/Layr-Labs/eigenx-kms-go/internal/keyGenerator/awsKms"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/ethereum/go-ethereum/crypto"
	"os"
)

func main() {
	l, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	awsCfg, err := aws.LoadAWSConfig(context.Background(), "")
	if err != nil {
		panic(err)
	}

	keyId := os.Getenv("KEY_ID")
	if keyId == "" {
		l.Sugar().Fatal("KEY_ID environment variable is not set")
	}

	cfg := &config.KMSServerConfig{
		ChainName: "sepolia",
	}

	keyGen := awsKms.NewAWSKMSKeyGenerator(awsCfg, "us-east-1", cfg, l)

	generatedKey, err := keyGen.GetECDSAKeyById(context.Background(), keyId)
	if err != nil {
		l.Sugar().Fatalw("failed to generate ECDSA key", "error", err)
	}

	// Get the public key in different representations
	pubKeyHex, err := generatedKey.GetPublicKeyHex()
	if err != nil {
		l.Sugar().Fatalw("failed to get public key hex", "error", err)
	}

	pubKeyBytes, err := generatedKey.GetPublicKeyBytes()
	if err != nil {
		l.Sugar().Fatalw("failed to get public key bytes", "error", err)
	}

	// Convert to go-ethereum's ecdsa.PublicKey for more representations
	goEthPubKey := &ecdsa.PublicKey{
		X: generatedKey.PublicKey.X,
		Y: generatedKey.PublicKey.Y,
	}

	// Get uncompressed public key (65 bytes: 0x04 + X + Y)
	uncompressedPubKey := crypto.FromECDSAPub(goEthPubKey)

	// Get compressed public key (33 bytes)
	compressedPubKey := crypto.CompressPubkey(goEthPubKey)

	// Get the address from go-ethereum's crypto package
	goEthAddress := crypto.PubkeyToAddress(*goEthPubKey)

	fmt.Println("=== AWS KMS ECDSA Key Information ===")
	fmt.Printf("Key ID: %s\n", generatedKey.KeyId)
	fmt.Printf("Address (from generated key): %s\n", generatedKey.Address)
	fmt.Printf("Address (from go-ethereum): %s\n", goEthAddress.Hex())
	fmt.Println()

	fmt.Println("=== Public Key Representations ===")
	fmt.Printf("Public Key (from GetPublicKeyHex): %s\n", pubKeyHex)
	fmt.Printf("Public Key Length (bytes): %d\n", len(pubKeyBytes))
	fmt.Println()

	fmt.Printf("Uncompressed Public Key (65 bytes): 0x%s\n", hex.EncodeToString(uncompressedPubKey))
	fmt.Printf("Uncompressed without prefix (64 bytes): 0x%s\n", hex.EncodeToString(uncompressedPubKey[1:]))
	fmt.Println()

	fmt.Printf("Compressed Public Key (33 bytes): 0x%s\n", hex.EncodeToString(compressedPubKey))
	fmt.Println()

	fmt.Printf("X coordinate: 0x%064x\n", goEthPubKey.X)
	fmt.Printf("Y coordinate: 0x%064x\n", goEthPubKey.Y)
	fmt.Println()

	// Additional format that Web3Signer might use
	// Some signers expect the public key without the 0x04 prefix
	if len(pubKeyBytes) == 65 && pubKeyBytes[0] == 0x04 {
		fmt.Println("=== Alternative Formats ===")
		fmt.Printf("Without 0x04 prefix (64 bytes): 0x%s\n", hex.EncodeToString(pubKeyBytes[1:]))
	}

	// Check what the Bytes() method actually returns
	fmt.Println()
	fmt.Println("=== Debug: Bytes() Method Output ===")
	fmt.Printf("Raw hex from Bytes(): 0x%s\n", hex.EncodeToString(pubKeyBytes))
	fmt.Printf("First byte: 0x%02x\n", pubKeyBytes[0])

	// Compare with expected Web3Signer format
	fmt.Println()
	fmt.Println("=== Web3Signer Compatibility Check ===")
	fmt.Println("Web3Signer typically expects one of these formats:")
	fmt.Println("1. Uncompressed with 0x04 prefix (65 bytes)")
	fmt.Println("2. Uncompressed without prefix (64 bytes)")
	fmt.Println("3. Compressed (33 bytes)")
	fmt.Println()
	fmt.Println("If Web3Signer shows a different public key, please provide:")
	fmt.Println("- The exact public key shown by Web3Signer")
	fmt.Println("- The format/length of that public key")
}
