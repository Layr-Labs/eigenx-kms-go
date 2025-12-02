package main

import (
	"context"
	"os"

	"github.com/Layr-Labs/eigenx-kms-go/internal/aws"
	"github.com/Layr-Labs/eigenx-kms-go/internal/keyGenerator/awsKms"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
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

	pubKeyHex, err := generatedKey.GetPublicKeyHex()
	if err != nil {
		l.Sugar().Fatalw("failed to get public key hex", "error", err)
	}

	pubKeyHexUnprefixed, err := generatedKey.GetPublicKeyHexUnprefixed()
	if err != nil {
		l.Sugar().Fatalw("failed to get unprefixed public key hex", "error", err)
	}

	l.Sugar().Infow("Generated Key",
		"keyId", generatedKey.KeyId,
		"publicKeyHex", pubKeyHex,
		"publicKeyHexUnprefixed", pubKeyHexUnprefixed,
		"address", generatedKey.Address,
	)
}
