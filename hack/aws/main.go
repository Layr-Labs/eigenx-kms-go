package main

import (
	"context"
	"fmt"

	"github.com/Layr-Labs/eigenx-kms-go/internal/aws"
	"github.com/Layr-Labs/eigenx-kms-go/internal/keyGenerator/awsKms"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"go.uber.org/zap"
)

func main() {
	l, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	awsCfg, err := aws.LoadAWSConfig(context.Background(), "")
	if err != nil {
		panic(err)
	}
	_ = l
	_ = awsCfg

	cfg := &config.KMSServerConfig{
		ChainName: "dev",
	}

	keyGen := awsKms.NewAWSKMSKeyGenerator(awsCfg, "us-east-1", cfg, l)

	generatedKey, err := keyGen.GenerateECDSAKey(context.Background(), "eigenx-kms-preprod-sepolia-operator-0", "alias/eigenx-kms-preprod-sepolia-operator-0")
	if err != nil {
		l.Fatal("failed to generate ECDSA key", zap.Error(err))
	}
	fmt.Printf("Generated Key:    %+v\n", generatedKey.Address)
	fmt.Printf("Generated Key ID: %+v\n", generatedKey.KeyId)
}
