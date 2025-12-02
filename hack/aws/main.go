package main

import (
	"context"

	"github.com/Layr-Labs/eigenx-kms-go/internal/aws"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
)

func main() {
	l, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})
	awsCfg, err := aws.LoadAWSConfig(context.Background(), "")
	if err != nil {
		panic(err)
	}
	_ = l
	_ = awsCfg

	/*keyGen := awsKms.NewAWSKMSKeyGenerator(l, awsCfg, "us-east-1")

	generatedKey, err := keyGen.GenerateECDSAKey(context.Background(), "test-key", "alias/test-key")
	if err != nil {
		l.Fatal("failed to generate ECDSA key", zap.Error(err))
	}
	fmt.Printf("Generated Key: %+v\n")*/
}
