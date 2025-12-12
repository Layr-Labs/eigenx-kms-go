package main

import (
	"fmt"

	"github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/web3signer"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/inMemoryTransportSigner"
	web3Signer "github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/web3TransportSigner"
	"github.com/ethereum/go-ethereum/common"
)

func main() {
	l, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	rootPath := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(rootPath)
	if err != nil {
		l.Sugar().Fatalf("failed to read chain config: %v", err)
	}

	address := chainConfig.OperatorAccountAddress1
	pubKey := chainConfig.OperatorAccountPublicKey1
	privateKeyStr := chainConfig.OperatorAccountPrivateKey1

	privateKey, err := ecdsa.NewPrivateKeyFromHexString(privateKeyStr)
	if err != nil {
		l.Sugar().Fatalf("failed to parse private key: %v", err)
	}

	pkSigner := inMemoryTransportSigner.NewInMemoryTransportSigner(privateKey, config.CurveTypeECDSA, l)

	signerCfg := &config.RemoteSignerConfig{
		Url:         "http://localhost:9100",
		FromAddress: address,
		PublicKey:   pubKey,
	}

	web3SignerClient, err := web3signer.NewWeb3SignerClientFromRemoteSignerConfig(signerCfg, l)
	if err != nil {
		l.Sugar().Fatalw("failed to create Web3Signer client", "error", err)
	}

	web3TransportSigner, err := web3Signer.NewWeb3TransportSigner(web3SignerClient, common.HexToAddress(address), pubKey, config.CurveTypeECDSA, l)
	if err != nil {
		l.Sugar().Fatalw("failed to create Web3Signer transport signer", "error", err)
	}

	message := []byte("Hello, Web3Signer!")

	signatureWeb3, err := web3TransportSigner.SignMessage(message)
	if err != nil {
		l.Sugar().Fatalw("failed to sign message with Web3Signer", "error", err)
	}

	signaturePK, err := pkSigner.SignMessage(message)
	if err != nil {
		l.Sugar().Fatalw("failed to sign message with private key signer", "error", err)
	}

	fmt.Printf("Message: %s\n", message)
	fmt.Printf("Signature (Web3Signer):  %s\n", common.Bytes2Hex(signatureWeb3))
	fmt.Printf("Signature (Private Key): %s\n", common.Bytes2Hex(signaturePK))

	if common.Bytes2Hex(signatureWeb3) == common.Bytes2Hex(signaturePK) {
		fmt.Println("Signatures match!")
	} else {
		fmt.Println("Signatures do not match!")
	}
}
