package awsKms

import (
	"context"
	cryptoEcdsa "crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	"github.com/Layr-Labs/eigenx-kms-go/internal/keyGenerator"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"math/big"
)

type AWSKMSKeyGenerator struct {
	logger       *zap.Logger
	awsConfig    aws.Config
	kmsClient    *kms.Client
	awsRegion    string
	globalConfig *config.KMSServerConfig
}

func NewAWSKMSKeyGenerator(awsCfg aws.Config, awsRegion string, cfg *config.KMSServerConfig, logger *zap.Logger) *AWSKMSKeyGenerator {
	kmsClient := kms.NewFromConfig(awsCfg)

	return &AWSKMSKeyGenerator{
		logger:       logger,
		awsConfig:    awsCfg,
		kmsClient:    kmsClient,
		awsRegion:    awsRegion,
		globalConfig: cfg,
	}
}

func (a *AWSKMSKeyGenerator) SignMessage(ctx context.Context, keyId string, message []byte) ([]byte, error) {
	return a.getSignatureFromKms(ctx, keyId, message)
}

func (a *AWSKMSKeyGenerator) GenerateECDSAKey(ctx context.Context, keyName string, aliasName string) (*keyGenerator.GeneratedECDSAKey, error) {
	keyRes, err := a.createEthereumSigningKey(ctx, keyName, string(a.globalConfig.ChainName))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create ECDSA key %s in region %s", keyName, a.awsRegion)
	}

	err = a.createKeyAlias(ctx, *keyRes.KeyMetadata.KeyId, aliasName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create alias %s for key %s in region %s", aliasName, *keyRes.KeyMetadata.KeyId, a.awsRegion)
	}

	return a.GetECDSAKeyById(ctx, *keyRes.KeyMetadata.KeyId)
}

func (a *AWSKMSKeyGenerator) GetECDSAKeyById(ctx context.Context, keyId string) (*keyGenerator.GeneratedECDSAKey, error) {
	kmsPubKey, err := a.getPublicKey(ctx, keyId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get public key for key %s in region %s", keyId, a.awsRegion)
	}

	ecdsaPubKey, err := parseECDSAPublicKey(kmsPubKey.PublicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse public key for key %s in region %s", keyId, a.awsRegion)
	}

	pk := &ecdsa.PublicKey{
		X: ecdsaPubKey.X,
		Y: ecdsaPubKey.Y,
	}

	addr, err := pk.DeriveAddress()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to derive Ethereum address from public key for key %s in region %s", keyId, a.awsRegion)
	}

	return &keyGenerator.GeneratedECDSAKey{
		PublicKey: pk,
		Address:   addr.String(),
		KeyId:     keyId,
	}, nil
}

// createEthereumSigningKey creates an ECDSA key suitable for Ethereum transaction signing
func (k *AWSKMSKeyGenerator) createEthereumSigningKey(ctx context.Context, keyName, environment string) (*kms.CreateKeyOutput, error) {
	// Create the KMS key with ECDSA_SECP256K1 spec (required for Ethereum)
	input := &kms.CreateKeyInput{
		KeyUsage:    types.KeyUsageTypeSignVerify,
		KeySpec:     types.KeySpecEccSecgP256k1, // secp256k1 curve used by Ethereum
		Description: aws.String(fmt.Sprintf("ECDSA key for Ethereum transaction signing - %s", keyName)),
		Tags: []types.Tag{
			{
				TagKey:   aws.String("Name"),
				TagValue: aws.String(keyName),
			},
			{
				TagKey:   aws.String("Environment"),
				TagValue: aws.String(environment),
			},
			{
				TagKey:   aws.String("Purpose"),
				TagValue: aws.String("signing-key"),
			},
			{
				TagKey:   aws.String("KeyType"),
				TagValue: aws.String("ECDSA"),
			},
			{
				TagKey:   aws.String("Curve"),
				TagValue: aws.String("secp256k1"),
			},
			{
				TagKey:   aws.String("EigenCompute"),
				TagValue: aws.String("true"),
			},
		},
	}

	result, err := k.kmsClient.CreateKey(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS key: %w", err)
	}

	return result, nil
}

// createKeyAlias creates an alias for the KMS key for easier reference
func (k *AWSKMSKeyGenerator) createKeyAlias(ctx context.Context, keyId, aliasName string) error {
	input := &kms.CreateAliasInput{
		AliasName:   aws.String(fmt.Sprintf("alias/%s", aliasName)),
		TargetKeyId: aws.String(keyId),
	}

	_, err := k.kmsClient.CreateAlias(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create key alias: %w", err)
	}

	fmt.Printf("Successfully created alias: alias/%s\n", aliasName)
	return nil
}

// getPublicKey retrieves the public key for verification
func (k *AWSKMSKeyGenerator) getPublicKey(ctx context.Context, keyId string) (*kms.GetPublicKeyOutput, error) {
	input := &kms.GetPublicKeyInput{
		KeyId: aws.String(keyId),
	}

	result, err := k.kmsClient.GetPublicKey(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	return result, nil
}

// parseECDSAPublicKey parses the DER-encoded public key from KMS
func parseECDSAPublicKey(derBytes []byte) (*cryptoEcdsa.PublicKey, error) {
	var asn1pubk asn1EcPublicKey
	_, err := asn1.Unmarshal(derBytes, &asn1pubk)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ASN.1 public key: %w", err)
	}

	return crypto.UnmarshalPubkey(asn1pubk.PublicKey.Bytes)
}

// ASN.1 structures matching the reference implementation
type asn1EcSig struct {
	R asn1.RawValue
	S asn1.RawValue
}

type asn1EcPublicKey struct {
	EcPublicKeyInfo asn1EcPublicKeyInfo
	PublicKey       asn1.BitString
}

type asn1EcPublicKeyInfo struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

func (k *AWSKMSKeyGenerator) getSignatureFromKms(ctx context.Context, keyId string, txHashBytes []byte) ([]byte, error) {
	// Validate input hash length
	if len(txHashBytes) != 32 {
		return nil, fmt.Errorf("hash must be exactly 32 bytes, got %d", len(txHashBytes))
	}

	// Get the expected public key from KMS first
	kmsPubKey, err := k.getPublicKey(ctx, keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	expectedPubKey, err := parseECDSAPublicKey(kmsPubKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	signInput := &kms.SignInput{
		KeyId:            aws.String(keyId),
		Message:          txHashBytes,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
		MessageType:      types.MessageTypeDigest,
	}

	signOutput, err := k.kmsClient.Sign(ctx, signInput)
	if err != nil {
		return nil, err
	}

	var sigAsn1 asn1EcSig
	_, err = asn1.Unmarshal(signOutput.Signature, &sigAsn1)
	if err != nil {
		return nil, err
	}

	// Convert raw bytes to big.Int
	r := new(big.Int).SetBytes(sigAsn1.R.Bytes)
	s := new(big.Int).SetBytes(sigAsn1.S.Bytes)

	// secp256k1 curve order for malleability protection
	curveOrder, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	halfOrder := new(big.Int).Rsh(curveOrder, 1)

	// Apply malleability protection (low-S canonicalization)
	if s.Cmp(halfOrder) > 0 {
		s = new(big.Int).Sub(curveOrder, s)
	}

	// Convert to 32-byte arrays
	rBytes := r.FillBytes(make([]byte, 32))
	sBytes := s.FillBytes(make([]byte, 32))

	// Try recovery IDs 0-3 (crypto.Ecrecover expects 0-3, not 27-28)
	for recoveryId := 0; recoveryId < 4; recoveryId++ {
		// Create signature with recovery ID for crypto.Ecrecover (0-3 range)
		signature := make([]byte, 65)
		copy(signature[0:32], rBytes)
		copy(signature[32:64], sBytes)
		signature[64] = byte(recoveryId) // Use 0-3 for crypto.Ecrecover

		// Test recovery with crypto.Ecrecover
		recoveredPubKeyBytes, err := crypto.Ecrecover(txHashBytes, signature)
		if err != nil {
			k.logger.Debug("Ecrecover failed",
				zap.Int("recoveryId", recoveryId),
				zap.Error(err))
			continue
		}

		// Convert recovered public key bytes to *ecdsa.PublicKey
		recoveredPubKey, err := crypto.UnmarshalPubkey(recoveredPubKeyBytes)
		if err != nil {
			k.logger.Warn("Failed to unmarshal recovered public key",
				zap.Int("recoveryId", recoveryId),
				zap.Error(err))
			continue
		}

		// Compare with expected public key
		if recoveredPubKey.X.Cmp(expectedPubKey.X) == 0 && recoveredPubKey.Y.Cmp(expectedPubKey.Y) == 0 {
			// Convert to Ethereum format (27+ for final signature)
			finalSignature := make([]byte, 65)
			copy(finalSignature[0:32], rBytes)
			copy(finalSignature[32:64], sBytes)
			finalSignature[64] = byte(27 + recoveryId) // Convert to Ethereum format (27+)

			return finalSignature, nil
		}
	}

	return nil, fmt.Errorf("could not determine valid recovery ID - signature recovery failed")
}
