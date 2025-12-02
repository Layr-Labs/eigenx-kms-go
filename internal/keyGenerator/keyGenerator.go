package keyGenerator

import (
	"context"
	"fmt"
	"github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type GeneratedECDSAKey struct {
	PublicKey *ecdsa.PublicKey
	Address   string
	KeyId     string
}

func (gek *GeneratedECDSAKey) GetPublicKeyBytes() ([]byte, error) {
	if gek.PublicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	return gek.PublicKey.Bytes(), nil
}

func (gek *GeneratedECDSAKey) GetPublicKeyHex() (string, error) {
	pubKeyBytes, err := gek.GetPublicKeyBytes()
	if err != nil {
		return "", fmt.Errorf("failed to get public key bytes: %w", err)
	}
	return hexutil.Encode(pubKeyBytes), nil
}

// GetPublicKeyBytesUnprefixed returns the public key without the 0x04 prefix (64 bytes)
// This format is used by Web3Signer
func (gek *GeneratedECDSAKey) GetPublicKeyBytesUnprefixed() ([]byte, error) {
	pubKeyBytes, err := gek.GetPublicKeyBytes()
	if err != nil {
		return nil, err
	}

	// Remove the 0x04 prefix if present
	if len(pubKeyBytes) == 65 && pubKeyBytes[0] == 0x04 {
		return pubKeyBytes[1:], nil
	}

	// If it's already 64 bytes, return as is
	if len(pubKeyBytes) == 64 {
		return pubKeyBytes, nil
	}

	return nil, fmt.Errorf("unexpected public key length: %d", len(pubKeyBytes))
}

// GetPublicKeyHexUnprefixed returns the public key hex without the 0x04 prefix
// This format is used by Web3Signer
func (gek *GeneratedECDSAKey) GetPublicKeyHexUnprefixed() (string, error) {
	pubKeyBytes, err := gek.GetPublicKeyBytesUnprefixed()
	if err != nil {
		return "", fmt.Errorf("failed to get unprefixed public key bytes: %w", err)
	}
	return hexutil.Encode(pubKeyBytes), nil
}

type IKeyGenerator interface {
	GenerateECDSAKey(ctx context.Context, keyName string, aliasName string) (*GeneratedECDSAKey, error)
	GetECDSAKeyById(ctx context.Context, keyId string) (*GeneratedECDSAKey, error)
	SignMessage(ctx context.Context, keyId string, message []byte) ([]byte, error)
}
