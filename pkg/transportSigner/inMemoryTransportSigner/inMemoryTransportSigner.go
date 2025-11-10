package inMemoryTransportSigner

import (
	"fmt"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	"github.com/Layr-Labs/crypto-libs/pkg/signing"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner"
	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"
)

type InMemoryTransportSigner struct {
	logger     *zap.Logger
	privateKey signing.PrivateKey
	curveType  config.CurveType
}

func NewBn254InMemoryTransportSigner(
	privateKey []byte,
	logger *zap.Logger,
) (*InMemoryTransportSigner, error) {
	scheme := bn254.NewScheme()
	key, err := scheme.NewPrivateKeyFromBytes(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error loading private key: %w", err)
	}

	return NewInMemoryTransportSigner(key, config.CurveTypeBN254, logger), nil
}

func NewECDSAInMemoryTransportSigner(
	privateKey []byte,
	logger *zap.Logger,
) (*InMemoryTransportSigner, error) {
	scheme := ecdsa.NewScheme()
	key, err := scheme.NewPrivateKeyFromBytes(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error loading private key: %w", err)
	}

	return NewInMemoryTransportSigner(key, config.CurveTypeECDSA, logger), nil
}

func NewInMemoryTransportSigner(
	key signing.PrivateKey,
	curveType config.CurveType,
	logger *zap.Logger,
) *InMemoryTransportSigner {
	return &InMemoryTransportSigner{
		logger:     logger,
		privateKey: key,
		curveType:  curveType,
	}
}

func (its *InMemoryTransportSigner) signBN254Message(hash [32]byte) (*bn254.Signature, error) {
	pkBytes := its.privateKey.Bytes()
	bn254Key, err := bn254.NewPrivateKeyFromBytes(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create BN254 private key: %w", err)
	}

	sig, err := bn254Key.SignSolidityCompatible(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message with BN254 key: %w", err)
	}
	return sig, nil
}

func (its *InMemoryTransportSigner) CreateAuthenticatedMessage(data []byte) (*transportSigner.SignedMessage, error) {
	hash := crypto.Keccak256Hash(data)

	var sigBytes []byte
	if its.curveType == config.CurveTypeBN254 {
		// the BN254 library's .Sign() function doesnt currently use the solidity-compatible signing,
		// so we cant use the generic scheme.Sign() interface
		sig, err := its.signBN254Message(hash)
		if err != nil {
			return nil, fmt.Errorf("failed to sign message with BN254 key: %w", err)
		}
		sigBytes = sig.Bytes()
	} else {
		sig, err := its.privateKey.Sign(hash.Bytes())
		if err != nil {
			return nil, fmt.Errorf("failed to sign message: %w", err)
		}
		sigBytes = sig.Bytes()
	}

	return &transportSigner.SignedMessage{
		Payload:   data,
		Signature: sigBytes,
		Hash:      hash,
	}, nil
}
