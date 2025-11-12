package inMemoryTransportSigner

import (
	"fmt"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner"
	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"
)

type InMemoryTransportSigner struct {
	logger     *zap.Logger
	privateKey interface{}
	curveType  config.CurveType
}

func NewBn254InMemoryTransportSigner(
	privateKey []byte,
	logger *zap.Logger,
) (*InMemoryTransportSigner, error) {
	key, err := bn254.NewPrivateKeyFromBytes(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error loading private key: %w", err)
	}

	return NewInMemoryTransportSigner(key, config.CurveTypeBN254, logger), nil
}

func NewECDSAInMemoryTransportSigner(
	privateKey []byte,
	logger *zap.Logger,
) (*InMemoryTransportSigner, error) {
	key, err := ecdsa.NewPrivateKeyFromBytes(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error loading private key: %w", err)
	}

	return NewInMemoryTransportSigner(key, config.CurveTypeECDSA, logger), nil
}

func NewInMemoryTransportSigner(
	key interface{},
	curveType config.CurveType,
	logger *zap.Logger,
) *InMemoryTransportSigner {
	return &InMemoryTransportSigner{
		logger:     logger,
		privateKey: key,
		curveType:  curveType,
	}
}

// data is the raw message bytes to sign
func (its *InMemoryTransportSigner) SignMessage(data []byte) ([]byte, error) {
	var sigBytes []byte
	hashedData := crypto.Keccak256Hash(data)
	if its.curveType == config.CurveTypeBN254 {
		pk := its.privateKey.(*bn254.PrivateKey)
		sig, err := pk.SignSolidityCompatible(hashedData)
		if err != nil {
			return nil, err
		}
		return sig.Bytes(), nil
	}
	if its.curveType == config.CurveTypeECDSA {
		pk := its.privateKey.(*ecdsa.PrivateKey)
		sig, err := pk.Sign(hashedData[:])
		if err != nil {
			return nil, err
		}
		return sig.Bytes(), nil
	}
	return sigBytes, nil
}

func (its *InMemoryTransportSigner) CreateAuthenticatedMessage(data []byte) (*transportSigner.SignedMessage, error) {
	hash := crypto.Keccak256Hash(data)

	sigBytes, err := its.SignMessage(data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign authenticated message: %w", err)
	}

	return &transportSigner.SignedMessage{
		Payload:   data,
		Signature: sigBytes,
		Hash:      hash,
	}, nil
}
