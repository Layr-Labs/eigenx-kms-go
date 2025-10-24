package transactionSigner

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"
)

// ITransactionSigner provides methods for signing Ethereum transactions
type ITransactionSigner interface {
	// GetTransactOpts returns transaction options for creating unsigned transactions
	GetTransactOpts(ctx context.Context) (*bind.TransactOpts, error)

	// SignAndSendTransaction signs a transaction and sends it to the network
	SignAndSendTransaction(ctx context.Context, tx *types.Transaction) (*types.Receipt, error)

	// GetFromAddress returns the address that will be used for signing
	GetFromAddress() common.Address

	// EstimateGasPriceAndLimit estimates gas price and limit for a transaction
	EstimateGasPriceAndLimit(ctx context.Context, tx *types.Transaction) (*big.Int, uint64, error)
}

type SignerConfig struct {
	PrivateKey string `json:"privateKey" yaml:"privateKey"`
}

func NewTransactionSigner(cfg *SignerConfig, ethClient *ethclient.Client, logger *zap.Logger) (ITransactionSigner, error) {
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("private key cannot be empty")
	}

	return NewPrivateKeySigner(cfg.PrivateKey, ethClient, logger)
}
