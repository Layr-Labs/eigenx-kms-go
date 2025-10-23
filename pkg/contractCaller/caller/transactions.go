package caller

import (
	"context"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethereumTypes "github.com/ethereum/go-ethereum/core/types"
	"go.uber.org/zap"
)

func (cc *ContractCaller) buildTransactionOpts(ctx context.Context) (*bind.TransactOpts, error) {
	return cc.signer.GetTransactOpts(ctx)
}

func (cc *ContractCaller) signAndSendTransaction(ctx context.Context, tx *ethereumTypes.Transaction, operation string) (*ethereumTypes.Receipt, error) {
	cc.logger.Sugar().Infow("Signing and sending transaction",
		zap.String("operation", operation),
		zap.String("from", cc.signer.GetFromAddress().Hex()),
		zap.String("to", tx.To().Hex()),
	)

	return cc.signer.SignAndSendTransaction(ctx, tx)
}
