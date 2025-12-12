package transactionSigner

import (
	"context"
	"fmt"
	"math/big"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/web3signer"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"
)

// Web3TransactionSigner implements ITransactionSigner using Web3TransactionSigner service
type Web3TransactionSigner struct {
	ethClient        *ethclient.Client
	logger           *zap.Logger
	chainID          *big.Int
	web3SignerClient *web3signer.Client
	fromAddress      common.Address
}

// NewWeb3TransactionSigner creates a new Web3TransactionSigner
func NewWeb3TransactionSigner(web3SignerClient *web3signer.Client, fromAddress common.Address, ethClient *ethclient.Client, logger *zap.Logger) (*Web3TransactionSigner, error) {
	// Get chain ID during initialization
	chainID, err := ethClient.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %w", err)
	}

	return &Web3TransactionSigner{
		ethClient:        ethClient,
		logger:           logger,
		chainID:          chainID,
		web3SignerClient: web3SignerClient,
		fromAddress:      fromAddress,
	}, nil
}

// GetTransactOpts returns transaction options for creating unsigned transactions
func (w3s *Web3TransactionSigner) GetTransactOpts(ctx context.Context) (*bind.TransactOpts, error) {
	// We need to provide a Signer function that returns the transaction unsigned
	// The actual signing happens in SignAndSendTransaction via Web3TransactionSigner
	opts := &bind.TransactOpts{
		From:    w3s.fromAddress,
		Context: ctx,
		NoSend:  true,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			// Just return the transaction as-is without signing
			// The actual signing will happen in SignAndSendTransaction
			return tx, nil
		},
	}
	return opts, nil
}

// SignAndSendTransaction signs a transaction and sends it to the network
func (w3s *Web3TransactionSigner) SignAndSendTransaction(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
	var FallbackGasTipCap *big.Int
	var baseFeeMultiplier int64

	if !config.IsEthereum(config.ChainId(w3s.chainID.Uint64())) {
		FallbackGasTipCap = big.NewInt(1500000000) // 1.5 gwei for Ethereum
		baseFeeMultiplier = 3                      // 3x buffer for Ethereum
	} else {
		FallbackGasTipCap = big.NewInt(1000000) // 0.001 gwei for Base
		baseFeeMultiplier = 2                   // 2x buffer for Base
	}

	// Estimate gas tip cap (priority fee)
	gasTipCap, err := w3s.ethClient.SuggestGasTipCap(ctx)
	if err != nil {
		// If the transaction failed because the backend does not support
		// eth_maxPriorityFeePerGas, fallback to using the default constant.
		w3s.logger.Sugar().Warnw("SignAndSendTransaction: cannot get gasTipCap, using fallback",
			zap.Error(err),
		)
		gasTipCap = FallbackGasTipCap
	}

	// Get the latest block header for base fee calculation
	header, err := w3s.ethClient.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block header: %w", err)
	}

	// Calculate max fee per gas: basefee * 2 + tip
	// Using 2x multiplier for buffer since Base fees can spike
	maxFeePerGas := new(big.Int).Add(
		new(big.Int).Mul(header.BaseFee, big.NewInt(baseFeeMultiplier)),
		gasTipCap,
	)

	// Estimate gas limit with proper parameters
	gasLimit, err := w3s.ethClient.EstimateGas(ctx, ethereum.CallMsg{
		From:      w3s.fromAddress,
		To:        tx.To(),
		GasTipCap: gasTipCap,
		GasFeeCap: maxFeePerGas,
		Value:     tx.Value(),
		Data:      tx.Data(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to estimate gas: %w", err)
	}

	// Add 20% buffer to gas limit
	gasLimitWithBuffer := addGasBuffer(gasLimit)

	// Get nonce - always fetch from the network since the incoming tx.Nonce() may be 0
	// which is a valid nonce value and we can't distinguish between "no nonce set" and "nonce is 0"
	nonce, err := w3s.ethClient.PendingNonceAt(ctx, w3s.fromAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}

	// Convert transaction to Web3Signer format with EIP-1559 parameters
	txData := map[string]interface{}{
		"to":                   tx.To().Hex(),
		"value":                hexutil.EncodeBig(tx.Value()),
		"gas":                  hexutil.EncodeUint64(gasLimitWithBuffer),
		"maxPriorityFeePerGas": hexutil.EncodeBig(gasTipCap),
		"maxFeePerGas":         hexutil.EncodeBig(maxFeePerGas),
		"nonce":                hexutil.EncodeUint64(nonce),
		"data":                 hexutil.Encode(tx.Data()),
		"type":                 "0x2", // EIP-1559 transaction type
		"chainId":              hexutil.EncodeUint64(w3s.chainID.Uint64()),
	}

	w3s.logger.Info("SignAndSendTransaction: sending transaction",
		zap.String("to", tx.To().Hex()),
		zap.String("maxPriorityFeePerGas", gasTipCap.String()),
		zap.String("maxFeePerGas", maxFeePerGas.String()),
		zap.String("baseFee", header.BaseFee.String()),
		zap.Uint64("gasLimit", gasLimitWithBuffer),
		zap.Uint64("nonce", nonce),
	)

	// Sign with Web3Signer
	signedTxHex, err := w3s.web3SignerClient.EthSignTransaction(ctx, w3s.fromAddress.Hex(), txData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction with Web3Signer: %w", err)
	}

	// Parse signed transaction
	signedTxBytes, err := hexutil.Decode(signedTxHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signed transaction: %w", err)
	}

	var signedTx types.Transaction
	err = signedTx.UnmarshalBinary(signedTxBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed transaction: %w", err)
	}

	// Send the transaction
	err = w3s.ethClient.SendTransaction(ctx, &signedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %w", err)
	}

	w3s.logger.Info("SignAndSendTransaction: transaction sent",
		zap.String("txHash", signedTx.Hash().Hex()),
	)

	// Verify the transaction is in the mempool
	_, isPending, err := w3s.ethClient.TransactionByHash(ctx, signedTx.Hash())
	if err != nil {
		w3s.logger.Warn("Could not verify transaction in mempool",
			zap.Error(err),
			zap.String("txHash", signedTx.Hash().Hex()),
		)
	} else {
		w3s.logger.Info("Transaction verified in mempool",
			zap.Bool("isPending", isPending),
			zap.String("txHash", signedTx.Hash().Hex()),
		)
	}

	// Wait for receipt and check status
	receipt, err := bind.WaitMined(ctx, w3s.ethClient, &signedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for transaction receipt: %w", err)
	}

	// Check transaction status
	if receipt.Status != 1 {
		w3s.logger.Error("SignAndSendTransaction: transaction failed",
			zap.String("txHash", receipt.TxHash.Hex()),
			zap.Uint64("status", receipt.Status),
			zap.Uint64("gasUsed", receipt.GasUsed),
		)
		return nil, fmt.Errorf("transaction failed with status %d", receipt.Status)
	}

	w3s.logger.Info("SignAndSendTransaction: transaction succeeded",
		zap.String("txHash", receipt.TxHash.Hex()),
		zap.Uint64("gasUsed", receipt.GasUsed),
		zap.Uint64("blockNumber", receipt.BlockNumber.Uint64()),
	)

	return receipt, nil
}

// GetFromAddress returns the address that will be used for signing
func (w3s *Web3TransactionSigner) GetFromAddress() common.Address {
	return w3s.fromAddress
}

// EstimateGasPriceAndLimit estimates gas price and limit for a transaction
func (w3s *Web3TransactionSigner) EstimateGasPriceAndLimit(ctx context.Context, tx *types.Transaction) (*big.Int, uint64, error) {
	// For now, return nil values - this method isn't fully implemented yet
	return nil, 0, nil
}
