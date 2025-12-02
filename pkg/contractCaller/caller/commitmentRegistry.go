package caller

import (
	"context"
	"fmt"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/middleware-bindings/EigenKMSCommitmentRegistry"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// SubmitCommitment submits a commitment hash and ack merkle root to the registry contract
func (c *ContractCaller) SubmitCommitment(
	ctx context.Context,
	registryAddress common.Address,
	epoch int64,
	commitmentHash [32]byte,
	ackMerkleRoot [32]byte,
) (*types.Receipt, error) {
	// Create contract instance
	registry, err := EigenKMSCommitmentRegistry.NewEigenKMSCommitmentRegistry(registryAddress, c.ethclient)
	if err != nil {
		return nil, fmt.Errorf("failed to create commitment registry instance: %w", err)
	}

	// Get transaction options
	opts, err := c.signer.GetTransactOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction options: %w", err)
	}

	// Submit commitment
	tx, err := registry.SubmitCommitment(opts, uint64(epoch), commitmentHash, ackMerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to submit commitment: %w", err)
	}

	// Wait for receipt
	receipt, err := bind.WaitMined(ctx, c.ethclient, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for transaction: %w", err)
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, fmt.Errorf("transaction failed with status %d", receipt.Status)
	}

	c.logger.Sugar().Infow("Submitted commitment to registry",
		"epoch", epoch,
		"commitmentHash", common.Bytes2Hex(commitmentHash[:]),
		"ackMerkleRoot", common.Bytes2Hex(ackMerkleRoot[:]),
		"txHash", tx.Hash().Hex(),
	)

	return receipt, nil
}

// GetCommitment queries commitment data from the registry contract
func (c *ContractCaller) GetCommitment(
	ctx context.Context,
	registryAddress common.Address,
	epoch int64,
	operator common.Address,
) (commitmentHash [32]byte, ackMerkleRoot [32]byte, submittedAt uint64, err error) {
	// Create contract instance
	registry, err := EigenKMSCommitmentRegistry.NewEigenKMSCommitmentRegistry(registryAddress, c.ethclient)
	if err != nil {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("failed to create commitment registry instance: %w", err)
	}

	// Query commitment
	commitment, err := registry.GetCommitment(&bind.CallOpts{Context: ctx}, uint64(epoch), operator)
	if err != nil {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("failed to get commitment: %w", err)
	}

	return commitment.CommitmentHash, commitment.AckMerkleRoot, commitment.SubmittedAt.Uint64(), nil
}
