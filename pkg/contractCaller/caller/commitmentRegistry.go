package caller

import (
	"context"
	"fmt"
	"math/big"

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

	// Build transaction options
	txOpts, err := c.buildTransactionOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction options: %w", err)
	}

	// Create transaction
	tx, err := registry.SubmitCommitment(txOpts, uint64(epoch), commitmentHash, ackMerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	c.logger.Sugar().Infow("Submitting commitment to registry",
		"epoch", epoch,
		"commitmentHash", common.Bytes2Hex(commitmentHash[:]),
		"ackMerkleRoot", common.Bytes2Hex(ackMerkleRoot[:]),
	)

	// Sign, send, and wait for transaction
	return c.signAndSendTransaction(ctx, tx, "SubmitCommitment")
}

// GetCommitment queries commitment data from the registry contract at chain head.
func (c *ContractCaller) GetCommitment(
	ctx context.Context,
	registryAddress common.Address,
	epoch int64,
	operator common.Address,
) (commitmentHash [32]byte, ackMerkleRoot [32]byte, submittedAt uint64, err error) {
	return c.GetCommitmentAt(ctx, registryAddress, epoch, operator, 0)
}

// GetCommitmentAt queries commitment data as-of a specific block height. blockNumber
// == 0 reads at chain head. Pinning the height lets all operators read the registry at
// the same point so they derive an identical reshare dealer set
// (docs/011_reshareDealerSetAgreement.md).
func (c *ContractCaller) GetCommitmentAt(
	ctx context.Context,
	registryAddress common.Address,
	epoch int64,
	operator common.Address,
	blockNumber uint64,
) (commitmentHash [32]byte, ackMerkleRoot [32]byte, submittedAt uint64, err error) {
	// Create contract instance
	registry, err := EigenKMSCommitmentRegistry.NewEigenKMSCommitmentRegistry(registryAddress, c.ethclient)
	if err != nil {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("failed to create commitment registry instance: %w", err)
	}

	callOpts := &bind.CallOpts{Context: ctx}
	if blockNumber != 0 {
		callOpts.BlockNumber = new(big.Int).SetUint64(blockNumber)
	}

	commitment, err := registry.GetCommitment(callOpts, uint64(epoch), operator)
	if err != nil {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("failed to get commitment: %w", err)
	}

	return commitment.CommitmentHash, commitment.AckMerkleRoot, commitment.SubmittedAt.Uint64(), nil
}
