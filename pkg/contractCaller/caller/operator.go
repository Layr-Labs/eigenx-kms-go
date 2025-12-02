package caller

import (
	"context"
	"fmt"

	"github.com/Layr-Labs/eigenlayer-contracts/pkg/bindings/IAllocationManager"
	"github.com/Layr-Labs/eigenlayer-contracts/pkg/bindings/IKeyRegistrar"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/middleware-bindings/IEigenKMSRegistrar"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (cc *ContractCaller) AcceptPendingAdmin(ctx context.Context, adminFor common.Address) (interface{}, error) {
	txOpts, err := cc.buildTransactionOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction options: %w", err)
	}

	tx, err := cc.permissionController.AcceptAdmin(txOpts, adminFor)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction for accepting pending admin for %s: %w", adminFor.Hex(), err)
	}

	return cc.signAndSendTransaction(ctx, tx, "AcceptPendingAdmin")
}

func (cc *ContractCaller) DeRegisterKey(
	ctx context.Context,
	operatorAddress common.Address,
	avsAddress common.Address,
	operatorSetId uint32,
) (*types.Receipt, error) {
	cc.logger.Sugar().Infow("Deregistering key for operator",
		zap.String("operatorAddress", operatorAddress.String()),
		zap.String("avsAddress", avsAddress.String()),
		zap.Uint32("operatorSetId", operatorSetId),
	)
	txOpts, err := cc.buildTransactionOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction options: %w", err)
	}

	tx, err := cc.keyRegistrar.DeregisterKey(txOpts, operatorAddress, IKeyRegistrar.OperatorSet{
		Avs: avsAddress,
		Id:  operatorSetId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction for deregistering key for operator %s in AVS %s and operator set ID %d: %w", operatorAddress.Hex(), avsAddress.Hex(), operatorSetId, err)
	}

	return cc.signAndSendTransaction(ctx, tx, "DeRegisterKey")
}

func (cc *ContractCaller) ModifyAllocations(
	ctx context.Context,
	operatorAddress common.Address,
	avsAddress common.Address,
	operatorSetId uint32,
	strategy common.Address,
	allocation uint64,
) (interface{}, error) {
	cc.logger.Sugar().Infow("Modifying allocations",
		zap.String("operatorAddress", operatorAddress.String()),
		zap.String("avsAddress", avsAddress.String()),
		zap.Uint32("operatorSetId", operatorSetId),
		zap.String("strategy", strategy.String()),
	)
	alloactionDelay, err := cc.allocationManager.GetAllocationDelay(&bind.CallOpts{}, operatorAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get allocation delay: %w", err)
	}
	cc.logger.Sugar().Infow("allocation delay:",
		zap.Any("allocationDelay", alloactionDelay),
		zap.String("operatorAddress", operatorAddress.String()),
	)

	txOpts, err := cc.buildTransactionOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction options: %w", err)
	}

	tx, err := cc.allocationManager.ModifyAllocations(txOpts, operatorAddress, []IAllocationManager.IAllocationManagerTypesAllocateParams{
		{
			OperatorSet: IAllocationManager.OperatorSet{
				Avs: avsAddress,
				Id:  operatorSetId,
			},
			Strategies:    []common.Address{strategy},
			NewMagnitudes: []uint64{allocation},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}
	return cc.signAndSendTransaction(ctx, tx, "ModifyAllocations")
}

func callOptsWithContext(ctx context.Context) *bind.CallOpts {
	return &bind.CallOpts{
		Context: ctx,
	}
}

func (cc *ContractCaller) GetAvsRegistrar(ctx context.Context, avsAddress common.Address) (common.Address, error) {
	return cc.allocationManager.GetAVSRegistrar(callOptsWithContext(ctx), avsAddress)
}

func (cc *ContractCaller) UpdateOperatorSocketForAvs(
	ctx context.Context,
	operatorAddress common.Address,
	avsAddress common.Address,
	encodedSocket string,
) (*types.Receipt, error) {
	cc.logger.Sugar().Infow("Updating operator socket for AVS",
		zap.String("operatorAddress", operatorAddress.String()),
		zap.String("avsAddress", avsAddress.String()),
		zap.String("encodedSocket", encodedSocket),
	)

	avsRegistrarAddr, err := cc.GetAvsRegistrar(ctx, avsAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get AVS registrar for address %s: %w", avsAddress.Hex(), err)
	}
	if avsRegistrarAddr == (common.Address{}) {
		return nil, fmt.Errorf("AVS registrar not found for address %s", avsAddress.Hex())
	}

	cc.logger.Sugar().Infow("AVS registrar address",
		zap.String("avsRegistrarAddress", avsRegistrarAddr.Hex()),
	)

	avsRegistrar, err := IEigenKMSRegistrar.NewIEigenKMSRegistrar(avsRegistrarAddr, cc.ethclient)
	if err != nil {
		return nil, fmt.Errorf("failed to create AVS registrar contract instance for address %s: %w", avsAddress.Hex(), err)
	}

	txOpts, err := cc.buildTransactionOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction options: %w", err)
	}

	cc.logger.Sugar().Infow("Creating transaction to update operator socket for AVS",
		zap.String("operatorAddress", operatorAddress.String()),
		zap.String("avsAddress", avsAddress.String()),
		zap.String("encodedSocket", encodedSocket),
	)
	tx, err := avsRegistrar.UpdateSocket(txOpts, operatorAddress, encodedSocket)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction for updating operator socket for AVS %s: %w", avsAddress.Hex(), err)
	}

	return cc.signAndSendTransaction(ctx, tx, "UpdateOperatorSocketForAvs")
}

func (cc *ContractCaller) RegisterKeyWithOperatorSet(
	ctx context.Context,
	operatorAddress common.Address,
	avsAddress common.Address,
	operatorSetId uint32,
	keyData []byte,
	sigBytes []byte,
) (*types.Receipt, error) {
	txOpts, err := cc.buildTransactionOpts(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build transaction options")
	}

	fmt.Printf("Transaction options: %+v\n", txOpts)
	tx, err := cc.keyRegistrar.RegisterKey(
		txOpts,
		operatorAddress,
		IKeyRegistrar.OperatorSet{
			Avs: avsAddress,
			Id:  operatorSetId,
		},
		keyData,
		sigBytes,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create transaction for key registration for operator %s in AVS %s and operator set ID %d", operatorAddress.Hex(), avsAddress.Hex(), operatorSetId)
	}
	return cc.signAndSendTransaction(ctx, tx, "RegisterKeyWithOperatorSet")
}
