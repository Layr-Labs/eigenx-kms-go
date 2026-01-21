package contractCaller

import (
	"context"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethereumTypes "github.com/ethereum/go-ethereum/core/types"
)

type IContractCaller interface {
	GetOperatorSetMembersWithPeering(
		avsAddress string,
		operatorSetId uint32,
	) (*peering.OperatorSetPeers, error)

	GetOperatorSetDetailsForOperator(
		operatorAddress common.Address,
		avsAddress string,
		operatorSetId uint32,
	) (*peering.OperatorSetPeer, error)

	GetOperatorSetMembers(avsAddress string, operatorSetId uint32) ([]string, error)

	// Helper functions for operator registration
	EncodeBN254KeyData(pubKey *bn254.PublicKey) ([]byte, error)

	GetOperatorSetCurveType(avsAddress string, operatorSetId uint32, blockNumber uint64) (config.CurveType, error)

	GetOperatorECDSAKeyRegistrationMessageHash(
		ctx context.Context,
		operatorAddress common.Address,
		avsAddress common.Address,
		operatorSetId uint32,
		signingKeyAddress common.Address,
	) ([32]byte, error)

	GetOperatorBN254KeyRegistrationMessageHash(
		ctx context.Context,
		operatorAddress common.Address,
		avsAddress common.Address,
		operatorSetId uint32,
		keyData []byte,
	) ([32]byte, error)

	RegisterKeyWithKeyRegistrar(
		ctx context.Context,
		operatorAddress common.Address,
		avsAddress common.Address,
		operatorSetId uint32,
		sigBytes []byte,
		keyData []byte,
	) (*ethereumTypes.Receipt, error)

	CreateOperatorAndRegisterWithAvs(
		ctx context.Context,
		avsAddress common.Address,
		operatorAddress common.Address,
		operatorSetIds []uint32,
		socket string,
		allocationDelay uint32,
		metadataUri string,
	) (*ethereumTypes.Receipt, error)

	// Commitment registry functions (Phase 2)
	SubmitCommitment(
		ctx context.Context,
		registryAddress common.Address,
		epoch int64,
		commitmentHash [32]byte,
		ackMerkleRoot [32]byte,
	) (*ethereumTypes.Receipt, error)

	GetCommitment(
		ctx context.Context,
		registryAddress common.Address,
		epoch int64,
		operator common.Address,
	) (commitmentHash [32]byte, ackMerkleRoot [32]byte, submittedAt uint64, err error)

	// EigenCompute app management functions
	SetAppController(appController caller.AppControllerInterface) error

	GetAppCreator(app common.Address, opts *bind.CallOpts) (common.Address, error)

	GetAppOperatorSetId(app common.Address, opts *bind.CallOpts) (uint32, error)

	GetAppLatestReleaseBlockNumber(app common.Address, opts *bind.CallOpts) (uint32, error)

	GetAppStatus(app common.Address, opts *bind.CallOpts) (uint8, error)

	FilterAppUpgraded(apps []common.Address, filterOpts *bind.FilterOpts) (caller.AppUpgradedIterator, error)

	GetLatestRelease(ctx context.Context, appID string) ([32]byte, caller.Env, []byte, error)
}
