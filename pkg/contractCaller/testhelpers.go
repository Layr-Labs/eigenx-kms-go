package contractCaller

import (
	"context"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
)

// MockContractCallerStub provides a minimal stub implementation of IContractCaller for testing
type MockContractCallerStub struct{}

func (m *MockContractCallerStub) GetOperatorSetMembersWithPeering(avsAddress string, operatorSetId uint32) (*peering.OperatorSetPeers, error) {
	return nil, nil
}

func (m *MockContractCallerStub) GetOperatorSetDetailsForOperator(operatorAddress common.Address, avsAddress string, operatorSetId uint32) (*peering.OperatorSetPeer, error) {
	return nil, nil
}

func (m *MockContractCallerStub) GetOperatorSetMembers(avsAddress string, operatorSetId uint32) ([]string, error) {
	return nil, nil
}

func (m *MockContractCallerStub) EncodeBN254KeyData(pubKey *bn254.PublicKey) ([]byte, error) {
	return nil, nil
}

func (m *MockContractCallerStub) GetOperatorSetCurveType(avsAddress string, operatorSetId uint32, blockNumber uint64) (config.CurveType, error) {
	return config.CurveTypeUnknown, nil
}

func (m *MockContractCallerStub) GetOperatorECDSAKeyRegistrationMessageHash(ctx context.Context, operatorAddress common.Address, avsAddress common.Address, operatorSetId uint32, signingKeyAddress common.Address) ([32]byte, error) {
	return [32]byte{}, nil
}

func (m *MockContractCallerStub) GetOperatorBN254KeyRegistrationMessageHash(ctx context.Context, operatorAddress common.Address, avsAddress common.Address, operatorSetId uint32, keyData []byte) ([32]byte, error) {
	return [32]byte{}, nil
}

func (m *MockContractCallerStub) RegisterKeyWithKeyRegistrar(ctx context.Context, operatorAddress common.Address, avsAddress common.Address, operatorSetId uint32, sigBytes []byte, keyData []byte) (*ethTypes.Receipt, error) {
	return nil, nil
}

func (m *MockContractCallerStub) CreateOperatorAndRegisterWithAvs(ctx context.Context, avsAddress common.Address, operatorAddress common.Address, operatorSetIds []uint32, socket string, allocationDelay uint32, metadataUri string) (*ethTypes.Receipt, error) {
	return nil, nil
}

func (m *MockContractCallerStub) SubmitCommitment(ctx context.Context, registryAddress common.Address, epoch int64, commitmentHash [32]byte, ackMerkleRoot [32]byte) (*ethTypes.Receipt, error) {
	return &ethTypes.Receipt{Status: 1}, nil
}

func (m *MockContractCallerStub) GetCommitment(ctx context.Context, registryAddress common.Address, epoch int64, operator common.Address) (commitmentHash [32]byte, ackMerkleRoot [32]byte, submittedAt uint64, err error) {
	return [32]byte{}, [32]byte{}, 0, nil
}

func (m *MockContractCallerStub) SetAppController(appController caller.AppControllerInterface) error {
	return nil
}

func (m *MockContractCallerStub) GetAppCreator(app common.Address, opts *bind.CallOpts) (common.Address, error) {
	return common.Address{}, nil
}

func (m *MockContractCallerStub) GetAppOperatorSetId(app common.Address, opts *bind.CallOpts) (uint32, error) {
	return 0, nil
}

func (m *MockContractCallerStub) GetAppLatestReleaseBlockNumber(app common.Address, opts *bind.CallOpts) (uint32, error) {
	return 0, nil
}

func (m *MockContractCallerStub) GetAppStatus(app common.Address, opts *bind.CallOpts) (uint8, error) {
	return 0, nil
}

func (m *MockContractCallerStub) FilterAppUpgraded(apps []common.Address, filterOpts *bind.FilterOpts) (caller.AppUpgradedIterator, error) {
	return nil, nil
}

func (m *MockContractCallerStub) GetLatestRelease(ctx context.Context, appID string) ([32]byte, caller.Env, []byte, error) {
	return [32]byte{}, nil, nil, nil
}
