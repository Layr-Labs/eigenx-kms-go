package contractCaller

import (
	"context"
	"fmt"
	"sync"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
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

func (m *MockContractCallerStub) GetLatestReleaseAsRelease(ctx context.Context, appID string) (*types.Release, error) {
	// Return test release data
	return &types.Release{
		ImageDigest:  "sha256:test123",
		EncryptedEnv: "encrypted-env-data-for-" + appID,
		PublicEnv:    `{"PUBLIC_VAR":"test-value"}`,
		Timestamp:    0,
	}, nil
}

// TestableContractCallerStub extends MockContractCallerStub with test data configuration
type TestableContractCallerStub struct {
	MockContractCallerStub
	releases map[string]*types.Release
	mu       sync.RWMutex
}

// NewTestableContractCallerStub creates a new testable stub with configurable releases
func NewTestableContractCallerStub() *TestableContractCallerStub {
	return &TestableContractCallerStub{
		releases: make(map[string]*types.Release),
	}
}

// AddTestRelease adds a test release for a specific app ID
func (m *TestableContractCallerStub) AddTestRelease(appID string, release *types.Release) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releases[appID] = release
	fmt.Printf("Added test release for app_id: %s, image: %s\n", appID, release.ImageDigest)
}

// GetLatestReleaseAsRelease returns the configured test release for an app
func (m *TestableContractCallerStub) GetLatestReleaseAsRelease(ctx context.Context, appID string) (*types.Release, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	release, exists := m.releases[appID]
	if !exists {
		return nil, fmt.Errorf("no release found for app_id: %s", appID)
	}

	fmt.Printf("Found release for app_id: %s, image: %s\n", appID, release.ImageDigest)
	return release, nil
}
