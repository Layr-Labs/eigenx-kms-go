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

// MockContractCallerStub provides a minimal stub implementation of IContractCaller for testing.
//
// GetCommitmentAtFunc, when set, lets a test drive what the commitment registry returns
// per (epoch, operator, block) — used by the reshare dealer-set-agreement simulation to
// model which operators submitted on-chain. When nil, reads return an empty commitment.
type MockContractCallerStub struct {
	GetCommitmentAtFunc func(ctx context.Context, registryAddress common.Address, epoch int64, operator common.Address, blockNumber uint64) (commitmentHash [32]byte, ackMerkleRoot [32]byte, submittedAt uint64, err error)
	// SubmitCommitmentFunc, when set, is invoked by SubmitCommitment so tests can record the
	// real per-(epoch,operator) commitment hash (needed to serve authentic hashes back via
	// GetCommitmentAt — docs/013 Change 2 verifies P2P commitments against the on-chain hash).
	// The operator identity is threaded via OperatorAddress below (SubmitCommitment's ABI has
	// no operator arg; the contract uses msg.sender).
	SubmitCommitmentFunc func(epoch int64, operator common.Address, commitmentHash [32]byte, ackMerkleRoot [32]byte)
	// OperatorAddress identifies which operator this caller instance acts as, so
	// SubmitCommitment can attribute the submission (mirrors msg.sender on-chain).
	OperatorAddress common.Address
}

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
	if m.SubmitCommitmentFunc != nil {
		m.SubmitCommitmentFunc(epoch, m.OperatorAddress, commitmentHash, ackMerkleRoot)
	}
	return &ethTypes.Receipt{Status: 1}, nil
}

func (m *MockContractCallerStub) GetCommitment(ctx context.Context, registryAddress common.Address, epoch int64, operator common.Address) (commitmentHash [32]byte, ackMerkleRoot [32]byte, submittedAt uint64, err error) {
	return m.GetCommitmentAt(ctx, registryAddress, epoch, operator, 0)
}

func (m *MockContractCallerStub) GetCommitmentAt(ctx context.Context, registryAddress common.Address, epoch int64, operator common.Address, blockNumber uint64) (commitmentHash [32]byte, ackMerkleRoot [32]byte, submittedAt uint64, err error) {
	if m.GetCommitmentAtFunc != nil {
		return m.GetCommitmentAtFunc(ctx, registryAddress, epoch, operator, blockNumber)
	}
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

func (m *MockContractCallerStub) GetLatestRelease(ctx context.Context, appID string) ([32]byte, caller.Env, []byte, types.ContainerPolicy, error) {
	return [32]byte{}, nil, nil, types.ContainerPolicy{}, nil
}

func (m *MockContractCallerStub) GetLatestReleaseAsRelease(ctx context.Context, appID string) (*types.Release, error) {
	// Timestamp is intentionally 0 — this stub returns static data for simple tests.
	// Use TestableContractCallerStub for tests that need realistic release data.
	return &types.Release{
		ImageDigest:  "sha256:test123",
		EncryptedEnv: "encrypted-env-data-for-" + appID,
		PublicEnv:    `{"PUBLIC_VAR":"test-value"}`,
		Timestamp:    0,
	}, nil
}

// TestableContractCallerStub extends MockContractCallerStub with test data configuration.
// It simulates the two-phase upgrade flow: upgradeApp() writes to pendingReleases,
// confirmUpgrade() promotes the pending release to the confirmed releases map.
type TestableContractCallerStub struct {
	MockContractCallerStub
	releases        map[string]*types.Release         // confirmed (active) releases
	pendingReleases map[string]*types.Release         // pending releases awaiting confirmation
	creators        map[common.Address]common.Address // configured app creators
	mu              sync.RWMutex
}

// NewTestableContractCallerStub creates a new testable stub with configurable releases
func NewTestableContractCallerStub() *TestableContractCallerStub {
	return &TestableContractCallerStub{
		releases:        make(map[string]*types.Release),
		pendingReleases: make(map[string]*types.Release),
		creators:        make(map[common.Address]common.Address),
	}
}

// AddTestRelease adds a confirmed test release for a specific app ID.
// This simulates a release that has already been confirmed via confirmUpgrade().
func (m *TestableContractCallerStub) AddTestRelease(appID string, release *types.Release) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releases[appID] = release
}

// SetPendingRelease simulates upgradeApp(): places a new release in the pending state.
// The confirmed (active) release is unchanged until ConfirmPendingRelease is called.
func (m *TestableContractCallerStub) SetPendingRelease(appID string, release *types.Release) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingReleases[appID] = release
}

// ConfirmUpgrade simulates the on-chain confirmUpgrade(): promotes the pending release to confirmed.
// Returns an error if no pending release exists for the app.
func (m *TestableContractCallerStub) ConfirmUpgrade(appID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	pending, exists := m.pendingReleases[appID]
	if !exists {
		return fmt.Errorf("no pending release for app_id: %s", appID)
	}
	m.releases[appID] = pending
	delete(m.pendingReleases, appID)
	return nil
}

// SetAppCreator configures the on-chain creator returned by GetAppCreator for
// a given app address. Used to drive ECDSA ownership-binding tests.
func (m *TestableContractCallerStub) SetAppCreator(app common.Address, creator common.Address) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creators[app] = creator
}

// GetAppCreator returns the configured creator for an app, or the zero address
// if none was set. It never errors — release lookups and creator lookups are
// independent in tests.
func (m *TestableContractCallerStub) GetAppCreator(app common.Address, opts *bind.CallOpts) (common.Address, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.creators[app], nil
}

// GetLatestRelease returns the confirmed release data for an app in its raw form.
// Delegates to the releases map so behaviour is consistent with GetLatestReleaseAsRelease.
func (m *TestableContractCallerStub) GetLatestRelease(ctx context.Context, appID string) ([32]byte, caller.Env, []byte, types.ContainerPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	release, exists := m.releases[appID]
	if !exists {
		return [32]byte{}, nil, nil, types.ContainerPolicy{}, fmt.Errorf("no release found for app_id: %s", appID)
	}

	var digest [32]byte
	copy(digest[:], []byte(release.ImageDigest))

	return digest, nil, []byte(release.EncryptedEnv), release.ContainerPolicy, nil
}

// GetLatestReleaseAsRelease returns the confirmed (active) release for an app.
// In the two-phase upgrade model, this is only updated after confirmUpgrade() is called,
// so in-flight requests issued before an upgrade are still validated correctly.
func (m *TestableContractCallerStub) GetLatestReleaseAsRelease(ctx context.Context, appID string) (*types.Release, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	release, exists := m.releases[appID]
	if !exists {
		return nil, fmt.Errorf("no release found for app_id: %s", appID)
	}

	return release, nil
}
