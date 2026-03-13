package caller

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	iappctl "github.com/Layr-Labs/eigenx-kms-go/pkg/middleware-bindings/IAppController"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
)

// Env represents environment variables as a map
type Env map[string]string

// AppControllerInterface defines the interface for interacting with EigenCompute AppController contract
// This allows for dependency injection and testing without requiring the actual bindings
type AppControllerInterface interface {
	GetAppCreator(opts *bind.CallOpts, app common.Address) (common.Address, error)
	GetAppOperatorSetId(opts *bind.CallOpts, app common.Address) (uint32, error)
	GetAppLatestReleaseBlockNumber(opts *bind.CallOpts, app common.Address) (uint32, error)
	GetAppStatus(opts *bind.CallOpts, app common.Address) (uint8, error)
	FilterAppUpgraded(opts *bind.FilterOpts, apps []common.Address) (AppUpgradedIterator, error)
}

// AppUpgradedIterator defines the interface for iterating over AppUpgraded events
type AppUpgradedIterator interface {
	Next() bool
	Event() *AppUpgradedEvent
	Error() error
	Close() error
}

// AppUpgradedEvent represents an AppUpgraded event
type AppUpgradedEvent struct {
	App          common.Address
	RmsReleaseId [32]byte
	Release      AppRelease
	Raw          ethTypes.Log
}

// AppRelease is an alias for the generated ABI binding type.
type AppRelease = iappctl.IAppControllerAppRelease

// RmsRelease is an alias for the generated ABI binding type.
type RmsRelease = iappctl.IAppControllerRmsRelease

// Artifact is an alias for the generated ABI binding type.
type Artifact = iappctl.IAppControllerArtifact

// contractPolicyToTypes converts the ABI-encoded ContainerPolicy (parallel string arrays
// for env maps) to the domain types.ContainerPolicy (map[string]string).
func contractPolicyToTypes(p iappctl.IAppControllerContainerPolicy) types.ContainerPolicy {
	env := make(map[string]string, len(p.EnvKeys))
	for i, k := range p.EnvKeys {
		if i < len(p.EnvValues) {
			env[k] = p.EnvValues[i]
		}
	}
	envOverride := make(map[string]string, len(p.EnvOverrideKeys))
	for i, k := range p.EnvOverrideKeys {
		if i < len(p.EnvOverrideValues) {
			envOverride[k] = p.EnvOverrideValues[i]
		}
	}
	return types.ContainerPolicy{
		Args:          p.Args,
		CmdOverride:   p.CmdOverride,
		Env:           env,
		EnvOverride:   envOverride,
		RestartPolicy: p.RestartPolicy,
	}
}

// SetAppController configures the AppController contract for EigenCompute app operations
// appController should implement the AppControllerInterface
func (cc *ContractCaller) SetAppController(appController AppControllerInterface) error {
	if appController == nil {
		return fmt.Errorf("appController cannot be nil")
	}
	cc.appController = appController
	cc.logger.Sugar().Info("AppController configured")
	return nil
}

// getAppController returns the AppController instance
func (cc *ContractCaller) getAppController() (AppControllerInterface, error) {
	if cc.appController == nil {
		return nil, fmt.Errorf("appController not initialized - call SetAppController first")
	}
	ctrl, ok := cc.appController.(AppControllerInterface)
	if !ok {
		return nil, fmt.Errorf("appController has unexpected type %T", cc.appController)
	}
	return ctrl, nil
}

// GetAppCreator returns the creator address for a given app
func (cc *ContractCaller) GetAppCreator(app common.Address, opts *bind.CallOpts) (common.Address, error) {
	appCtrl, err := cc.getAppController()
	if err != nil {
		return common.Address{}, err
	}
	creator, err := appCtrl.GetAppCreator(opts, app)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to get app creator: %w", err)
	}
	return creator, nil
}

// GetAppOperatorSetId returns the operator set ID for a given app
func (cc *ContractCaller) GetAppOperatorSetId(app common.Address, opts *bind.CallOpts) (uint32, error) {
	appCtrl, err := cc.getAppController()
	if err != nil {
		return 0, err
	}
	setId, err := appCtrl.GetAppOperatorSetId(opts, app)
	if err != nil {
		return 0, fmt.Errorf("failed to get app operator set ID: %w", err)
	}
	return setId, nil
}

// GetAppLatestReleaseBlockNumber returns the block number of the latest release for a given app
func (cc *ContractCaller) GetAppLatestReleaseBlockNumber(app common.Address, opts *bind.CallOpts) (uint32, error) {
	appCtrl, err := cc.getAppController()
	if err != nil {
		return 0, err
	}
	blockNumber, err := appCtrl.GetAppLatestReleaseBlockNumber(opts, app)
	if err != nil {
		return 0, fmt.Errorf("failed to get app latest release block number: %w", err)
	}
	return blockNumber, nil
}

// GetAppStatus returns the status of a given app
func (cc *ContractCaller) GetAppStatus(app common.Address, opts *bind.CallOpts) (uint8, error) {
	appCtrl, err := cc.getAppController()
	if err != nil {
		return 0, err
	}
	status, err := appCtrl.GetAppStatus(opts, app)
	if err != nil {
		return 0, fmt.Errorf("failed to get app status: %w", err)
	}
	return status, nil
}

// FilterAppUpgraded filters for AppUpgraded events
func (cc *ContractCaller) FilterAppUpgraded(apps []common.Address, filterOpts *bind.FilterOpts) (AppUpgradedIterator, error) {
	appCtrl, err := cc.getAppController()
	if err != nil {
		return nil, err
	}
	iterator, err := appCtrl.FilterAppUpgraded(filterOpts, apps)
	if err != nil {
		return nil, fmt.Errorf("failed to filter app upgraded events: %w", err)
	}
	return iterator, nil
}

// resolveLatestRelease is the internal implementation shared by GetLatestRelease and
// GetLatestReleaseAsRelease. It also returns the release block number so callers can
// fetch the authoritative block timestamp.
func (cc *ContractCaller) resolveLatestRelease(ctx context.Context, appID string) ([32]byte, Env, []byte, types.ContainerPolicy, uint64, error) {
	appCtrl, err := cc.getAppController()
	if err != nil {
		return [32]byte{}, Env{}, nil, types.ContainerPolicy{}, 0, err
	}

	cc.logger.Sugar().Debugw("Getting latest release", "app_id", appID)

	appAddress := common.HexToAddress(appID)
	cc.logger.Sugar().Debugw("Fetching app latest release block number", "app_address", appAddress)

	latestReleaseBlockNumber, err := cc.GetAppLatestReleaseBlockNumber(appAddress, &bind.CallOpts{Context: ctx})
	if err != nil {
		return [32]byte{}, Env{}, nil, types.ContainerPolicy{}, 0, fmt.Errorf("failed to get app latest release block number: %w", err)
	}
	cc.logger.Sugar().Debugw("App latest release block number fetched successfully", "block_number", latestReleaseBlockNumber)

	releaseBlockNumberUint64 := uint64(latestReleaseBlockNumber)
	cc.logger.Sugar().Debug("Filtering app upgraded events", "block_number", releaseBlockNumberUint64, "app_address", appAddress)

	appUpgrades, err := appCtrl.FilterAppUpgraded(&bind.FilterOpts{Context: ctx, Start: releaseBlockNumberUint64, End: &releaseBlockNumberUint64}, []common.Address{appAddress})
	if err != nil {
		return [32]byte{}, Env{}, nil, types.ContainerPolicy{}, 0, fmt.Errorf("failed to filter app upgraded: %w", err)
	}
	cc.logger.Sugar().Debug("App upgraded events filtered successfully")
	defer appUpgrades.Close()

	var lastAppUpgrade *AppUpgradedEvent
	for appUpgrades.Next() {
		event := appUpgrades.Event()
		if lastAppUpgrade == nil {
			lastAppUpgrade = event
		} else if event.Raw.Index > lastAppUpgrade.Raw.Index {
			lastAppUpgrade = event
		}
	}
	if appUpgrades.Error() != nil {
		return [32]byte{}, Env{}, nil, types.ContainerPolicy{}, 0, fmt.Errorf("error iterating app upgrades: %w", appUpgrades.Error())
	}
	if lastAppUpgrade == nil {
		return [32]byte{}, Env{}, nil, types.ContainerPolicy{}, 0, fmt.Errorf("no app upgrade found for app %s at block %d", appID, releaseBlockNumberUint64)
	}

	release := lastAppUpgrade.Release
	cc.logger.Sugar().Debug("Found app upgraded event", "app_id", appID, "release_id", fmt.Sprintf("%x", lastAppUpgrade.RmsReleaseId), "block", lastAppUpgrade.Raw.BlockNumber)

	if len(release.RmsRelease.Artifacts) != 1 {
		return [32]byte{}, Env{}, nil, types.ContainerPolicy{}, 0, fmt.Errorf("expected 1 artifact, got %d", len(release.RmsRelease.Artifacts))
	}
	cc.logger.Sugar().Debug("Release retrieved successfully", "app_id", appID, "artifact_digest", fmt.Sprintf("%x", release.RmsRelease.Artifacts[0].Digest))

	publicEnv := Env{}
	if err = json.Unmarshal(release.PublicEnv, &publicEnv); err != nil {
		return [32]byte{}, Env{}, nil, types.ContainerPolicy{}, 0, fmt.Errorf("failed to unmarshal env: %w", err)
	}
	cc.logger.Sugar().Debug("Latest release data prepared", "app_id", appID, "public_env_vars_count", len(publicEnv))

	return release.RmsRelease.Artifacts[0].Digest, publicEnv, release.EncryptedEnv, contractPolicyToTypes(release.ContainerPolicy), lastAppUpgrade.Raw.BlockNumber, nil
}

// GetLatestRelease retrieves the latest release information for an app.
// Returns: image digest, public env, encrypted env, container policy, error
func (cc *ContractCaller) GetLatestRelease(ctx context.Context, appID string) ([32]byte, Env, []byte, types.ContainerPolicy, error) {
	digest, env, encrypted, policy, _, err := cc.resolveLatestRelease(ctx, appID)
	return digest, env, encrypted, policy, err
}

// GetLatestReleaseAsRelease is an adapter that returns release data in the types.Release format.
// This provides compatibility with the legacy registry.Client interface.
func (cc *ContractCaller) GetLatestReleaseAsRelease(ctx context.Context, appID string) (*types.Release, error) {
	digest, publicEnv, encryptedEnv, containerPolicy, blockNumber, err := cc.resolveLatestRelease(ctx, appID)
	if err != nil {
		return nil, err
	}

	// Fetch the block header to get the authoritative release timestamp
	header, err := cc.ethclient.HeaderByNumber(ctx, new(big.Int).SetUint64(blockNumber))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch block header for timestamp: %w", err)
	}

	imageDigest := fmt.Sprintf("sha256:%x", digest)

	var publicEnvStr string
	if len(publicEnv) > 0 {
		envBytes, err := json.Marshal(publicEnv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public env: %w", err)
		}
		publicEnvStr = string(envBytes)
	}

	return &types.Release{
		ImageDigest:     imageDigest,
		EncryptedEnv:    string(encryptedEnv),
		PublicEnv:       publicEnvStr,
		Timestamp:       int64(header.Time),
		ContainerPolicy: containerPolicy,
	}, nil
}
