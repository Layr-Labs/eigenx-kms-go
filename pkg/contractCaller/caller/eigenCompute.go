package caller

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
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
	Raw          types.Log
}

// AppRelease represents the release data structure
type AppRelease struct {
	RmsRelease   RmsRelease
	PublicEnv    []byte
	EncryptedEnv []byte
}

// RmsRelease represents the RMS release structure
type RmsRelease struct {
	Artifacts []Artifact
}

// Artifact represents a container artifact
type Artifact struct {
	Digest [32]byte
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
	appCtrl, ok := cc.appController.(AppControllerInterface)
	if !ok {
		return nil, fmt.Errorf("appController has invalid type")
	}
	return appCtrl, nil
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

// GetLatestRelease retrieves the latest release information for an app
// Returns: image digest, public env, encrypted env, error
func (cc *ContractCaller) GetLatestRelease(ctx context.Context, appID string) ([32]byte, Env, []byte, error) {
	appCtrl, err := cc.getAppController()
	if err != nil {
		return [32]byte{}, Env{}, nil, err
	}

	cc.logger.Sugar().Debugw("Getting latest release", "app_id", appID)

	appAddress := common.HexToAddress(appID)
	cc.logger.Sugar().Debugw("Fetching app latest release block number", "app_address", appAddress)

	latestReleaseBlockNumber, err := cc.GetAppLatestReleaseBlockNumber(appAddress, &bind.CallOpts{Context: ctx})
	if err != nil {
		return [32]byte{}, Env{}, nil, fmt.Errorf("failed to get app latest release block number: %w", err)
	}
	cc.logger.Sugar().Debugw("App latest release block number fetched successfully", "block_number", latestReleaseBlockNumber)

	// Get the latest release deployed at the block number
	releaseBlockNumberUint64 := uint64(latestReleaseBlockNumber)
	cc.logger.Sugar().Debug("Filtering app upgraded events", "block_number", releaseBlockNumberUint64, "app_address", appAddress)

	appUpgrades, err := appCtrl.FilterAppUpgraded(&bind.FilterOpts{Context: ctx, Start: releaseBlockNumberUint64, End: &releaseBlockNumberUint64}, []common.Address{appAddress})
	if err != nil {
		return [32]byte{}, Env{}, nil, fmt.Errorf("failed to filter app upgraded: %w", err)
	}
	cc.logger.Sugar().Debug("App upgraded events filtered successfully")

	// Get the latest release deployed of all returned logs
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
		return [32]byte{}, Env{}, nil, fmt.Errorf("error iterating app upgrades: %w", appUpgrades.Error())
	}
	if lastAppUpgrade == nil {
		return [32]byte{}, Env{}, nil, fmt.Errorf("no app upgrade found for app %s at block %d", appID, releaseBlockNumberUint64)
	}

	release := lastAppUpgrade.Release
	cc.logger.Sugar().Debug("Found app upgraded event", "app_id", appID, "release_id", fmt.Sprintf("%x", lastAppUpgrade.RmsReleaseId), "block", lastAppUpgrade.Raw.BlockNumber)

	if len(release.RmsRelease.Artifacts) != 1 {
		return [32]byte{}, Env{}, nil, fmt.Errorf("expected 1 artifact, got %d", len(release.RmsRelease.Artifacts))
	}
	cc.logger.Sugar().Debug("Release retrieved successfully", "app_id", appID, "artifact_digest", fmt.Sprintf("%x", release.RmsRelease.Artifacts[0].Digest))

	publicEnv := Env{}
	err = json.Unmarshal(release.PublicEnv, &publicEnv)
	if err != nil {
		return [32]byte{}, Env{}, nil, fmt.Errorf("failed to unmarshal env: %w", err)
	}
	cc.logger.Sugar().Debug("Latest release data prepared", "app_id", appID, "public_env_vars_count", len(publicEnv))

	return release.RmsRelease.Artifacts[0].Digest, publicEnv, release.EncryptedEnv, nil
}
