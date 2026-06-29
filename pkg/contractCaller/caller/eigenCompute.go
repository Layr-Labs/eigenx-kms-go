package caller

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	iappctl "github.com/Layr-Labs/eigenx-kms-go/pkg/middleware-bindings/IAppController"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Env represents environment variables as a map
type Env map[string]string

// AppControllerInterface defines the interface for interacting with EigenCompute AppController contract
// This allows for dependency injection and testing without requiring the actual bindings
type AppControllerInterface interface {
	GetAppCreator(opts *bind.CallOpts, app common.Address) (common.Address, error)
	GetAppOperatorSetId(opts *bind.CallOpts, app common.Address) (uint32, error)
	// GetAppLatestReleaseBlockNumber returns the block number of the latest CONFIRMED release.
	// A release is confirmed only after confirmUpgrade() has been called by the Coordinator,
	// which prevents race conditions during in-flight requests at upgrade time.
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
	RmsReleaseId *big.Int
	Release      AppRelease
	Raw          ethTypes.Log
}

// AppRelease is an alias for the generated ABI binding type.
type AppRelease = iappctl.IAppControllerAppRelease

// RmsRelease is an alias for the generated ABI binding type.
type RmsRelease = iappctl.IAppControllerRmsRelease

// Artifact is an alias for the generated ABI binding type.
type Artifact = iappctl.IAppControllerArtifact

// contractPolicyToTypes converts the ABI-encoded ContainerPolicy (env as
// (key,value) tuple arrays, per the v1.5.x AppController) to the domain
// types.ContainerPolicy (map[string]string).
func contractPolicyToTypes(p iappctl.IAppControllerContainerPolicy) types.ContainerPolicy {
	env := make(map[string]string, len(p.Env))
	for _, kv := range p.Env {
		env[kv.Key] = kv.Value
	}
	envOverride := make(map[string]string, len(p.EnvOverride))
	for _, kv := range p.EnvOverride {
		envOverride[kv.Key] = kv.Value
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

// SetAppControllerBlockClient sets the L1 backend used to resolve the AppController's
// release block timestamps. Call this alongside SetAppController when this
// ContractCaller's primary `ethclient` is on a different chain than the AppController
// (e.g. baseContractCaller is L2/Base but the AppController is on L1). Passing nil is a
// no-op (resolveLatestRelease then falls back to `ethclient`). Not part of
// IContractCaller — it's only relevant to the concrete ContractCaller wiring.
func (cc *ContractCaller) SetAppControllerBlockClient(client *ethclient.Client) {
	cc.appControllerClient = client
}

// getAppController returns the AppController instance
func (cc *ContractCaller) getAppController() (AppControllerInterface, error) {
	if cc.appController == nil {
		return nil, fmt.Errorf("appController not initialized - call SetAppController first")
	}
	return cc.appController, nil
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

// GetAppLatestReleaseBlockNumber returns the block number of the latest CONFIRMED release for a given app.
// This is the release that has been acknowledged by the Coordinator via confirmUpgrade().
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

// resolvedRelease bundles the on-chain release fields surfaced by
// resolveLatestRelease. Returning a struct keeps the call sites readable
// as fields are added to the Artifact / AppRelease bindings (e.g.
// Registry, added when the IAppController.Artifact ABI was extended).
type resolvedRelease struct {
	Digest          [32]byte
	Registry        string
	PublicEnv       Env
	EncryptedEnv    []byte
	ContainerPolicy types.ContainerPolicy
	BlockNumber     uint64
}

// resolveLatestRelease is the internal implementation shared by GetLatestRelease and
// GetLatestReleaseAsRelease. It also returns the release block number so callers can
// fetch the authoritative block timestamp.
func (cc *ContractCaller) resolveLatestRelease(ctx context.Context, appID string) (resolvedRelease, error) {
	appCtrl, err := cc.getAppController()
	if err != nil {
		return resolvedRelease{}, err
	}

	cc.logger.Sugar().Debugw("Getting latest release", "app_id", appID)

	appAddress := common.HexToAddress(appID)
	cc.logger.Sugar().Debugw("Fetching app latest release block number", "app_address", appAddress)

	latestReleaseBlockNumber, err := cc.GetAppLatestReleaseBlockNumber(appAddress, &bind.CallOpts{Context: ctx})
	if err != nil {
		return resolvedRelease{}, fmt.Errorf("failed to get app latest release block number: %w", err)
	}
	cc.logger.Sugar().Debugw("App latest release block number fetched successfully", "block_number", latestReleaseBlockNumber)

	releaseBlockNumberUint64 := uint64(latestReleaseBlockNumber)
	cc.logger.Sugar().Debug("Filtering app upgraded events", "block_number", releaseBlockNumberUint64, "app_address", appAddress)

	appUpgrades, err := appCtrl.FilterAppUpgraded(&bind.FilterOpts{Context: ctx, Start: releaseBlockNumberUint64, End: &releaseBlockNumberUint64}, []common.Address{appAddress})
	if err != nil {
		return resolvedRelease{}, fmt.Errorf("failed to filter app upgraded: %w", err)
	}
	cc.logger.Sugar().Debug("App upgraded events filtered successfully")
	defer func() { _ = appUpgrades.Close() }()

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
		return resolvedRelease{}, fmt.Errorf("error iterating app upgrades: %w", appUpgrades.Error())
	}
	if lastAppUpgrade == nil {
		return resolvedRelease{}, fmt.Errorf("no app upgrade found for app %s at block %d", appID, releaseBlockNumberUint64)
	}

	release := lastAppUpgrade.Release
	cc.logger.Sugar().Debug("Found app upgraded event", "app_id", appID, "release_id", fmt.Sprintf("%x", lastAppUpgrade.RmsReleaseId), "block", lastAppUpgrade.Raw.BlockNumber)

	if len(release.RmsRelease.Artifacts) != 1 {
		return resolvedRelease{}, fmt.Errorf("expected 1 artifact, got %d", len(release.RmsRelease.Artifacts))
	}
	artifact := release.RmsRelease.Artifacts[0]
	cc.logger.Sugar().Debug("Release retrieved successfully", "app_id", appID, "artifact_digest", fmt.Sprintf("%x", artifact.Digest), "registry", artifact.Registry)

	publicEnv := Env{}
	if err = json.Unmarshal(release.PublicEnv, &publicEnv); err != nil {
		return resolvedRelease{}, fmt.Errorf("failed to unmarshal env: %w", err)
	}
	cc.logger.Sugar().Debug("Latest release data prepared", "app_id", appID, "public_env_vars_count", len(publicEnv))

	return resolvedRelease{
		Digest:          artifact.Digest,
		Registry:        artifact.Registry,
		PublicEnv:       publicEnv,
		EncryptedEnv:    release.EncryptedEnv,
		ContainerPolicy: contractPolicyToTypes(release.ContainerPolicy),
		BlockNumber:     lastAppUpgrade.Raw.BlockNumber,
	}, nil
}

// GetLatestRelease retrieves the latest release information for an app.
// Returns: image digest, public env, encrypted env, container policy, error.
// Note: callers needing the artifact's registry should use
// GetLatestReleaseAsRelease — this signature is preserved for the legacy
// flow that doesn't yet care about the registry.
func (cc *ContractCaller) GetLatestRelease(ctx context.Context, appID string) ([32]byte, Env, []byte, types.ContainerPolicy, error) {
	r, err := cc.resolveLatestRelease(ctx, appID)
	if err != nil {
		return [32]byte{}, Env{}, nil, types.ContainerPolicy{}, err
	}
	return r.Digest, r.PublicEnv, r.EncryptedEnv, r.ContainerPolicy, nil
}

// GetLatestReleaseAsRelease is an adapter that returns release data in the types.Release format.
// This provides compatibility with the legacy registry.Client interface.
func (cc *ContractCaller) GetLatestReleaseAsRelease(ctx context.Context, appID string) (*types.Release, error) {
	r, err := cc.resolveLatestRelease(ctx, appID)
	if err != nil {
		return nil, err
	}

	// Fetch the block header to get the authoritative release timestamp. r.BlockNumber
	// is an AppController (L1) block height, so read it from the L1 client when one was
	// configured via SetAppControllerBlockClient — cc.ethclient may be the L2/Base
	// client (the /secrets release lookup runs on baseContractCaller), and L1/L2 block
	// numbers are not interchangeable. Fall back to cc.ethclient for single-chain setups.
	blockClient := cc.ethclient
	if cc.appControllerClient != nil {
		blockClient = cc.appControllerClient
	}
	header, err := blockClient.HeaderByNumber(ctx, new(big.Int).SetUint64(r.BlockNumber))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch block header for timestamp: %w", err)
	}

	imageDigest := fmt.Sprintf("sha256:%x", r.Digest)

	var publicEnvStr string
	if len(r.PublicEnv) > 0 {
		envBytes, err := json.Marshal(r.PublicEnv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public env: %w", err)
		}
		publicEnvStr = string(envBytes)
	}

	// r.EncryptedEnv is the raw on-chain IBE envelope — arbitrary binary, not
	// valid UTF-8. types.Release.EncryptedEnv is a string that is serialized to
	// JSON (it crosses the /secrets HTTP boundary), and a raw string([]byte)
	// cast of non-UTF-8 bytes is corrupted by json.Marshal (invalid runes become
	// U+FFFD). Hex-encode so the bytes survive serialization losslessly; callers
	// decode back to the original envelope. Empty stays empty (public-only
	// releases have no encrypted_env).
	var encryptedEnvStr string
	if len(r.EncryptedEnv) > 0 {
		encryptedEnvStr = hex.EncodeToString(r.EncryptedEnv)
	}

	return &types.Release{
		ImageDigest:     imageDigest,
		Registry:        r.Registry,
		EncryptedEnv:    encryptedEnvStr,
		PublicEnv:       publicEnvStr,
		Timestamp:       int64(header.Time),
		ContainerPolicy: r.ContainerPolicy,
	}, nil
}
