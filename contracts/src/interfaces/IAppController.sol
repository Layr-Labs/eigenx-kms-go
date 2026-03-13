// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title IAppController
/// @notice Interface for the EigenCompute AppController contract that manages app registrations and releases.
/// @dev Map fields (env, env_override) are encoded as parallel string arrays because Solidity
///      does not support mappings in ABI-encoded structs.
interface IAppController {
    /// @notice Container execution policy enforced by KMS nodes when verifying attestation claims.
    /// @dev env and env_override are stored as parallel key/value string arrays; the Go layer
    ///      converts them back to map[string]string.
    struct ContainerPolicy {
        string[] args;
        string[] cmdOverride;
        string[] envKeys;
        string[] envValues;
        string[] envOverrideKeys;
        string[] envOverrideValues;
        string restartPolicy;
    }

    /// @notice A single container image artifact identified by its digest.
    struct Artifact {
        bytes32 digest;
    }

    /// @notice A release record from the RMS (Release Management System).
    struct RmsRelease {
        Artifact[] artifacts;
    }

    /// @notice Full release data emitted in the AppUpgraded event.
    struct AppRelease {
        RmsRelease rmsRelease;
        bytes publicEnv;
        bytes encryptedEnv;
        ContainerPolicy containerPolicy;
    }

    /// @notice Emitted when an app is upgraded to a new release.
    event AppUpgraded(address indexed app, bytes32 rmsReleaseId, AppRelease release);

    /// @notice Returns the creator address of the given app.
    function getAppCreator(address app) external view returns (address);

    /// @notice Returns the operator set ID for the given app.
    function getAppOperatorSetId(address app) external view returns (uint32);

    /// @notice Returns the block number of the latest release for the given app.
    function getAppLatestReleaseBlockNumber(address app) external view returns (uint32);

    /// @notice Returns the status code of the given app.
    function getAppStatus(address app) external view returns (uint8);
}
