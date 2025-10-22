pragma solidity ^0.8.27;

import {IAVSRegistrar} from "@eigenlayer-contracts/src/contracts/interfaces/IAVSRegistrar.sol";
import {IAVSRegistrarInternal} from "@eigenlayer-middleware/src/interfaces/IAVSRegistrarInternal.sol";
import {ISocketRegistryV2} from "@eigenlayer-middleware/src/interfaces/ISocketRegistryV2.sol";
import {IAllowlist} from "@eigenlayer-middleware/src/interfaces/IAllowlist.sol";

interface IEigenKMSRegistrarTypes {
    struct AvsConfig {
        uint32 operatorSetId;
    }
}

/**
 * @title ITaskAVSRegistrarBase
 * @author Layr Labs, Inc.
 * @notice Interface for TaskAVSRegistrarBase contract that manages AVS configuration
 */
interface IEigenKMSRegistrar is
    IAVSRegistrar,
    IAVSRegistrarInternal,
    ISocketRegistryV2,
    IAllowlist
{
    /**
     * @notice Sets the configuration for this AVS
     * @param config Configuration for the AVS
     * @dev The executorOperatorSetIds must be monotonically increasing.
     */
    function setAvsConfig(
        IEigenKMSRegistrarTypes.AvsConfig memory config
    ) external;

    /**
     * @notice Gets the configuration for this AVS
     * @return Configuration for the AVS
     */
    function getAvsConfig() external view returns (IEigenKMSRegistrarTypes.AvsConfig memory);
}
