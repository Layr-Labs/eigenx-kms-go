// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {IAllocationManager} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import {IKeyRegistrar} from "@eigenlayer-contracts/src/contracts/interfaces/IKeyRegistrar.sol";
import {IPermissionController} from "@eigenlayer-contracts/src/contracts/interfaces/IPermissionController.sol";
import {AVSRegistrar} from "@eigenlayer-middleware/src/middlewareV2/registrar/AVSRegistrar.sol";
import {SocketRegistry} from "@eigenlayer-middleware/src/middlewareV2/registrar/modules/SocketRegistry.sol";
import {Allowlist} from "@eigenlayer-middleware/src/middlewareV2/registrar/modules/Allowlist.sol";
import { IEigenKMSRegistrarTypes } from "./interfaces/IEigenKMSRegistrar.sol";
import {EigenKMSRegistrarStorage} from "./EigenKMSRegistrarStorage.sol";

contract EigenKMSRegistrar is AVSRegistrar, SocketRegistry, Allowlist, EigenKMSRegistrarStorage {
    /**
      * @dev Constructor that passes parameters to parent
     * @param _allocationManager The AllocationManager contract address
     * @param _keyRegistrar The KeyRegistrar contract address
     * @param _permissionController The PermissionController contract address
     */
    constructor(
        IAllocationManager _allocationManager,
        IKeyRegistrar _keyRegistrar,
        IPermissionController _permissionController
    ) AVSRegistrar(_allocationManager, _keyRegistrar) SocketRegistry(_permissionController) {
        _disableInitializers();
    }

    /**
     * @dev Initializer for the upgradeable contract
     * @param _avs The address of the AVS
     * @param _owner The owner of the contract
     * @param _initialConfig The initial AVS configuration
     */
    function initialize(
        address _avs,
        address _owner,
        IEigenKMSRegistrarTypes.AvsConfig memory _initialConfig
    ) internal onlyInitializing {
        __Allowlist_init(_owner); // initializes Ownable
        __AVSRegistrar_init(_avs);

        _setAvsConfig(_initialConfig);
    }

    /**
     * @notice Sets the configuration for this AVS
     * @param config Configuration for the AVS
     */
    function setAvsConfig(
        IEigenKMSRegistrarTypes.AvsConfig memory config
    ) external onlyOwner {
        _setAvsConfig(config);
    }

    /**
     * @notice Gets the configuration for this AVS
     * @return Configuration for the AVS
     */
    function getAvsConfig() external view returns (IEigenKMSRegistrarTypes.AvsConfig memory) {
        return avsConfig;
    }

    /**
     * @notice Internal function to set AVS configuration
     * @param config Configuration for the AVS
     */
    function _setAvsConfig(IEigenKMSRegistrarTypes.AvsConfig memory config) internal {
        avsConfig = config;
    }
}
