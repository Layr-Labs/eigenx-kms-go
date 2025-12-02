// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {IAllocationManager} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import {IKeyRegistrar} from "@eigenlayer-contracts/src/contracts/interfaces/IKeyRegistrar.sol";
import {IPermissionController} from "@eigenlayer-contracts/src/contracts/interfaces/IPermissionController.sol";
import {OperatorSet, OperatorSetLib} from "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import {AVSRegistrar} from "@eigenlayer-middleware/src/middlewareV2/registrar/AVSRegistrar.sol";
import {SocketRegistry} from "@eigenlayer-middleware/src/middlewareV2/registrar/modules/SocketRegistry.sol";
import {Allowlist} from "@eigenlayer-middleware/src/middlewareV2/registrar/modules/Allowlist.sol";
import {IEigenKMSRegistrarTypes} from "./interfaces/IEigenKMSRegistrar.sol";
import {EigenKMSRegistrarStorage} from "./EigenKMSRegistrarStorage.sol";

contract EigenKMSRegistrar is AVSRegistrar, SocketRegistry, Allowlist, EigenKMSRegistrarStorage {
    using OperatorSetLib for OperatorSet;

    /// @notice Thrown when operator is not in the allowlist for an operator set
    error OperatorNotAllowed(address operator, uint32 operatorSetId);

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
    ) external initializer {
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
    function _setAvsConfig(
        IEigenKMSRegistrarTypes.AvsConfig memory config
    ) internal {
        avsConfig = config;
    }

    /**
     * @notice Before registering operator, check if the operator is in the allowlist
     * @dev Validates operator is allowed for each operator set they're registering to
     * @param operator The address of the operator
     * @param operatorSetIds The IDs of the operator sets
     * @param data The data passed to the operator
     */
    function _beforeRegisterOperator(
        address operator,
        uint32[] calldata operatorSetIds,
        bytes calldata data
    ) internal override {
        super._beforeRegisterOperator(operator, operatorSetIds, data);

        // Check allowlist for each operator set
        for (uint256 i = 0; i < operatorSetIds.length; i++) {
            OperatorSet memory operatorSet = OperatorSet({avs: avs, id: operatorSetIds[i]});

            // Check if operator is allowed in this operator set
            if (!isOperatorAllowed(operatorSet, operator)) {
                revert OperatorNotAllowed(operator, operatorSetIds[i]);
            }
        }
    }

    /**
     * @notice Set the socket for the operator
     * @dev This function sets the socket even if the operator is already registered
     * @dev Operators should make sure to always provide the socket when registering
     * @param operator The address of the operator
     * @param operatorSetIds The IDs of the operator sets
     * @param data The data passed to the operator
     */
    function _afterRegisterOperator(
        address operator,
        uint32[] calldata operatorSetIds,
        bytes calldata data
    ) internal override {
        super._afterRegisterOperator(operator, operatorSetIds, data);

        // Set operator socket
        string memory socket = abi.decode(data, (string));
        _setOperatorSocket(operator, socket);
    }
}
