// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {IEigenKMSRegistrar, IEigenKMSRegistrarTypes} from "./interfaces/IEigenKMSRegistrar.sol";

/**
 * @title IEigenKMSRegistrarStorage
 * @author Layr Labs, Inc.
 * @notice Storage contract for EigenKMSRegistrar
 * @dev This contract holds the storage variables for EigenKMSRegistrar
 */
abstract contract EigenKMSRegistrarStorage is IEigenKMSRegistrar {
    /// @notice Configuration for this AVS
    IEigenKMSRegistrarTypes.AvsConfig internal avsConfig;

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[48] private __gap;
}
