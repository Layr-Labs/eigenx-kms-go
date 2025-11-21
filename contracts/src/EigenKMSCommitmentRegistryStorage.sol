// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {IEigenKMSCommitmentRegistry} from "./interfaces/IEigenKMSCommitmentRegistry.sol";

/**
 * @title EigenKMSCommitmentRegistryStorage
 * @notice Storage contract for EigenKMSCommitmentRegistry
 * @dev This contract holds the storage variables for EigenKMSCommitmentRegistry
 */
abstract contract EigenKMSCommitmentRegistryStorage is IEigenKMSCommitmentRegistry {
    /// @notice Address of the AVS contract
    address public avs;

    /// @notice Operator set ID to use for this registry
    uint32 public operatorSetId;

    /// @notice Address of the ECDSA certificate verifier
    address public ecdsaCertificateVerifier;

    /// @notice Address of the BN254 certificate verifier
    address public bn254CertificateVerifier;

    /// @notice Curve type to use for operator validation (0 = Unknown, 1 = ECDSA, 2 = BN254)
    uint8 public curveType;

    /// @notice Mapping: epoch => operator => commitment data
    mapping(uint64 => mapping(address => OperatorCommitment)) public commitments;

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[44] private __gap;
}
