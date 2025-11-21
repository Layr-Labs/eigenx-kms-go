// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

/**
 * @title ICertificateVerifier
 * @notice Interface for operator certificate verification
 * @dev Verifies that an operator is registered in a specific operator set
 */
interface ICertificateVerifier {
    /**
     * @notice Check if an operator has a valid certificate for the operator set
     * @param avs The AVS address
     * @param operatorSetId The operator set ID
     * @param operator The operator address to check
     * @dev Reverts if the operator does not have a valid certificate
     */
    function checkCertificate(address avs, uint32 operatorSetId, address operator) external view;
}
