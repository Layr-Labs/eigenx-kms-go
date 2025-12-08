// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

/**
 * @title IEigenKMSCommitmentRegistryErrors
 * @notice Custom errors for EigenKMSCommitmentRegistry
 */
interface IEigenKMSCommitmentRegistryErrors {
    /// @notice Thrown when commitment hash is zero
    /// @dev Selector: 0x29dd5dd0
    error InvalidCommitmentHash();

    /// @notice Thrown when merkle root is zero
    /// @dev Selector: 0x9dd854d3
    error InvalidMerkleRoot();

    /// @notice Thrown when operator has already submitted for this epoch
    /// @dev Selector: 0x1a85f740
    error CommitmentAlreadySubmitted();

    /// @notice Thrown when ECDSA verifier is not configured but curveType requires it
    /// @dev Selector: 0xf3d5ad20
    error ECDSAVerifierNotConfigured();

    /// @notice Thrown when BN254 verifier is not configured but curveType requires it
    /// @dev Selector: 0xcb3529b5
    error BN254VerifierNotConfigured();

    /// @notice Thrown when operator is not registered in the operator set (ECDSA)
    /// @dev Selector: 0xbec01e91
    error OperatorNotRegisteredECDSA();

    /// @notice Thrown when operator is not registered in the operator set (BN254)
    /// @dev Selector: 0x5deb4e33
    error OperatorNotRegisteredBN254();

    /// @notice Thrown when dealer has no commitment for the epoch
    /// @dev Selector: 0x5b07c989
    error NoCommitment();

    /// @notice Thrown when shareHashes are the same (not equivocation)
    /// @dev Selector: 0xdc3fa63c
    error ShareHashesMustDiffer();

    /// @notice Thrown when first ack is not in merkle tree
    /// @dev Selector: 0x7990605b
    error Ack1Invalid();

    /// @notice Thrown when second ack is not in merkle tree
    /// @dev Selector: 0xc00719db
    error Ack2Invalid();

    /// @notice Thrown when curve type is invalid (must be 1 or 2)
    /// @dev Selector: 0xfdea7c09
    error InvalidCurveType();
}
