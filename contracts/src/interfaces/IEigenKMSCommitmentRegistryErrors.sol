// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

/**
 * @title IEigenKMSCommitmentRegistryErrors
 * @notice Custom errors for EigenKMSCommitmentRegistry
 */
interface IEigenKMSCommitmentRegistryErrors {
    /// @notice Thrown when commitment hash is zero
    error InvalidCommitmentHash();

    /// @notice Thrown when merkle root is zero
    error InvalidMerkleRoot();

    /// @notice Thrown when operator has already submitted for this epoch
    error CommitmentAlreadySubmitted();

    /// @notice Thrown when ECDSA verifier is not configured but curveType requires it
    error ECDSAVerifierNotConfigured();

    /// @notice Thrown when BN254 verifier is not configured but curveType requires it
    error BN254VerifierNotConfigured();

    /// @notice Thrown when operator is not registered in the operator set (ECDSA)
    error OperatorNotRegisteredECDSA();

    /// @notice Thrown when operator is not registered in the operator set (BN254)
    error OperatorNotRegisteredBN254();

    /// @notice Thrown when dealer has no commitment for the epoch
    error NoCommitment();

    /// @notice Thrown when shareHashes are the same (not equivocation)
    error ShareHashesMustDiffer();

    /// @notice Thrown when first ack is not in merkle tree
    error Ack1Invalid();

    /// @notice Thrown when second ack is not in merkle tree
    error Ack2Invalid();

    /// @notice Thrown when curve type is invalid (must be 1 or 2)
    error InvalidCurveType();
}
