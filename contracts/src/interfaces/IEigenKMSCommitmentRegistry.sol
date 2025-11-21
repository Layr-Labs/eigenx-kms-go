// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

/**
 * @title IEigenKMSCommitmentRegistry
 * @notice Interface for the EigenKMS commitment registry
 */
interface IEigenKMSCommitmentRegistry {
    /// @notice Storage structure for operator commitments per epoch
    struct OperatorCommitment {
        bytes32 commitmentHash; // Hash of polynomial commitments
        bytes32 ackMerkleRoot; // Root of acknowledgement merkle tree
        uint256 submittedAt; // Block number when submitted
    }

    /// @notice Acknowledgement data for equivocation proof
    struct AckData {
        address player;
        uint64 dealerID;
        bytes32 shareHash;
        bytes32 commitmentHash;
        bytes32[] proof;
    }

    /// @notice Emitted when an operator submits their commitment
    event CommitmentSubmitted(
        uint64 indexed epoch, address indexed operator, bytes32 commitmentHash, bytes32 ackMerkleRoot
    );

    /// @notice Emitted when equivocation is proven
    event EquivocationProven(uint64 indexed epoch, address indexed dealer, address player1, address player2);

    /// @notice Emitted when curve type is updated
    event CurveTypeUpdated(uint8 oldCurveType, uint8 newCurveType);

    /// @notice Submit commitment hash and acknowledgement merkle root for an epoch
    function submitCommitment(uint64 epoch, bytes32 _commitmentHash, bytes32 _ackMerkleRoot) external;

    /// @notice Update the curve type used for operator validation
    function setCurveType(
        uint8 _curveType
    ) external;

    /// @notice Query commitment data for a specific operator and epoch
    function getCommitment(
        uint64 epoch,
        address operator
    ) external view returns (bytes32 commitmentHash, bytes32 ackMerkleRoot, uint256 submittedAt);

    /// @notice Prove equivocation by an operator
    function proveEquivocation(uint64 epoch, address dealer, AckData calldata ack1, AckData calldata ack2) external;
}
