// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title EigenKMSCommitmentRegistry
 * @notice Registry for storing operator commitments and acknowledgement merkle roots
 * @dev Each operator submits their polynomial commitment hash and ack merkle root per epoch
 *      This enables fraud detection while minimizing on-chain storage costs
 */
contract EigenKMSCommitmentRegistry {
    /// @notice Storage structure for operator commitments per epoch
    struct OperatorCommitment {
        bytes32 commitmentHash; // Hash of polynomial commitments
        bytes32 ackMerkleRoot; // Root of acknowledgement merkle tree
        uint256 submittedAt; // Block number when submitted
    }

    /// @notice Mapping: epoch => operator => commitment data
    mapping(uint64 => mapping(address => OperatorCommitment)) public commitments;

    /// @notice Emitted when an operator submits their commitment
    /// @param epoch The epoch number for this commitment
    /// @param operator The address of the operator submitting
    /// @param commitmentHash Hash of the operator's polynomial commitments
    /// @param ackMerkleRoot Root of the acknowledgement merkle tree
    event CommitmentSubmitted(
        uint64 indexed epoch, address indexed operator, bytes32 commitmentHash, bytes32 ackMerkleRoot
    );

    /**
     * @notice Submit commitment hash and acknowledgement merkle root for an epoch
     * @dev Can only be called once per operator per epoch
     * @param epoch The epoch number for this commitment
     * @param _commitmentHash Hash of polynomial commitments
     * @param _ackMerkleRoot Root of the acknowledgement merkle tree
     */
    function submitCommitment(uint64 epoch, bytes32 _commitmentHash, bytes32 _ackMerkleRoot) external {
        require(_commitmentHash != bytes32(0), "Invalid commitment hash");
        require(_ackMerkleRoot != bytes32(0), "Invalid merkle root");
        require(commitments[epoch][msg.sender].commitmentHash == bytes32(0), "Commitment already submitted");

        commitments[epoch][msg.sender] = OperatorCommitment({
            commitmentHash: _commitmentHash,
            ackMerkleRoot: _ackMerkleRoot,
            submittedAt: block.number
        });

        emit CommitmentSubmitted(epoch, msg.sender, _commitmentHash, _ackMerkleRoot);
    }

    /**
     * @notice Query commitment data for a specific operator and epoch
     * @param epoch The epoch number to query
     * @param operator The operator address to query
     * @return commitmentHash The commitment hash for this operator/epoch
     * @return ackMerkleRoot The ack merkle root for this operator/epoch
     * @return submittedAt The block number when this was submitted
     */
    function getCommitment(
        uint64 epoch,
        address operator
    ) external view returns (bytes32 commitmentHash, bytes32 ackMerkleRoot, uint256 submittedAt) {
        OperatorCommitment memory c = commitments[epoch][operator];
        return (c.commitmentHash, c.ackMerkleRoot, c.submittedAt);
    }

    /// @notice Acknowledgement data for equivocation proof
    struct AckData {
        address player;
        uint64 dealerID;
        bytes32 shareHash;
        bytes32 commitmentHash;
        bytes32[] proof;
    }

    /// @notice Emitted when equivocation is proven
    event EquivocationProven(uint64 indexed epoch, address indexed dealer, address player1, address player2);

    /**
     * @notice Prove that an operator equivocated by sending different shares to different players
     * @dev Verifies that both acks are in dealer's merkle tree but have different shareHashes
     * @param epoch The epoch in which equivocation occurred
     * @param dealer The operator who equivocated
     * @param ack1 First acknowledgement data
     * @param ack2 Second acknowledgement data
     */
    function proveEquivocation(uint64 epoch, address dealer, AckData calldata ack1, AckData calldata ack2) external {
        bytes32 root = commitments[epoch][dealer].ackMerkleRoot;
        require(root != bytes32(0), "No commitment");
        require(ack1.shareHash != ack2.shareHash, "ShareHashes must differ");

        bytes32 hash1 =
            keccak256(abi.encodePacked(ack1.player, ack1.dealerID, epoch, ack1.shareHash, ack1.commitmentHash));
        bytes32 hash2 =
            keccak256(abi.encodePacked(ack2.player, ack2.dealerID, epoch, ack2.shareHash, ack2.commitmentHash));

        require(MerkleProof.verify(ack1.proof, root, hash1), "Ack1 invalid");
        require(MerkleProof.verify(ack2.proof, root, hash2), "Ack2 invalid");

        emit EquivocationProven(epoch, dealer, ack1.player, ack2.player);
    }
}
