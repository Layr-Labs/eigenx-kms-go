// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Initializable} from "openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import {EigenKMSCommitmentRegistryStorage} from "./EigenKMSCommitmentRegistryStorage.sol";
import {ICertificateVerifier} from "./interfaces/ICertificateVerifier.sol";
import {IEigenKMSCommitmentRegistryErrors} from "./interfaces/IEigenKMSCommitmentRegistryErrors.sol";

/**
 * @title EigenKMSCommitmentRegistry
 * @notice Registry for storing operator commitments and acknowledgement merkle roots
 * @dev Each operator submits their polynomial commitment hash and ack merkle root per epoch
 *      This enables fraud detection while minimizing on-chain storage costs
 *      Upgradeable using UUPS pattern with storage separation
 */
contract EigenKMSCommitmentRegistry is
    Initializable,
    OwnableUpgradeable,
    EigenKMSCommitmentRegistryStorage,
    IEigenKMSCommitmentRegistryErrors
{
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the upgradeable contract
     * @param _owner Address to set as owner
     * @param _avs AVS contract address
     * @param _operatorSetId Operator set ID
     * @param _ecdsaCertificateVerifier ECDSA certificate verifier address
     * @param _bn254CertificateVerifier BN254 certificate verifier address
     * @param _curveType Curve type to use (1 = ECDSA, 2 = BN254)
     */
    function initialize(
        address _owner,
        address _avs,
        uint32 _operatorSetId,
        address _ecdsaCertificateVerifier,
        address _bn254CertificateVerifier,
        uint8 _curveType
    ) external initializer {
        if (_curveType != 1 && _curveType != 2) revert InvalidCurveType();
        __Ownable_init();
        _transferOwnership(_owner);

        avs = _avs;
        operatorSetId = _operatorSetId;
        ecdsaCertificateVerifier = _ecdsaCertificateVerifier;
        bn254CertificateVerifier = _bn254CertificateVerifier;
        curveType = _curveType;
    }

    /**
     * @notice Update the curve type used for operator validation
     * @dev Only callable by owner
     * @param _curveType New curve type (1 = ECDSA, 2 = BN254)
     */
    function setCurveType(
        uint8 _curveType
    ) external override onlyOwner {
        if (_curveType != 1 && _curveType != 2) revert InvalidCurveType();
        uint8 oldCurveType = curveType;
        curveType = _curveType;
        emit CurveTypeUpdated(oldCurveType, _curveType);
    }

    /**
     * @notice Submit commitment hash and acknowledgement merkle root for an epoch
     * @dev Can only be called once per operator per epoch
     *      Validates operator is registered in the configured operator set
     * @param epoch The epoch number for this commitment
     * @param _commitmentHash Hash of polynomial commitments
     * @param _ackMerkleRoot Root of the acknowledgement merkle tree
     */
    function submitCommitment(uint64 epoch, bytes32 _commitmentHash, bytes32 _ackMerkleRoot) external override {
        if (_commitmentHash == bytes32(0)) revert InvalidCommitmentHash();
        if (_ackMerkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (commitments[epoch][msg.sender].commitmentHash != bytes32(0)) revert CommitmentAlreadySubmitted();

        // TODO(seanmcgary): integrate with certificate verifier
        // Validate operator is registered using the configured curve type
        // if (curveType == 1) {
        //     // ECDSA validation
        //     if (ecdsaCertificateVerifier == address(0)) revert ECDSAVerifierNotConfigured();
        //     if (!_isValidOperator(msg.sender, ecdsaCertificateVerifier)) revert OperatorNotRegisteredECDSA();
        // } else if (curveType == 2) {
        //     // BN254 validation
        //     if (bn254CertificateVerifier == address(0)) revert BN254VerifierNotConfigured();
        //     if (!_isValidOperator(msg.sender, bn254CertificateVerifier)) revert OperatorNotRegisteredBN254();
        // }
        // curveType == 0 (Unknown) allows any operator (for testing/development)

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
    ) external view override returns (bytes32 commitmentHash, bytes32 ackMerkleRoot, uint256 submittedAt) {
        OperatorCommitment memory c = commitments[epoch][operator];
        return (c.commitmentHash, c.ackMerkleRoot, c.submittedAt);
    }

    /**
     * @notice Prove that an operator equivocated by sending different shares to different players
     * @dev Verifies that both acks are in dealer's merkle tree but have different shareHashes
     * @param epoch The epoch in which equivocation occurred
     * @param dealer The operator who equivocated
     * @param ack1 First acknowledgement data
     * @param ack2 Second acknowledgement data
     */
    function proveEquivocation(
        uint64 epoch,
        address dealer,
        AckData calldata ack1,
        AckData calldata ack2
    ) external override {
        bytes32 root = commitments[epoch][dealer].ackMerkleRoot;
        if (root == bytes32(0)) revert NoCommitment();
        if (ack1.shareHash == ack2.shareHash) revert ShareHashesMustDiffer();

        bytes32 hash1 =
            keccak256(abi.encodePacked(ack1.player, ack1.dealerID, epoch, ack1.shareHash, ack1.commitmentHash));
        bytes32 hash2 =
            keccak256(abi.encodePacked(ack2.player, ack2.dealerID, epoch, ack2.shareHash, ack2.commitmentHash));

        if (!MerkleProof.verify(ack1.proof, root, hash1)) revert Ack1Invalid();
        if (!MerkleProof.verify(ack2.proof, root, hash2)) revert Ack2Invalid();

        emit EquivocationProven(epoch, dealer, ack1.player, ack2.player);

        // Note: Actual slashing would integrate with EigenLayer here
        // Future: Add slashing logic via AVS service manager
    }

    // ============ INTERNAL FUNCTIONS ============

    /**
     * @dev Check if an operator is valid in the configured operator set
     * @param operator The operator address to check
     * @param certificateVerifier The certificate verifier to use
     * @return bool True if operator has valid certificate
     */
    function _isValidOperator(address operator, address certificateVerifier) internal view returns (bool) {
        if (certificateVerifier == address(0)) {
            return false;
        }

        try ICertificateVerifier(certificateVerifier).checkCertificate(avs, operatorSetId, operator) {
            return true;
        } catch {
            return false;
        }
    }
}
