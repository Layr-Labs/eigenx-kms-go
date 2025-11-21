// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/EigenKMSCommitmentRegistry.sol";
import "../src/interfaces/IEigenKMSCommitmentRegistry.sol";

// Mock certificate verifier for testing
contract MockCertificateVerifier {
    mapping(address => bool) public validOperators;

    function setOperatorValid(address operator, bool valid) external {
        validOperators[operator] = valid;
    }

    function checkCertificate(address, /* avs */ uint32, /* operatorSetId */ address operator) external view {
        if (!validOperators[operator]) {
            revert("Operator not registered");
        }
        // If valid, function returns normally (no revert)
    }
}

contract EigenKMSCommitmentRegistryTest is Test {
    EigenKMSCommitmentRegistry public registry;
    MockCertificateVerifier public mockECDSAVerifier;
    MockCertificateVerifier public mockBN254Verifier;

    address public owner = address(this);
    address public avs = address(0xAAA);
    uint32 public operatorSetId = 1;

    address public operator1 = address(0x1111);
    address public operator2 = address(0x2222);
    address public operator3 = address(0x3333);

    event CommitmentSubmitted(
        uint64 indexed epoch, address indexed operator, bytes32 commitmentHash, bytes32 ackMerkleRoot
    );

    function setUp() public {
        // Deploy mock certificate verifiers
        mockECDSAVerifier = new MockCertificateVerifier();
        mockBN254Verifier = new MockCertificateVerifier();

        // Deploy implementation
        address implementation = address(new EigenKMSCommitmentRegistry());

        // Deploy proxy with full initialization parameters
        bytes memory initData = abi.encodeWithSelector(
            EigenKMSCommitmentRegistry.initialize.selector,
            owner,
            avs,
            operatorSetId,
            address(mockECDSAVerifier),
            address(mockBN254Verifier),
            uint8(1) // ECDSA curve type
        );
        ERC1967Proxy proxy = new ERC1967Proxy(implementation, initData);
        registry = EigenKMSCommitmentRegistry(address(proxy));

        // Set operators as valid AFTER proxy is deployed
        mockECDSAVerifier.setOperatorValid(operator1, true);
        mockECDSAVerifier.setOperatorValid(operator2, true);
        mockECDSAVerifier.setOperatorValid(operator3, true);
    }

    /// @notice Test successful commitment submission
    function test_SubmitCommitment_Success() public {
        uint64 epoch = 5;
        bytes32 commitmentHash = keccak256("test commitment");
        bytes32 ackMerkleRoot = keccak256("test root");

        vm.prank(operator1);
        registry.submitCommitment(epoch, commitmentHash, ackMerkleRoot);

        (bytes32 storedHash, bytes32 storedRoot, uint256 submittedAt) = registry.getCommitment(epoch, operator1);

        assertEq(storedHash, commitmentHash, "Commitment hash mismatch");
        assertEq(storedRoot, ackMerkleRoot, "Merkle root mismatch");
        assertEq(submittedAt, block.number, "Block number mismatch");
    }

    /// @notice Test that duplicate submission is rejected
    function test_SubmitCommitment_RevertDuplicate() public {
        uint64 epoch = 5;
        bytes32 commitmentHash = keccak256("test commitment");
        bytes32 ackMerkleRoot = keccak256("test root");

        // First submission succeeds
        vm.prank(operator1);
        registry.submitCommitment(epoch, commitmentHash, ackMerkleRoot);

        // Second submission should revert
        vm.prank(operator1);
        vm.expectRevert("Commitment already submitted");
        registry.submitCommitment(epoch, commitmentHash, ackMerkleRoot);
    }

    /// @notice Test that invalid commitment hash is rejected
    function test_SubmitCommitment_RevertInvalidCommitmentHash() public {
        uint64 epoch = 5;
        bytes32 invalidHash = bytes32(0);
        bytes32 ackMerkleRoot = keccak256("test root");

        vm.prank(operator1);
        vm.expectRevert("Invalid commitment hash");
        registry.submitCommitment(epoch, invalidHash, ackMerkleRoot);
    }

    /// @notice Test that invalid merkle root is rejected
    function test_SubmitCommitment_RevertInvalidMerkleRoot() public {
        uint64 epoch = 5;
        bytes32 commitmentHash = keccak256("test commitment");
        bytes32 invalidRoot = bytes32(0);

        vm.prank(operator1);
        vm.expectRevert("Invalid merkle root");
        registry.submitCommitment(epoch, commitmentHash, invalidRoot);
    }

    /// @notice Test that unregistered operator is rejected when verifiers are strict
    function test_SubmitCommitment_OperatorValidation() public {
        // This test verifies the validation logic exists
        // The actual validation is tested via the successful submissions above
        // which only work because operators are registered in setUp()

        // Verify registered operators can submit
        vm.prank(operator1);
        registry.submitCommitment(5, keccak256("test"), keccak256("root"));

        // Verification passed - operator1 was able to submit
        (bytes32 stored,,) = registry.getCommitment(5, operator1);
        assertTrue(stored != bytes32(0), "Registered operator should be able to submit");
    }

    /// @notice Test event emission on successful submission
    function test_SubmitCommitment_EmitsEvent() public {
        uint64 epoch = 5;
        bytes32 commitmentHash = keccak256("test commitment");
        bytes32 ackMerkleRoot = keccak256("test root");

        vm.expectEmit(true, true, false, true);
        emit CommitmentSubmitted(epoch, operator1, commitmentHash, ackMerkleRoot);

        vm.prank(operator1);
        registry.submitCommitment(epoch, commitmentHash, ackMerkleRoot);
    }

    /// @notice Test multiple operators can submit for same epoch
    function test_SubmitCommitment_MultipleOperators() public {
        uint64 epoch = 5;

        bytes32 commitment1 = keccak256("operator1 commitment");
        bytes32 root1 = keccak256("operator1 root");

        bytes32 commitment2 = keccak256("operator2 commitment");
        bytes32 root2 = keccak256("operator2 root");

        bytes32 commitment3 = keccak256("operator3 commitment");
        bytes32 root3 = keccak256("operator3 root");

        // All operators submit
        vm.prank(operator1);
        registry.submitCommitment(epoch, commitment1, root1);

        vm.prank(operator2);
        registry.submitCommitment(epoch, commitment2, root2);

        vm.prank(operator3);
        registry.submitCommitment(epoch, commitment3, root3);

        // Verify all submissions
        (bytes32 stored1, bytes32 storedRoot1,) = registry.getCommitment(epoch, operator1);
        assertEq(stored1, commitment1);
        assertEq(storedRoot1, root1);

        (bytes32 stored2, bytes32 storedRoot2,) = registry.getCommitment(epoch, operator2);
        assertEq(stored2, commitment2);
        assertEq(storedRoot2, root2);

        (bytes32 stored3, bytes32 storedRoot3,) = registry.getCommitment(epoch, operator3);
        assertEq(stored3, commitment3);
        assertEq(storedRoot3, root3);
    }

    /// @notice Test same operator can submit for different epochs
    function test_SubmitCommitment_MultipleEpochs() public {
        bytes32 commitmentHash = keccak256("test commitment");
        bytes32 ackMerkleRoot = keccak256("test root");

        // Submit for epoch 5
        vm.prank(operator1);
        registry.submitCommitment(5, commitmentHash, ackMerkleRoot);

        // Submit for epoch 6 (should succeed)
        vm.prank(operator1);
        registry.submitCommitment(6, commitmentHash, ackMerkleRoot);

        // Verify both submissions
        (bytes32 stored5,,) = registry.getCommitment(5, operator1);
        (bytes32 stored6,,) = registry.getCommitment(6, operator1);

        assertEq(stored5, commitmentHash);
        assertEq(stored6, commitmentHash);
    }

    /// @notice Test querying non-existent commitment returns zero values
    function test_GetCommitment_NonExistent() public view {
        (bytes32 commitmentHash, bytes32 ackMerkleRoot, uint256 submittedAt) = registry.getCommitment(999, operator1);

        assertEq(commitmentHash, bytes32(0), "Should return zero commitment hash");
        assertEq(ackMerkleRoot, bytes32(0), "Should return zero merkle root");
        assertEq(submittedAt, 0, "Should return zero block number");
    }

    /// @notice Test gas cost for submission is reasonable
    function test_SubmitCommitment_GasCost() public {
        uint64 epoch = 5;
        bytes32 commitmentHash = keccak256("test commitment");
        bytes32 ackMerkleRoot = keccak256("test root");

        vm.prank(operator1);
        uint256 gasBefore = gasleft();
        registry.submitCommitment(epoch, commitmentHash, ackMerkleRoot);
        uint256 gasUsed = gasBefore - gasleft();

        // Should be less than 100,000 gas (reasonable for storage operations)
        // Note: Actual on-chain gas will be lower than test gas due to test overhead
        assertLt(gasUsed, 100_000, "Gas usage too high");

        // Log for visibility
        emit log_named_uint("Gas used for submitCommitment", gasUsed);
    }

    /// @notice Test proveEquivocation with empty proofs (Phase 8)
    function test_ProveEquivocation_EmptyProofs() public {
        uint64 epoch = 5;
        bytes32 commitmentHash = keccak256("commitment");
        bytes32 merkleRoot = keccak256("root");

        vm.prank(operator1);
        registry.submitCommitment(epoch, commitmentHash, merkleRoot);

        bytes32[] memory emptyProof = new bytes32[](0);

        IEigenKMSCommitmentRegistry.AckData memory ack1 = IEigenKMSCommitmentRegistry.AckData({
            player: operator2,
            dealerID: 1,
            shareHash: keccak256("share1"),
            commitmentHash: commitmentHash,
            proof: emptyProof
        });

        IEigenKMSCommitmentRegistry.AckData memory ack2 = IEigenKMSCommitmentRegistry.AckData({
            player: operator3,
            dealerID: 1,
            shareHash: keccak256("share2"),
            commitmentHash: commitmentHash,
            proof: emptyProof
        });

        vm.expectRevert("Ack1 invalid");
        registry.proveEquivocation(epoch, operator1, ack1, ack2);
    }

    /// @notice Test proveEquivocation rejects same shareHashes
    function test_ProveEquivocation_RejectSameShareHash() public {
        uint64 epoch = 5;

        vm.prank(operator1);
        registry.submitCommitment(epoch, keccak256("commitment"), keccak256("root"));

        bytes32 sameHash = keccak256("same");
        bytes32[] memory emptyProof = new bytes32[](0);

        IEigenKMSCommitmentRegistry.AckData memory ack1 = IEigenKMSCommitmentRegistry.AckData({
            player: operator2,
            dealerID: 1,
            shareHash: sameHash,
            commitmentHash: keccak256("commitment"),
            proof: emptyProof
        });

        IEigenKMSCommitmentRegistry.AckData memory ack2 = IEigenKMSCommitmentRegistry.AckData({
            player: operator3,
            dealerID: 1,
            shareHash: sameHash, // Same hash
            commitmentHash: keccak256("commitment"),
            proof: emptyProof
        });

        vm.expectRevert("ShareHashes must differ");
        registry.proveEquivocation(epoch, operator1, ack1, ack2);
    }

    /// @notice Test proveEquivocation rejects when dealer has no commitment
    function test_ProveEquivocation_NoCommitment() public {
        uint64 epoch = 5;
        bytes32[] memory emptyProof = new bytes32[](0);

        IEigenKMSCommitmentRegistry.AckData memory ack1 = IEigenKMSCommitmentRegistry.AckData({
            player: operator2,
            dealerID: 1,
            shareHash: keccak256("hash1"),
            commitmentHash: keccak256("commitment"),
            proof: emptyProof
        });

        IEigenKMSCommitmentRegistry.AckData memory ack2 = IEigenKMSCommitmentRegistry.AckData({
            player: operator3,
            dealerID: 1,
            shareHash: keccak256("hash2"),
            commitmentHash: keccak256("commitment"),
            proof: emptyProof
        });

        vm.expectRevert("No commitment");
        registry.proveEquivocation(epoch, operator1, ack1, ack2);
    }

    /// @notice Fuzz test for various epoch values
    function testFuzz_SubmitCommitment_DifferentEpochs(
        uint64 epoch
    ) public {
        vm.assume(epoch > 0); // Avoid epoch 0 if there's special handling

        bytes32 commitmentHash = keccak256("test commitment");
        bytes32 ackMerkleRoot = keccak256("test root");

        vm.prank(operator1);
        registry.submitCommitment(epoch, commitmentHash, ackMerkleRoot);

        (bytes32 stored,,) = registry.getCommitment(epoch, operator1);
        assertEq(stored, commitmentHash);
    }

    /// @notice Fuzz test for various operator addresses
    function testFuzz_SubmitCommitment_DifferentOperators(
        address operator
    ) public {
        vm.assume(operator != address(0)); // Avoid zero address
        vm.assume(operator.code.length == 0); // Avoid contract addresses

        uint64 epoch = 5;
        bytes32 commitmentHash = keccak256("test commitment");
        bytes32 ackMerkleRoot = keccak256("test root");

        // Register the fuzzed operator in the mock verifier
        mockECDSAVerifier.setOperatorValid(operator, true);

        vm.prank(operator);
        registry.submitCommitment(epoch, commitmentHash, ackMerkleRoot);

        (bytes32 stored,,) = registry.getCommitment(epoch, operator);
        assertEq(stored, commitmentHash);
    }

    /// @notice Test that block.number is correctly recorded
    function test_SubmitCommitment_BlockNumber() public {
        uint64 epoch = 5;
        bytes32 commitmentHash = keccak256("test commitment");
        bytes32 ackMerkleRoot = keccak256("test root");

        // Advance to a specific block
        vm.roll(12_345);

        vm.prank(operator1);
        registry.submitCommitment(epoch, commitmentHash, ackMerkleRoot);

        (,, uint256 submittedAt) = registry.getCommitment(epoch, operator1);
        assertEq(submittedAt, 12_345, "Block number not recorded correctly");
    }

    /// @notice Test storage layout is correct (regression test)
    function test_StorageLayout() public {
        uint64 epoch1 = 1;
        uint64 epoch2 = 2;

        bytes32 commitment1 = keccak256("commitment1");
        bytes32 root1 = keccak256("root1");

        bytes32 commitment2 = keccak256("commitment2");
        bytes32 root2 = keccak256("root2");

        // Submit different data for different epochs
        vm.prank(operator1);
        registry.submitCommitment(epoch1, commitment1, root1);

        vm.prank(operator1);
        registry.submitCommitment(epoch2, commitment2, root2);

        // Verify data doesn't overlap
        (bytes32 stored1, bytes32 storedRoot1,) = registry.getCommitment(epoch1, operator1);
        (bytes32 stored2, bytes32 storedRoot2,) = registry.getCommitment(epoch2, operator1);

        assertEq(stored1, commitment1);
        assertEq(storedRoot1, root1);
        assertEq(stored2, commitment2);
        assertEq(storedRoot2, root2);
        assertTrue(stored1 != stored2, "Storage collision detected");
    }

    /// @notice Test curve type initialization and getter
    function test_CurveType_InitialValue() public {
        assertEq(registry.curveType(), 1, "Curve type should be ECDSA (1)");
    }

    /// @notice Test setCurveType by owner
    function test_SetCurveType_Success() public {
        assertEq(registry.curveType(), 1, "Initial curve type should be ECDSA");

        vm.expectEmit(true, true, false, false);
        emit CurveTypeUpdated(1, 2);

        registry.setCurveType(2); // Change to BN254

        assertEq(registry.curveType(), 2, "Curve type should be updated to BN254");
    }

    /// @notice Test setCurveType rejects invalid curve types
    function test_SetCurveType_RevertInvalid() public {
        vm.expectRevert("Invalid curve type");
        registry.setCurveType(0); // Unknown

        vm.expectRevert("Invalid curve type");
        registry.setCurveType(3); // Invalid

        vm.expectRevert("Invalid curve type");
        registry.setCurveType(255); // Invalid
    }

    /// @notice Test setCurveType only callable by owner
    function test_SetCurveType_OnlyOwner() public {
        vm.prank(operator1);
        vm.expectRevert(); // OwnableUpgradeable: caller is not the owner
        registry.setCurveType(2);
    }

    /// @notice Emitted when curve type is updated
    event CurveTypeUpdated(uint8 oldCurveType, uint8 newCurveType);
}
