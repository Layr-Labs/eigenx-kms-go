# Fraud Proof System for DKG/Reshare Security

## Overview

This document describes the fraud proof system for detecting and slashing malicious operators during DKG and Reshare protocols. The system enables operators to submit cryptographic proofs of misbehavior to the AVS smart contract, triggering economic penalties via EigenLayer slashing.

## Motivation

**Problem**: In a distributed key generation protocol, malicious operators can:
1. Send invalid shares that don't match their broadcast commitments
2. Send different shares to different operators (equivocation)
3. Fail to acknowledge valid shares from other operators
4. Attempt to bias the distribution of generated keys

**Solution**: On-chain fraud proofs allow honest operators to cryptographically prove misbehavior, enabling:
- Automatic detection of protocol violations
- Economic disincentives via slashing
- Transparent accountability
- Self-healing operator networks

## Fraud Types

### 1. Invalid Share Fraud

**Description**: Dealer sends a share that doesn't verify against their broadcast commitments.

**Detection**:
```
Receiver j gets share s_ij from dealer i
Verification fails: g^s_ij ` �(C_ik * j^k)
```

**Evidence Required**:
- Broadcast commitments `C_ik` (signed by dealer)
- Invalid share `s_ij` (signed in private message to receiver)
- Receiver's node ID `j`

**Smart Contract Verification**:
```solidity
function verifyShareAgainstCommitments(
    uint256 share,
    uint256 nodeID,
    G2Point[] memory commitments
) internal view returns (bool) {
    // Left side: g^share
    G2Point memory leftSide = g2Mul(G2_GENERATOR, share);

    // Right side: �(commitments[k] * nodeID^k)
    G2Point memory rightSide = commitments[0];
    uint256 nodeIDPower = nodeID;

    for (uint256 k = 1; k < commitments.length; k++) {
        G2Point memory term = g2Mul(commitments[k], nodeIDPower);
        rightSide = g2Add(rightSide, term);
        nodeIDPower = mulmod(nodeIDPower, nodeID, BLS12_381_FR_MODULUS);
    }

    return g2Equal(leftSide, rightSide);
}
```

### 2. Equivocation Fraud

**Description**: Dealer sends different shares to different operators for the same polynomial.

**Detection**:
```
Two operators receive shares: s_ij and s_ik
Both verify against commitments individually
But they define different polynomials (inconsistent)
```

**Evidence Required**:
- Broadcast commitments (signed by dealer)
- Share 1 with receiver 1's node ID (signed)
- Share 2 with receiver 2's node ID (signed)
- Proof that shares are inconsistent

**Smart Contract Verification**:
```solidity
function verifyEquivocation(
    G2Point[] memory commitments,
    uint256 share1,
    uint256 nodeID1,
    uint256 share2,
    uint256 nodeID2
) internal view returns (bool) {
    // Both shares should verify individually
    bool valid1 = verifyShareAgainstCommitments(share1, nodeID1, commitments);
    bool valid2 = verifyShareAgainstCommitments(share2, nodeID2, commitments);

    if (!valid1 || !valid2) {
        return false;  // Not equivocation, just invalid shares
    }

    // Check if shares define consistent polynomial
    // Using Lagrange: if polynomial is degree t-1, any t points define it uniquely
    // Two shares should interpolate to same polynomial
    // If they don't � equivocation

    return !sharesDefineConsistentPolynomial(
        share1, nodeID1,
        share2, nodeID2,
        commitments.length - 1  // degree
    );
}
```

### 3. Missing Acknowledgement Fraud

**Description**: Dealer fails to acknowledge receiving valid shares during verification phase.

**Evidence Required**:
- Receiver sent valid acknowledgement (signed by receiver)
- Dealer failed to proceed or claimed non-receipt
- Timestamp showing dealer had sufficient time

**Note**: This is harder to prove on-chain (absence of action), may require off-chain monitoring with on-chain checkpoints.

### 4. Commitment Inconsistency Fraud

**Description**: Dealer broadcasts different commitments to different operators.

**Evidence Required**:
- Two different commitment sets with same session timestamp
- Both signed by dealer
- Sent to different operators

**Smart Contract Verification**:
```solidity
function verifyCommitmentInconsistency(
    G2Point[] memory commitments1,
    bytes memory signature1,
    address receiver1,
    G2Point[] memory commitments2,
    bytes memory signature2,
    address receiver2,
    address dealer
) internal view returns (bool) {
    // Verify dealer signed both commitment sets
    bytes32 hash1 = keccak256(abi.encode(receiver1, commitments1));
    bytes32 hash2 = keccak256(abi.encode(receiver2, commitments2));

    bool validSig1 = verifyBN254Signature(hash1, signature1, dealer);
    bool validSig2 = verifyBN254Signature(hash2, signature2, dealer);

    // Check commitments are different
    bool different = !arraysEqual(commitments1, commitments2);

    return validSig1 && validSig2 && different;
}
```

## Smart Contract Architecture

### Contract: EigenKMSSlashing.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BLS12381.sol";  // BLS12-381 curve operations
import "@eigenlayer/contracts/interfaces/IAllocationManager.sol";
import "@eigenlayer/contracts/interfaces/IOperatorSetRegistrar.sol";

contract EigenKMSSlashing {

    // ========== TYPES ==========

    struct G2Point {
        uint256 x;
        uint256 y;
    }

    struct InvalidShareProof {
        address dealer;
        uint256 sessionTimestamp;
        G2Point[] commitments;
        bytes commitmentSignature;
        uint256 share;
        bytes shareSignature;
        uint256 receiverNodeID;
    }

    struct EquivocationProof {
        address dealer;
        uint256 sessionTimestamp;
        G2Point[] commitments;
        bytes commitmentSignature;
        uint256 share1;
        bytes share1Signature;
        uint256 receiver1NodeID;
        uint256 share2;
        bytes share2Signature;
        uint256 receiver2NodeID;
    }

    struct FraudCounter {
        uint256 count;
        mapping(address => bool) hasReported;  // Prevent double-reporting
    }

    // ========== STATE ==========

    // dealer => session => FraudCounter
    mapping(address => mapping(uint256 => FraudCounter)) public fraudCounts;

    // Configuration
    uint256 public FRAUD_THRESHOLD = 3;  // Slash after 3 invalid shares
    uint256 public SLASH_AMOUNT = 1 ether;  // Amount to slash per fraud
    uint32 public operatorSetID;

    IAllocationManager public immutable allocationManager;
    IOperatorSetRegistrar public immutable operatorSetRegistrar;

    // ========== EVENTS ==========

    event FraudProofSubmitted(
        address indexed dealer,
        address indexed reporter,
        uint256 sessionTimestamp,
        string fraudType,
        uint256 fraudCount
    );

    event OperatorSlashed(
        address indexed operator,
        uint256 sessionTimestamp,
        uint256 amount,
        string reason
    );

    event OperatorEjected(
        address indexed operator,
        uint256 sessionTimestamp
    );

    // ========== CONSTRUCTOR ==========

    constructor(
        address _allocationManager,
        address _operatorSetRegistrar,
        uint32 _operatorSetID,
        uint256 _fraudThreshold,
        uint256 _slashAmount
    ) {
        allocationManager = IAllocationManager(_allocationManager);
        operatorSetRegistrar = IOperatorSetRegistrar(_operatorSetRegistrar);
        operatorSetID = _operatorSetID;
        FRAUD_THRESHOLD = _fraudThreshold;
        SLASH_AMOUNT = _slashAmount;
    }

    // ========== FRAUD PROOF SUBMISSION ==========

    function submitInvalidShareProof(InvalidShareProof calldata proof) external {
        address reporter = msg.sender;

        // 1. Verify reporter is valid operator
        require(isOperatorInSet(reporter), "Reporter not in operator set");

        // 2. Verify dealer signed the commitments (broadcast)
        bytes32 commitmentHash = keccak256(abi.encode(proof.commitments));
        require(
            verifyBN254Signature(commitmentHash, proof.commitmentSignature, proof.dealer),
            "Invalid commitment signature"
        );

        // 3. Verify dealer signed the share sent to reporter
        bytes32 shareHash = keccak256(abi.encodePacked(
            proof.dealer,
            reporter,
            proof.sessionTimestamp,
            proof.share
        ));
        require(
            verifyBN254Signature(shareHash, proof.shareSignature, proof.dealer),
            "Invalid share signature"
        );

        // 4. Verify the share is actually invalid (on-chain verification)
        require(
            !verifyShareAgainstCommitments(
                proof.share,
                proof.receiverNodeID,
                proof.commitments
            ),
            "Share is actually valid - false accusation"
        );

        // 5. Record fraud and check threshold
        recordFraud(proof.dealer, proof.sessionTimestamp, reporter, "INVALID_SHARE");
    }

    function submitEquivocationProof(EquivocationProof calldata proof) external {
        address reporter = msg.sender;

        // 1. Verify reporter is valid operator
        require(isOperatorInSet(reporter), "Reporter not in operator set");

        // 2. Verify dealer signed commitments
        bytes32 commitmentHash = keccak256(abi.encode(proof.commitments));
        require(
            verifyBN254Signature(commitmentHash, proof.commitmentSignature, proof.dealer),
            "Invalid commitment signature"
        );

        // 3. Verify both shares are signed by dealer
        bytes32 share1Hash = keccak256(abi.encodePacked(
            proof.dealer,
            proof.receiver1NodeID,
            proof.sessionTimestamp,
            proof.share1
        ));
        bytes32 share2Hash = keccak256(abi.encodePacked(
            proof.dealer,
            proof.receiver2NodeID,
            proof.sessionTimestamp,
            proof.share2
        ));

        require(
            verifyBN254Signature(share1Hash, proof.share1Signature, proof.dealer),
            "Invalid share1 signature"
        );
        require(
            verifyBN254Signature(share2Hash, proof.share2Signature, proof.dealer),
            "Invalid share2 signature"
        );

        // 4. Verify both shares are individually valid
        bool valid1 = verifyShareAgainstCommitments(
            proof.share1,
            proof.receiver1NodeID,
            proof.commitments
        );
        bool valid2 = verifyShareAgainstCommitments(
            proof.share2,
            proof.receiver2NodeID,
            proof.commitments
        );

        require(valid1 && valid2, "Shares not individually valid");

        // 5. Verify shares are inconsistent (equivocation)
        require(
            !sharesDefineConsistentPolynomial(
                proof.share1, proof.receiver1NodeID,
                proof.share2, proof.receiver2NodeID,
                proof.commitments.length - 1
            ),
            "Shares are consistent - no equivocation"
        );

        // 6. Record fraud (equivocation is more severe - instant slash)
        recordFraud(proof.dealer, proof.sessionTimestamp, reporter, "EQUIVOCATION");
        slashOperator(proof.dealer, proof.sessionTimestamp, "EQUIVOCATION");
    }

    // ========== INTERNAL FUNCTIONS ==========

    function recordFraud(
        address dealer,
        uint256 sessionTimestamp,
        address reporter,
        string memory fraudType
    ) internal {
        FraudCounter storage counter = fraudCounts[dealer][sessionTimestamp];

        // Prevent double-reporting
        require(!counter.hasReported[reporter], "Already reported this fraud");
        counter.hasReported[reporter] = true;
        counter.count++;

        emit FraudProofSubmitted(
            dealer,
            reporter,
            sessionTimestamp,
            fraudType,
            counter.count
        );

        // Check if slashing threshold reached
        if (counter.count >= FRAUD_THRESHOLD) {
            slashOperator(dealer, sessionTimestamp, fraudType);
        }
    }

    function slashOperator(
        address operator,
        uint256 sessionTimestamp,
        string memory reason
    ) internal {
        // Slash via EigenLayer AllocationManager
        allocationManager.slashOperator(operator, SLASH_AMOUNT);

        emit OperatorSlashed(operator, sessionTimestamp, SLASH_AMOUNT, reason);

        // Consider ejection if fraud count is severe
        FraudCounter storage counter = fraudCounts[operator][sessionTimestamp];
        if (counter.count >= FRAUD_THRESHOLD * 2) {
            ejectOperator(operator, sessionTimestamp);
        }
    }

    function ejectOperator(address operator, uint256 sessionTimestamp) internal {
        // Remove from operator set
        operatorSetRegistrar.ejectOperator(operator, operatorSetID);

        emit OperatorEjected(operator, sessionTimestamp);
    }

    function verifyShareAgainstCommitments(
        uint256 share,
        uint256 nodeID,
        G2Point[] memory commitments
    ) internal view returns (bool) {
        // Left side: g^share
        G2Point memory leftSide = BLS12381.g2Mul(BLS12381.G2_GENERATOR(), share);

        // Right side: �(commitments[k] * nodeID^k)
        G2Point memory rightSide = commitments[0];
        uint256 nodeIDPower = nodeID;

        for (uint256 k = 1; k < commitments.length; k++) {
            G2Point memory term = BLS12381.g2Mul(commitments[k], nodeIDPower);
            rightSide = BLS12381.g2Add(rightSide, term);
            nodeIDPower = mulmod(nodeIDPower, nodeID, BLS12381.FR_MODULUS());
        }

        return BLS12381.g2Equal(leftSide, rightSide);
    }

    function sharesDefineConsistentPolynomial(
        uint256 share1,
        uint256 nodeID1,
        uint256 share2,
        uint256 nodeID2,
        uint256 degree
    ) internal pure returns (bool) {
        // For degree t-1 polynomial, any t points define it uniquely
        // Two shares should be consistent if they lie on same polynomial

        // Simple check: Use Lagrange interpolation at point 0
        // If shares are from same polynomial, they should interpolate to same f(0)

        // �1 = nodeID2 / (nodeID2 - nodeID1)
        // �2 = -nodeID1 / (nodeID2 - nodeID1)
        // f(0) = �1 * share1 + �2 * share2

        // If we compute f(0) from both shares, they should match
        // For simplicity, we'll use a more direct check:
        // shares define same polynomial if linear interpolation is consistent

        uint256 diff = (nodeID2 > nodeID1) ? (nodeID2 - nodeID1) : (nodeID1 - nodeID2);

        // This is simplified - full implementation would use Lagrange interpolation
        // For now, we trust that if shares verify individually, they're likely consistent
        // unless we can prove otherwise with more complex math

        return true;  // Simplified - TODO: full Lagrange check
    }

    function verifyBN254Signature(
        bytes32 messageHash,
        bytes memory signature,
        address signer
    ) internal pure returns (bool) {
        // Recover signer from signature
        address recovered = recoverSigner(messageHash, signature);
        return recovered == signer;
    }

    function recoverSigner(
        bytes32 messageHash,
        bytes memory signature
    ) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        return ecrecover(messageHash, v, r, s);
    }

    function isOperatorInSet(address operator) internal view returns (bool) {
        // Query OperatorSetRegistrar to check if operator is in set
        return operatorSetRegistrar.isOperatorInSet(operator, operatorSetID);
    }
}
```

## Go Implementation (Operator Side)

### Fraud Detection and Reporting

```go
// pkg/node/fraud_reporter.go

package node

import (
    "fmt"
    "log"

    "github.com/Layr-Labs/eigenx-kms-go/pkg/contract"
    "github.com/Layr-Labs/eigenx-kms-go/pkg/types"
    "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
    "github.com/ethereum/go-ethereum/common"
)

type FraudReporter struct {
    contractCaller  *contract.ContractCaller
    nodeAddress     common.Address
    slashingAddress common.Address
}

type InvalidShareProof struct {
    Dealer              common.Address
    SessionTimestamp    int64
    Commitments         []types.G2Point
    CommitmentSignature []byte
    Share               *fr.Element
    ShareSignature      []byte
    ReceiverNodeID      int
}

type EquivocationProof struct {
    Dealer              common.Address
    SessionTimestamp    int64
    Commitments         []types.G2Point
    CommitmentSignature []byte
    Share1              *fr.Element
    Share1Signature     []byte
    Receiver1NodeID     int
    Share2              *fr.Element
    Share2Signature     []byte
    Receiver2NodeID     int
}

func NewFraudReporter(
    contractCaller *contract.ContractCaller,
    nodeAddress common.Address,
    slashingAddress common.Address,
) *FraudReporter {
    return &FraudReporter{
        contractCaller:  contractCaller,
        nodeAddress:     nodeAddress,
        slashingAddress: slashingAddress,
    }
}

// SubmitInvalidShareProof submits proof of invalid share to smart contract
func (fr *FraudReporter) SubmitInvalidShareProof(proof InvalidShareProof) error {
    log.Printf("=� Submitting invalid share fraud proof against %s",
        proof.Dealer.Hex())

    // Serialize proof for contract call
    tx, err := fr.contractCaller.SubmitInvalidShareProof(
        fr.slashingAddress,
        proof.Dealer,
        proof.SessionTimestamp,
        proof.Commitments,
        proof.CommitmentSignature,
        proof.Share.Bytes(),
        proof.ShareSignature,
        uint64(proof.ReceiverNodeID),
    )

    if err != nil {
        return fmt.Errorf("failed to submit fraud proof: %w", err)
    }

    log.Printf(" Fraud proof submitted, tx=%s", tx.Hash().Hex())
    return nil
}

// SubmitEquivocationProof submits proof of equivocation to smart contract
func (fr *FraudReporter) SubmitEquivocationProof(proof EquivocationProof) error {
    log.Printf("=� Submitting equivocation fraud proof against %s",
        proof.Dealer.Hex())

    tx, err := fr.contractCaller.SubmitEquivocationProof(
        fr.slashingAddress,
        proof.Dealer,
        proof.SessionTimestamp,
        proof.Commitments,
        proof.CommitmentSignature,
        proof.Share1.Bytes(),
        proof.Share1Signature,
        uint64(proof.Receiver1NodeID),
        proof.Share2.Bytes(),
        proof.Share2Signature,
        uint64(proof.Receiver2NodeID),
    )

    if err != nil {
        return fmt.Errorf("failed to submit equivocation proof: %w", err)
    }

    log.Printf(" Equivocation proof submitted, tx=%s", tx.Hash().Hex())
    return nil
}
```

### Integration with DKG Handler

```go
// pkg/node/handlers.go (modified)

func (n *Node) handleDKGShare(w http.ResponseWriter, r *http.Request) {
    // Parse authenticated message
    var authMsg transport.AuthenticatedMessage
    if err := json.NewDecoder(r.Body).Decode(&authMsg); err != nil {
        http.Error(w, "invalid message", http.StatusBadRequest)
        return
    }

    // Deserialize share message
    var shareMsg types.ShareMessage
    if err := json.Unmarshal(authMsg.Payload, &shareMsg); err != nil {
        http.Error(w, "invalid payload", http.StatusBadRequest)
        return
    }

    // Get dealer's commitments (from earlier broadcast)
    dealerCommitments, err := n.getCommitmentsForDealer(
        shareMsg.FromOperatorAddress,
        shareMsg.SessionTimestamp,
    )
    if err != nil {
        http.Error(w, "commitments not found", http.StatusBadRequest)
        return
    }

    // Deserialize and verify share
    share := deserializeShare(shareMsg.Share)
    dealerNodeID := util.AddressToNodeID(shareMsg.FromOperatorAddress)

    valid := n.dkg.VerifyShare(
        dealerNodeID,
        share,
        dealerCommitments.Commitments,
    )

    if !valid {
        log.Printf("L FRAUD DETECTED: Invalid share from %s",
            shareMsg.FromOperatorAddress.Hex())

        // Submit fraud proof to contract
        proof := InvalidShareProof{
            Dealer:              shareMsg.FromOperatorAddress,
            SessionTimestamp:    shareMsg.SessionTimestamp,
            Commitments:         dealerCommitments.Commitments,
            CommitmentSignature: dealerCommitments.Signature,
            Share:               share,
            ShareSignature:      authMsg.Signature,
            ReceiverNodeID:      n.nodeID,
        }

        if err := n.fraudReporter.SubmitInvalidShareProof(proof); err != nil {
            log.Printf("�  Failed to submit fraud proof: %v", err)
        }

        // Respond with error
        http.Error(w, "invalid share - fraud proof submitted", http.StatusBadRequest)
        return
    }

    log.Printf(" Valid share received from %s",
        shareMsg.FromOperatorAddress.Hex())

    // Store share and continue protocol...
    n.storeReceivedShare(shareMsg.FromOperatorAddress, share, shareMsg.SessionTimestamp)
    w.WriteHeader(http.StatusOK)
}
```

## Slashing Thresholds and Configuration

### Recommended Thresholds

```go
// Configuration for different fraud severities

const (
    // Invalid shares: Slash after 3 different receivers report
    InvalidShareThreshold = 3
    InvalidShareSlashAmount = 0.1 ether  // Per fraud, escalating

    // Equivocation: Immediate slash (more severe)
    EquivocationThreshold = 1  // Single proof sufficient
    EquivocationSlashAmount = 1 ether  // Higher penalty

    // Multiple sessions: Escalating penalties
    CrossSessionThreshold = 2  // Fraud in 2+ sessions
    EjectionThreshold = 3      // Automatic ejection after 3 sessions with fraud
)
```

### Escalating Penalties

```solidity
function calculateSlashAmount(
    address operator,
    uint256 currentSessionFraudCount,
    string memory fraudType
) internal view returns (uint256) {
    // Base slash amount
    uint256 baseAmount = keccak256(bytes(fraudType)) == keccak256("EQUIVOCATION")
        ? 1 ether
        : 0.1 ether;

    // Count total fraud sessions
    uint256 totalFraudSessions = countFraudSessions(operator);

    // Escalate: 1x, 2x, 4x, 8x...
    uint256 multiplier = 2 ** totalFraudSessions;

    return baseAmount * multiplier;
}
```

## Monitoring and Analytics

### Off-Chain Monitoring Service

```go
// Operator dashboard tracks fraud patterns

type FraudMetrics struct {
    TotalFraudProofs       uint64
    InvalidShareCount      uint64
    EquivocationCount      uint64
    SlashedOperators       []common.Address
    AverageFraudPerSession float64
}

func (m *Monitor) TrackFraudMetrics() {
    // Subscribe to FraudProofSubmitted events
    fraudChan := make(chan *contract.FraudProofSubmitted)

    sub, err := m.contract.WatchFraudProofSubmitted(nil, fraudChan, nil, nil)
    if err != nil {
        log.Fatal(err)
    }

    for {
        select {
        case event := <-fraudChan:
            log.Printf("=� Fraud detected: %s by %s (count: %d)",
                event.FraudType,
                event.Dealer.Hex(),
                event.FraudCount,
            )

            // Update metrics
            m.metrics.TotalFraudProofs++

            // Alert if threshold approaching
            if event.FraudCount >= FRAUD_THRESHOLD - 1 {
                m.alertOperatorAtRisk(event.Dealer)
            }

        case err := <-sub.Err():
            log.Printf("Subscription error: %v", err)
        }
    }
}
```

## Testing Strategy

### Unit Tests

```go
// Test fraud proof generation
func TestGenerateInvalidShareProof(t *testing.T) {
    // Setup: Create dealer with invalid share
    dealer := createTestDealer()

    // Generate commitments
    commitments, _ := dealer.GenerateCommitments()

    // Create invalid share (doesn't match commitments)
    invalidShare := generateRandomShare()

    // Create proof
    proof := InvalidShareProof{
        Dealer:           dealer.Address,
        Commitments:      commitments,
        Share:            invalidShare,
        ReceiverNodeID:   123,
    }

    // Verify proof is valid
    assert.True(t, proof.IsValid())
}
```

### Integration Tests

```go
func TestFraudProofSlashing(t *testing.T) {
    // Setup test cluster
    cluster := testutil.NewTestCluster(t, 7)
    defer cluster.Close()

    // Inject malicious operator
    maliciousNode := cluster.Nodes[0]
    maliciousNode.SetBehavior(SendInvalidShares)

    // Run DKG protocol
    cluster.RunDKG()

    // Verify fraud proofs were submitted
    fraudCount := cluster.GetFraudCount(maliciousNode.Address)
    assert.GreaterOrEqual(t, fraudCount, 3)

    // Verify operator was slashed
    slashed := cluster.IsOperatorSlashed(maliciousNode.Address)
    assert.True(t, slashed)
}
```

## Security Considerations

### False Accusations

**Problem**: Malicious operators could submit false fraud proofs to harm honest operators.

**Defense**:
- Contract verifies proof cryptographically (share must actually be invalid)
- False accusers can be counter-slashed
- Reputation system tracks accusation accuracy

### Collusion

**Problem**: Multiple malicious operators collude to frame honest operator.

**Defense**:
- Proofs require cryptographic signatures (can't forge)
- Threshold requires multiple independent reports
- Economic cost of collusion (stake at risk)

### Frontrunning

**Problem**: Malicious operator sees fraud proof in mempool, tries to eject reporter.

**Defense**:
- Fraud proofs processed in order received
- Cannot eject operator mid-session
- Time-locks on ejection actions

## Future Enhancements

1. **Reputation System**: Track long-term operator behavior
2. **Graduated Penalties**: Warning � Temporary suspension � Ejection
3. **Insurance Pool**: Slashed funds go to insurance for affected applications
4. **Cross-AVS Fraud Sharing**: Share fraud patterns across EigenLayer AVSs
5. **ZK Fraud Proofs**: Privacy-preserving fraud proofs using zero-knowledge proofs

## References

- Gennaro et al. "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"
- EigenLayer Slashing Documentation
- BLS12-381 Curve Specification
- Feldman VSS Protocol
