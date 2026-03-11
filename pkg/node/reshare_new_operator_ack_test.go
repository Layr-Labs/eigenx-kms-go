package node

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/reshare"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/util"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// setupReshareTestOperators creates test operators using ChainConfig and generates
// reshare shares from each dealer to the target (new) operator.
func setupReshareTestOperators(t *testing.T, numDealers int) (
	operators []*peering.OperatorSetPeer,
	targetNodeID int64,
	shares map[int64]*fr.Element,
	commitmentsByDealer map[int64][]types.G2Point,
) {
	t.Helper()

	// Use numDealers+1 operators: dealers are operators[0..numDealers-1], new operator is operators[numDealers]
	allOps := createTestOperatorsFromChainConfig(t, numDealers+1)
	operators = allOps
	newOp := allOps[numDealers]
	targetNodeID = util.AddressToNodeID(newOp.OperatorAddress)

	shares = make(map[int64]*fr.Element)
	commitmentsByDealer = make(map[int64][]types.G2Point)

	threshold := dkg.CalculateThreshold(len(allOps))

	for i := 0; i < numDealers; i++ {
		dealerNodeID := util.AddressToNodeID(allOps[i].OperatorAddress)
		r := reshare.NewReshare(dealerNodeID, allOps)

		currentShare := new(fr.Element)
		_, _ = currentShare.SetRandom()

		generatedShares, commitments, err := r.GenerateNewShares(currentShare, threshold)
		require.NoError(t, err)

		shares[dealerNodeID] = generatedShares[targetNodeID]
		commitmentsByDealer[dealerNodeID] = commitments
	}
	return
}

// createTestOperatorsFromChainConfig is a helper that mirrors reshare_test.go's createTestOperators.
func createTestOperatorsFromChainConfig(t *testing.T, numOperators int) []*peering.OperatorSetPeer {
	t.Helper()

	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	require.NoError(t, err, "Failed to read chain config")

	addresses := []string{
		chainConfig.OperatorAccountAddress1,
		chainConfig.OperatorAccountAddress2,
		chainConfig.OperatorAccountAddress3,
		chainConfig.OperatorAccountAddress4,
		chainConfig.OperatorAccountAddress5,
	}

	require.LessOrEqual(t, numOperators, len(addresses), "not enough test operators in ChainConfig")

	ops := make([]*peering.OperatorSetPeer, numOperators)
	for i := 0; i < numOperators; i++ {
		ops[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress(addresses[i]),
		}
	}
	return ops
}

// mockSigner returns a deterministic non-empty signature for testing.
func mockSigner(dealerID int64, commitmentHash [32]byte) []byte {
	return []byte("mock-ack-signature")
}

func TestReshareNewOperator_VerifiesValidShares(t *testing.T) {
	operators, targetNodeID, shares, commitmentsByDealer := setupReshareTestOperators(t, 3)

	r := reshare.NewReshare(targetNodeID, operators)

	var acks []*types.Acknowledgement
	validShares := make(map[int64]*fr.Element)

	for dealerID, share := range shares {
		commitments := commitmentsByDealer[dealerID]
		valid := r.VerifyNewShare(dealerID, share, commitments)
		require.True(t, valid, "share from dealer %d should be valid", dealerID)

		validShares[dealerID] = share

		ack := reshare.CreateAcknowledgement(targetNodeID, dealerID, 1000, share, commitments, mockSigner)
		acks = append(acks, ack)
	}

	require.Len(t, validShares, 3, "all 3 shares should be valid")
	require.Len(t, acks, 3, "should produce 3 acks")

	for _, ack := range acks {
		require.Equal(t, targetNodeID, ack.PlayerID)
		require.Equal(t, int64(1000), ack.Epoch)
		require.NotZero(t, ack.ShareHash)
		require.NotZero(t, ack.CommitmentHash)
		require.NotEmpty(t, ack.Signature)
		// DealerID should match one of the dealers
		_, ok := shares[ack.DealerID]
		require.True(t, ok, "ack DealerID should correspond to a dealer")
	}
}

func TestReshareNewOperator_RejectsInvalidShares(t *testing.T) {
	core, observed := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	operators, targetNodeID, _, commitmentsByDealer := setupReshareTestOperators(t, 3)

	r := reshare.NewReshare(targetNodeID, operators)

	n := &Node{
		OperatorAddress: operators[len(operators)-1].OperatorAddress,
		logger:          logger,
	}

	for dealerID := range commitmentsByDealer {
		// Use a corrupted (random) share
		corruptedShare := new(fr.Element)
		_, _ = corruptedShare.SetRandom()

		commitments := commitmentsByDealer[dealerID]
		valid := r.VerifyNewShare(dealerID, corruptedShare, commitments)
		require.False(t, valid, "corrupted share from dealer %d should fail verification", dealerID)

		n.logInvalidShareComplaint("reshare", 1000, targetNodeID, dealerID, corruptedShare, commitments)
	}
	require.Len(t, observed.All(), 3, "should log 3 complaint entries")

	for _, entry := range observed.All() {
		require.Equal(t, "ComplaintRecord: invalid share", entry.Message)
		ctx := entry.ContextMap()
		require.Equal(t, "reshare", ctx["protocol"])
	}
}

func TestReshareNewOperator_MixedValidity_OnlyValidUsed(t *testing.T) {
	// Use 4 dealers + 1 new operator = 5 total (max available in ChainConfig)
	// Corrupt 2 of the 4 shares, leaving 2 valid
	operators, targetNodeID, shares, commitmentsByDealer := setupReshareTestOperators(t, 4)

	r := reshare.NewReshare(targetNodeID, operators)

	corruptedCount := 0
	corruptedDealers := make(map[int64]bool)
	for dealerID := range shares {
		if corruptedCount < 2 {
			corruptedShare := new(fr.Element)
			_, _ = corruptedShare.SetRandom()
			shares[dealerID] = corruptedShare
			corruptedDealers[dealerID] = true
			corruptedCount++
		}
	}

	validShares := make(map[int64]*fr.Element)
	validParticipantIDs := make([]int64, 0)
	validCommitments := make([][]types.G2Point, 0)

	for dealerID, share := range shares {
		commitments := commitmentsByDealer[dealerID]
		if r.VerifyNewShare(dealerID, share, commitments) {
			validShares[dealerID] = share
		}
	}

	// Build ordered participant lists from valid shares (same as production code)
	for _, op := range operators {
		opNodeID := util.AddressToNodeID(op.OperatorAddress)
		if _, ok := validShares[opNodeID]; ok {
			validParticipantIDs = append(validParticipantIDs, opNodeID)
			if comm, ok := commitmentsByDealer[opNodeID]; ok {
				validCommitments = append(validCommitments, comm)
			}
		}
	}

	require.Len(t, validShares, 2, "only 2 valid shares should remain")
	require.Len(t, validParticipantIDs, 2, "only 2 valid participant IDs")
	require.Len(t, validCommitments, 2, "only 2 valid commitment sets")

	// Verify none of the corrupted dealers are included
	for _, id := range validParticipantIDs {
		require.False(t, corruptedDealers[id], "corrupted dealer %d should not be in valid set", id)
	}

	// Compute key share from valid subset only
	keyVersion := r.ComputeNewKeyShare(validParticipantIDs, validShares, validCommitments)
	require.NotNil(t, keyVersion)
	require.NotNil(t, keyVersion.PrivateShare)
}

func TestReshareNewOperator_BelowThreshold_Precondition(t *testing.T) {
	// 4 dealers + 1 new operator = 5 total. Threshold = ceil(2*5/3) = 4.
	// Corrupt 3 of 4 shares so only 1 is valid — below threshold.
	operators, targetNodeID, shares, commitmentsByDealer := setupReshareTestOperators(t, 4)

	r := reshare.NewReshare(targetNodeID, operators)
	threshold := dkg.CalculateThreshold(len(operators))

	corruptedCount := 0
	for dealerID := range shares {
		if corruptedCount < 3 {
			corruptedShare := new(fr.Element)
			_, _ = corruptedShare.SetRandom()
			shares[dealerID] = corruptedShare
			corruptedCount++
		}
	}

	validShares := make(map[int64]*fr.Element)
	for dealerID, share := range shares {
		commitments := commitmentsByDealer[dealerID]
		if r.VerifyNewShare(dealerID, share, commitments) {
			validShares[dealerID] = share
		}
	}

	require.Less(t, len(validShares), threshold,
		"valid shares (%d) should be below threshold (%d)", len(validShares), threshold)
}

func TestReshareNewOperator_AckContentCorrect(t *testing.T) {
	operators, targetNodeID, shares, commitmentsByDealer := setupReshareTestOperators(t, 3)

	r := reshare.NewReshare(targetNodeID, operators)

	epoch := int64(5000)

	for dealerID, share := range shares {
		commitments := commitmentsByDealer[dealerID]
		require.True(t, r.VerifyNewShare(dealerID, share, commitments))

		ack := reshare.CreateAcknowledgement(targetNodeID, dealerID, epoch, share, commitments, mockSigner)

		// Verify ack fields
		require.Equal(t, dealerID, ack.DealerID)
		require.Equal(t, targetNodeID, ack.PlayerID)
		require.Equal(t, epoch, ack.Epoch)

		// Verify hashes match crypto functions
		expectedShareHash := crypto.HashShareForAck(share)
		require.Equal(t, expectedShareHash, ack.ShareHash, "ShareHash should match crypto.HashShareForAck")

		expectedCommitmentHash := crypto.HashCommitment(commitments)
		require.Equal(t, expectedCommitmentHash, ack.CommitmentHash, "CommitmentHash should match crypto.HashCommitment")

		require.NotEmpty(t, ack.Signature, "signature should be non-empty")
	}
}

func TestReshareNewOperator_MissingCommitments_SkipsShare(t *testing.T) {
	core, observed := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	operators, targetNodeID, shares, commitmentsByDealer := setupReshareTestOperators(t, 3)

	r := reshare.NewReshare(targetNodeID, operators)

	n := &Node{
		OperatorAddress: operators[len(operators)-1].OperatorAddress,
		logger:          logger,
		resharer:        r,
	}

	// Remove commitments for one dealer to simulate missing commitments
	var removedDealerID int64
	for dealerID := range commitmentsByDealer {
		removedDealerID = dealerID
		delete(commitmentsByDealer, dealerID)
		break
	}

	// Replicate the production code's verification loop
	validShares := make(map[int64]*fr.Element)
	for dealerID, share := range shares {
		commitments, hasCommitments := commitmentsByDealer[dealerID]
		if !hasCommitments || len(commitments) == 0 {
			n.logger.Sugar().Warnw("Missing commitments for dealer, skipping share",
				"operator_address", n.OperatorAddress.Hex(),
				"dealer_id", dealerID)
			continue
		}
		if r.VerifyNewShare(dealerID, share, commitments) {
			validShares[dealerID] = share
		}
	}

	// The dealer with removed commitments should be skipped
	_, included := validShares[removedDealerID]
	require.False(t, included, "dealer with missing commitments should not be in validShares")
	require.Len(t, validShares, 2, "only 2 shares with commitments should be valid")

	// Should have logged a warning about missing commitments
	warnings := observed.FilterMessage("Missing commitments for dealer, skipping share").All()
	require.Len(t, warnings, 1, "should log one missing commitments warning")
}
