package node

import (
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func makeTestOperators(n int) []*peering.OperatorSetPeer {
	ops := make([]*peering.OperatorSetPeer, n)
	for i := range ops {
		ops[i] = &peering.OperatorSetPeer{}
	}
	return ops
}

func makeTestOperatorsWithAddresses(n int) []*peering.OperatorSetPeer {
	ops := make([]*peering.OperatorSetPeer, n)
	for i := range ops {
		// Use distinct addresses so addressToNodeID produces distinct IDs
		addr := common.BigToAddress(common.Big1)
		addr[19] = byte(i + 1) // distinct last byte
		ops[i] = &peering.OperatorSetPeer{OperatorAddress: addr}
	}
	return ops
}

// TestWaitForSharesWithThreshold_AllSharesReceived verifies the happy path:
// all shares arrive before timeout, no threshold fallback needed.
func TestWaitForSharesWithThreshold_AllSharesReceived(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	const n = 5
	session := &ProtocolSession{
		Operators:               makeTestOperators(n),
		shares:                  make(map[int64]*fr.Element),
		sharesCompleteChan:      make(chan bool, 1),
		commitmentsCompleteChan: make(chan bool, 1),
	}

	// Deliver all n shares asynchronously
	go func() {
		time.Sleep(20 * time.Millisecond)
		for i := int64(0); i < n; i++ {
			elem := fr.NewElement(uint64(i + 1))
			_ = session.HandleReceivedShare(i, &elem)
		}
	}()

	err := waitForSharesWithThreshold(session, 2*time.Second, 4, logger.Sugar())
	require.NoError(t, err)

	session.mu.RLock()
	require.Equal(t, n, len(session.shares))
	session.mu.RUnlock()
}

// TestWaitForSharesWithThreshold_ThresholdFallback verifies the degraded path:
// only threshold shares arrive, timeout fires, but we proceed successfully.
func TestWaitForSharesWithThreshold_ThresholdFallback(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	const n = 5
	const threshold = 4 // ceil(2*5/3)
	session := &ProtocolSession{
		Operators:               makeTestOperators(n),
		shares:                  make(map[int64]*fr.Element),
		sharesCompleteChan:      make(chan bool, 1),
		commitmentsCompleteChan: make(chan bool, 1),
	}

	// Deliver only threshold shares (simulating one unresponsive operator)
	for i := int64(0); i < threshold; i++ {
		elem := fr.NewElement(uint64(i + 1))
		_ = session.HandleReceivedShare(i, &elem)
	}

	// Channel won't signal (need all n), so waitForShares will timeout.
	// But waitForSharesWithThreshold should succeed via threshold fallback.
	err := waitForSharesWithThreshold(session, 200*time.Millisecond, threshold, logger.Sugar())
	require.NoError(t, err)

	session.mu.RLock()
	require.Equal(t, threshold, len(session.shares))
	session.mu.RUnlock()
}

// TestWaitForSharesWithThreshold_BelowThresholdFails verifies that if fewer
// than threshold shares arrive, the function returns an error.
func TestWaitForSharesWithThreshold_BelowThresholdFails(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	const n = 5
	const threshold = 4
	session := &ProtocolSession{
		Operators:               makeTestOperators(n),
		shares:                  make(map[int64]*fr.Element),
		sharesCompleteChan:      make(chan bool, 1),
		commitmentsCompleteChan: make(chan bool, 1),
	}

	// Deliver only threshold-1 shares (below minimum)
	for i := int64(0); i < threshold-1; i++ {
		elem := fr.NewElement(uint64(i + 1))
		_ = session.HandleReceivedShare(i, &elem)
	}

	err := waitForSharesWithThreshold(session, 200*time.Millisecond, threshold, logger.Sugar())
	require.Error(t, err)
	require.Contains(t, err.Error(), "timeout waiting for shares")
}

// TestWaitForCommitmentsWithThreshold_ThresholdFallback verifies the degraded path:
// only threshold commitments arrive, timeout fires, but we proceed successfully.
func TestWaitForCommitmentsWithThreshold_ThresholdFallback(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	const n = 5
	const threshold = 4
	session := &ProtocolSession{
		Operators:               makeTestOperators(n),
		commitments:             make(map[int64][]types.G2Point),
		sharesCompleteChan:      make(chan bool, 1),
		commitmentsCompleteChan: make(chan bool, 1),
	}

	for i := int64(0); i < threshold; i++ {
		_ = session.HandleReceivedCommitment(i, []types.G2Point{})
	}

	err := waitForCommitmentsWithThreshold(session, 200*time.Millisecond, threshold, logger.Sugar())
	require.NoError(t, err)
}

// TestWaitForCommitmentsWithThreshold_BelowThresholdFails verifies that if fewer
// than threshold commitments arrive, the function returns an error.
func TestWaitForCommitmentsWithThreshold_BelowThresholdFails(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	const n = 5
	const threshold = 4
	session := &ProtocolSession{
		Operators:               makeTestOperators(n),
		commitments:             make(map[int64][]types.G2Point),
		sharesCompleteChan:      make(chan bool, 1),
		commitmentsCompleteChan: make(chan bool, 1),
	}

	for i := int64(0); i < threshold-1; i++ {
		_ = session.HandleReceivedCommitment(i, []types.G2Point{})
	}

	err := waitForCommitmentsWithThreshold(session, 200*time.Millisecond, threshold, logger.Sugar())
	require.Error(t, err)
	require.Contains(t, err.Error(), "timeout waiting for commitments")
}

// TestWaitForAcks_ThresholdFallback verifies that waitForAcks times out
// but the caller can apply a threshold fallback when enough acks were received.
func TestWaitForAcks_ThresholdFallback(t *testing.T) {
	const n = 5
	const threshold = 4 // ceil(2*5/3)

	t.Run("succeeds when required acks received", func(t *testing.T) {
		session := &ProtocolSession{
			Operators:        makeTestOperators(n),
			acks:             make(map[int64]map[int64]*types.Acknowledgement),
			sharesCompleteChan: make(chan bool, 1),
		}

		dealerID := int64(1)
		session.acks[dealerID] = make(map[int64]*types.Acknowledgement)
		for i := int64(2); i <= int64(threshold+1); i++ {
			session.acks[dealerID][i] = &types.Acknowledgement{PlayerID: i, DealerID: dealerID}
		}

		err := waitForAcks(session, dealerID, threshold, 200*time.Millisecond)
		require.NoError(t, err)
	})

	t.Run("times out when below required acks", func(t *testing.T) {
		session := &ProtocolSession{
			Operators:        makeTestOperators(n),
			acks:             make(map[int64]map[int64]*types.Acknowledgement),
			sharesCompleteChan: make(chan bool, 1),
		}

		dealerID := int64(1)
		session.acks[dealerID] = make(map[int64]*types.Acknowledgement)
		// Only deliver threshold-2 acks (below threshold-1 fallback)
		for i := int64(2); i < int64(threshold); i++ {
			session.acks[dealerID][i] = &types.Acknowledgement{PlayerID: i, DealerID: dealerID}
		}

		err := waitForAcks(session, dealerID, threshold, 200*time.Millisecond)
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout waiting for acks")

		// Verify that the caller can check received count for fallback logic
		session.mu.RLock()
		received := len(session.acks[dealerID])
		session.mu.RUnlock()
		require.Equal(t, threshold-2, received)
	})

	t.Run("fallback threshold-1 is sufficient", func(t *testing.T) {
		session := &ProtocolSession{
			Operators:        makeTestOperators(n),
			acks:             make(map[int64]map[int64]*types.Acknowledgement),
			sharesCompleteChan: make(chan bool, 1),
		}

		dealerID := int64(1)
		session.acks[dealerID] = make(map[int64]*types.Acknowledgement)
		// Deliver threshold-1 acks (enough for fallback, not enough for full requirement)
		for i := int64(2); i <= int64(threshold); i++ {
			session.acks[dealerID][i] = &types.Acknowledgement{PlayerID: i, DealerID: dealerID}
		}

		// waitForAcks requires threshold, so it times out
		err := waitForAcks(session, dealerID, threshold, 200*time.Millisecond)
		require.Error(t, err)

		// But the fallback check passes with threshold-1
		session.mu.RLock()
		received := len(session.acks[dealerID])
		session.mu.RUnlock()
		fallbackRequired := threshold - 1
		require.GreaterOrEqual(t, received, fallbackRequired, "fallback threshold should be met")
	})
}

// TestSelectDeterministicParticipants verifies that the participant set is
// chosen deterministically from operators that sent both shares and commitments.
func TestSelectDeterministicParticipants(t *testing.T) {
	operators := makeTestOperatorsWithAddresses(5)

	// Compute node IDs for these operators
	nodeIDs := make([]int64, len(operators))
	for i, op := range operators {
		nodeIDs[i] = addressToNodeID(op.OperatorAddress)
	}

	t.Run("returns all candidates sorted by node ID without truncation", func(t *testing.T) {
		session := &ProtocolSession{
			Operators:   operators,
			shares:      make(map[int64]*fr.Element),
			commitments: make(map[int64][]types.G2Point),
		}

		// All 5 operators sent both shares and commitments
		for _, id := range nodeIDs {
			elem := fr.NewElement(uint64(id))
			session.shares[id] = &elem
			session.commitments[id] = []types.G2Point{}
		}

		result := selectDeterministicParticipants(session, operators)
		require.Len(t, result, 5, "should return all candidates, not truncate to threshold")

		// Verify sorted ascending
		for i := 1; i < len(result); i++ {
			require.Less(t, result[i-1], result[i], "participants should be sorted by node ID")
		}
	})

	t.Run("excludes operators missing shares", func(t *testing.T) {
		session := &ProtocolSession{
			Operators:   operators,
			shares:      make(map[int64]*fr.Element),
			commitments: make(map[int64][]types.G2Point),
		}

		// All operators sent commitments, but only first 4 sent shares
		for i, id := range nodeIDs {
			session.commitments[id] = []types.G2Point{}
			if i < 4 {
				elem := fr.NewElement(uint64(id))
				session.shares[id] = &elem
			}
		}

		result := selectDeterministicParticipants(session, operators)
		require.Len(t, result, 4)

		// The 5th operator (missing share) should not be in the result
		resultSet := make(map[int64]bool)
		for _, id := range result {
			resultSet[id] = true
		}
		require.False(t, resultSet[nodeIDs[4]], "operator missing share should be excluded")
	})

	t.Run("excludes operators missing commitments", func(t *testing.T) {
		session := &ProtocolSession{
			Operators:   operators,
			shares:      make(map[int64]*fr.Element),
			commitments: make(map[int64][]types.G2Point),
		}

		// All operators sent shares, but only first 4 sent commitments
		for i, id := range nodeIDs {
			elem := fr.NewElement(uint64(id))
			session.shares[id] = &elem
			if i < 4 {
				session.commitments[id] = []types.G2Point{}
			}
		}

		result := selectDeterministicParticipants(session, operators)
		require.Len(t, result, 4)

		resultSet := make(map[int64]bool)
		for _, id := range result {
			resultSet[id] = true
		}
		require.False(t, resultSet[nodeIDs[4]], "operator missing commitment should be excluded")
	})

	t.Run("returns fewer than threshold when insufficient candidates", func(t *testing.T) {
		session := &ProtocolSession{
			Operators:   operators,
			shares:      make(map[int64]*fr.Element),
			commitments: make(map[int64][]types.G2Point),
		}

		// Only 3 operators sent both — caller would check len(result) >= threshold
		for i := 0; i < 3; i++ {
			id := nodeIDs[i]
			elem := fr.NewElement(uint64(id))
			session.shares[id] = &elem
			session.commitments[id] = []types.G2Point{}
		}

		result := selectDeterministicParticipants(session, operators)
		require.Len(t, result, 3, "should return all candidates when fewer than threshold")
	})

	t.Run("deterministic across calls", func(t *testing.T) {
		session := &ProtocolSession{
			Operators:   operators,
			shares:      make(map[int64]*fr.Element),
			commitments: make(map[int64][]types.G2Point),
		}

		for _, id := range nodeIDs {
			elem := fr.NewElement(uint64(id))
			session.shares[id] = &elem
			session.commitments[id] = []types.G2Point{}
		}

		result1 := selectDeterministicParticipants(session, operators)
		result2 := selectDeterministicParticipants(session, operators)
		require.Equal(t, result1, result2, "should produce identical results on repeated calls")
	})
}
