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

// TestSelectDeterministicParticipants verifies that the participant set is
// chosen deterministically from operators that sent both shares and commitments.
func TestSelectDeterministicParticipants(t *testing.T) {
	operators := makeTestOperatorsWithAddresses(5)

	// Compute node IDs for these operators
	nodeIDs := make([]int64, len(operators))
	for i, op := range operators {
		nodeIDs[i] = addressToNodeID(op.OperatorAddress)
	}

	t.Run("selects first threshold from intersection sorted by node ID", func(t *testing.T) {
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

		threshold := 4
		result := selectDeterministicParticipants(session, operators, threshold)
		require.Len(t, result, threshold)

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

		threshold := 4
		result := selectDeterministicParticipants(session, operators, threshold)
		require.Len(t, result, threshold)

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

		threshold := 4
		result := selectDeterministicParticipants(session, operators, threshold)
		require.Len(t, result, threshold)

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

		// Only 3 operators sent both
		for i := 0; i < 3; i++ {
			id := nodeIDs[i]
			elem := fr.NewElement(uint64(id))
			session.shares[id] = &elem
			session.commitments[id] = []types.G2Point{}
		}

		threshold := 4
		result := selectDeterministicParticipants(session, operators, threshold)
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

		threshold := 4
		result1 := selectDeterministicParticipants(session, operators, threshold)
		result2 := selectDeterministicParticipants(session, operators, threshold)
		require.Equal(t, result1, result2, "should produce identical results on repeated calls")
	})
}
