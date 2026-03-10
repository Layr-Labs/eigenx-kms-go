package node

import (
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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

// TestWaitForCommitments_NoThresholdFallback verifies that commitments always
// require all n operators (no threshold fallback) to ensure participant set
// agreement across nodes.
func TestWaitForCommitments_NoThresholdFallback(t *testing.T) {
	const n = 5
	session := &ProtocolSession{
		Operators:               makeTestOperators(n),
		commitments:             make(map[int64][]types.G2Point),
		sharesCompleteChan:      make(chan bool, 1),
		commitmentsCompleteChan: make(chan bool, 1),
	}

	// Deliver only n-1 commitments (simulating one unresponsive operator)
	for i := int64(0); i < n-1; i++ {
		_ = session.HandleReceivedCommitment(i, []types.G2Point{})
	}

	// Should timeout — no threshold fallback for commitments
	err := waitForCommitments(session, 200*time.Millisecond)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timeout waiting for commitments")
}
