package node

import (
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

// makeTestOps returns n blank OperatorSetPeer entries for session construction.
func makeTestOps(n int) []*peering.OperatorSetPeer {
	ops := make([]*peering.OperatorSetPeer, n)
	for i := range ops {
		ops[i] = &peering.OperatorSetPeer{}
	}
	return ops
}

// --- waitForNShares ---

func TestWaitForNShares_SucceedsWithRequiredCount(t *testing.T) {
	const n = 5
	session := &ProtocolSession{
		Operators: makeTestOps(n),
		shares:    make(map[int64]*fr.Element),
	}

	for i := int64(0); i < n-1; i++ {
		elem := fr.NewElement(uint64(i + 1))
		session.shares[i] = &elem
	}

	require.NoError(t, waitForNShares(session, n-1, 200*time.Millisecond))
}

func TestWaitForNShares_TimesOutIfInsufficient(t *testing.T) {
	const n = 5
	session := &ProtocolSession{
		Operators: makeTestOps(n),
		shares:    make(map[int64]*fr.Element),
	}

	// Only n-2 shares present; require n-1 → should timeout.
	for i := int64(0); i < n-2; i++ {
		elem := fr.NewElement(uint64(i + 1))
		session.shares[i] = &elem
	}

	err := waitForNShares(session, n-1, 80*time.Millisecond)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timeout waiting for shares")
}

// TestWaitForNShares_NewOperatorScenario mirrors RunReshareAsNewOperator:
// N operators total, but only the N-1 existing operators contribute shares.
// The wait must complete on N-1, not block waiting for the Nth (self).
func TestWaitForNShares_NewOperatorScenario(t *testing.T) {
	const n = 4
	session := &ProtocolSession{
		Operators: makeTestOps(n),
		shares:    make(map[int64]*fr.Element),
	}

	// Simulate n-1 existing operators delivering shares asynchronously.
	go func() {
		time.Sleep(20 * time.Millisecond)
		session.mu.Lock()
		for i := int64(0); i < n-1; i++ {
			elem := fr.NewElement(uint64(i + 10))
			session.shares[i] = &elem
		}
		session.mu.Unlock()
	}()

	// Should complete with n-1 even though the nth share never arrives.
	require.NoError(t, waitForNShares(session, n-1, 500*time.Millisecond))

	session.mu.RLock()
	received := len(session.shares)
	session.mu.RUnlock()
	require.Equal(t, n-1, received, "exactly n-1 shares should be present; nth never arrived")
}

// TestRunReshareAsNewOperator_UsesNMinus1Threshold explicitly validates that
// a session with N operators completes the share-wait once N-1 shares arrive,
// which is the threshold RunReshareAsNewOperator passes to waitForNShares.
func TestRunReshareAsNewOperator_UsesNMinus1Threshold(t *testing.T) {
	const n = 5
	session := &ProtocolSession{
		Operators: makeTestOps(n),
		shares:    make(map[int64]*fr.Element),
	}

	// Deliver exactly n-1 shares (all existing operators contributed; new op did not).
	for i := int64(0); i < n-1; i++ {
		elem := fr.NewElement(uint64(i + 1))
		session.shares[i] = &elem
	}

	// The call RunReshareAsNewOperator makes: waitForNShares(session, len(operators)-1, ...).
	require.NoError(t, waitForNShares(session, len(session.Operators)-1, 200*time.Millisecond))

	// Confirm waiting for all N would NOT have been satisfied.
	err := waitForNShares(session, n, 80*time.Millisecond)
	require.Error(t, err, "waiting for all N shares should timeout when only N-1 arrived")
}

// --- waitForNCommitments ---

func TestWaitForNCommitments_SucceedsWithRequiredCount(t *testing.T) {
	const n = 5
	session := &ProtocolSession{
		Operators:   makeTestOps(n),
		commitments: make(map[int64][]types.G2Point),
	}

	for i := int64(0); i < n-1; i++ {
		session.commitments[i] = []types.G2Point{}
	}

	require.NoError(t, waitForNCommitments(session, n-1, 200*time.Millisecond))
}

func TestWaitForNCommitments_TimesOutIfInsufficient(t *testing.T) {
	const n = 5
	session := &ProtocolSession{
		Operators:   makeTestOps(n),
		commitments: make(map[int64][]types.G2Point),
	}

	// Only n-2 commitments present; require n-1 → should timeout.
	for i := int64(0); i < n-2; i++ {
		session.commitments[i] = []types.G2Point{}
	}

	err := waitForNCommitments(session, n-1, 80*time.Millisecond)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timeout waiting for commitments")
}

// TestWaitForNCommitments_NewOperatorScenario mirrors the commitment side of
// RunReshareAsNewOperator: only N-1 existing operators broadcast commitments.
func TestWaitForNCommitments_NewOperatorScenario(t *testing.T) {
	const n = 4
	session := &ProtocolSession{
		Operators:   makeTestOps(n),
		commitments: make(map[int64][]types.G2Point),
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		session.mu.Lock()
		for i := int64(0); i < n-1; i++ {
			session.commitments[i] = []types.G2Point{}
		}
		session.mu.Unlock()
	}()

	require.NoError(t, waitForNCommitments(session, n-1, 500*time.Millisecond))

	session.mu.RLock()
	received := len(session.commitments)
	session.mu.RUnlock()
	require.Equal(t, n-1, received, "exactly n-1 commitments should be present; nth never arrived")
}
