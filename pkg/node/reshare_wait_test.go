package node

import (
	"fmt"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
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

// --- HandleReceivedCommitment ---

func TestHandleReceivedCommitment_EmptyCommitmentsRejected(t *testing.T) {
	session := &ProtocolSession{
		commitments:             make(map[common.Address][]types.G2Point),
		commitmentsCompleteChan: make(chan bool, 1),
		Operators:               makeTestOps(3),
	}

	err := session.HandleReceivedCommitment(common.HexToAddress("0x01"), nil, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty commitments")

	err = session.HandleReceivedCommitment(common.HexToAddress("0x01"), []types.G2Point{}, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty commitments")

	// Verify nothing was stored
	require.Empty(t, session.commitments)
}

// The source version must be recorded ATOMICALLY with the commitment, under the same
// lock and BEFORE the completion channel is signaled. Otherwise the reshare goroutine
// (unblocked by the signal) can read GetSourceVersions() before the last dealer's source
// version is stored, drop that dealer as "unknown", and abort the round unnecessarily.
// (bot review round 3.)
func TestHandleReceivedCommitment_RecordsSourceVersionBeforeSignal(t *testing.T) {
	session := &ProtocolSession{
		commitments:             make(map[common.Address][]types.G2Point),
		sourceVersions:          make(map[common.Address]int64),
		commitmentsCompleteChan: make(chan bool, 1),
		Operators:               makeTestOps(1), // single operator: this commitment completes the set
	}

	dealer := common.HexToAddress("0x0A")
	comm := []types.G2Point{{CompressedBytes: []byte{1}}}
	require.NoError(t, session.HandleReceivedCommitment(dealer, comm, 1783020000))

	// The completion signal is now readable — and by the time it is, the source version
	// MUST already be visible (recorded under the same lock, before the signal).
	select {
	case <-session.commitmentsCompleteChan:
	default:
		t.Fatal("expected commitments-complete to be signaled")
	}
	got := session.GetSourceVersions()
	require.Equal(t, int64(1783020000), got[dealer],
		"source version must be recorded atomically with the commitment, before the completion signal")
}

// --- waitForNShares ---

func TestWaitForNShares_SucceedsWithRequiredCount(t *testing.T) {
	const n = 5
	session := &ProtocolSession{
		Operators: makeTestOps(n),
		shares:    make(map[common.Address]*fr.Element),
	}

	for i := 0; i < n-1; i++ {
		elem := fr.NewElement(uint64(i + 1))
		session.shares[common.HexToAddress(fmt.Sprintf("0x%040x", i+1))] = &elem
	}

	require.NoError(t, waitForNShares(session, n-1, 200*time.Millisecond))
}

func TestWaitForNShares_TimesOutIfInsufficient(t *testing.T) {
	const n = 5
	session := &ProtocolSession{
		Operators: makeTestOps(n),
		shares:    make(map[common.Address]*fr.Element),
	}

	// Only n-2 shares present; require n-1 → should timeout.
	for i := 0; i < n-2; i++ {
		elem := fr.NewElement(uint64(i + 1))
		session.shares[common.HexToAddress(fmt.Sprintf("0x%040x", i+1))] = &elem
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
		shares:    make(map[common.Address]*fr.Element),
	}

	// Simulate n-1 existing operators delivering shares asynchronously.
	go func() {
		time.Sleep(20 * time.Millisecond)
		session.mu.Lock()
		for i := 0; i < n-1; i++ {
			elem := fr.NewElement(uint64(i + 10))
			session.shares[common.HexToAddress(fmt.Sprintf("0x%040x", i+1))] = &elem
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

// TestRunReshareAsNewOperator_ThresholdMatchesExistingOperators validates that
// RunReshareAsNewOperator and RunReshareAsExistingOperator use the same threshold
// formula (len(operators) - numNewOperators), keeping the two paths consistent.
func TestRunReshareAsNewOperator_ThresholdMatchesExistingOperators(t *testing.T) {
	t.Run("single new operator (numNewOperators=1)", func(t *testing.T) {
		const n, numNew = 5, 1
		session := &ProtocolSession{
			Operators: makeTestOps(n),
			shares:    make(map[common.Address]*fr.Element),
		}

		// Existing operators deliver n-numNew shares.
		for i := 0; i < n-numNew; i++ {
			elem := fr.NewElement(uint64(i + 1))
			session.shares[common.HexToAddress(fmt.Sprintf("0x%040x", i+1))] = &elem
		}

		// Both paths use len(operators)-numNewOperators as the threshold.
		require.NoError(t, waitForNShares(session, n-numNew, 200*time.Millisecond))

		// Confirm that the old hardcoded len(operators)-1 would have timed out for numNew>1.
	})

	t.Run("multiple new operators (numNewOperators=2)", func(t *testing.T) {
		const n, numNew = 6, 2
		session := &ProtocolSession{
			Operators: makeTestOps(n),
			shares:    make(map[common.Address]*fr.Element),
		}

		// Only n-numNew existing operators contribute shares.
		for i := 0; i < n-numNew; i++ {
			elem := fr.NewElement(uint64(i + 1))
			session.shares[common.HexToAddress(fmt.Sprintf("0x%040x", i+1))] = &elem
		}

		// Correct threshold: n-numNew succeeds.
		require.NoError(t, waitForNShares(session, n-numNew, 200*time.Millisecond))

		// Old hardcoded n-1 would have failed: only n-numNew < n-1 shares present.
		err := waitForNShares(session, n-1, 80*time.Millisecond)
		require.Error(t, err, "n-1 threshold would deadlock when numNewOperators > 1")
	})
}

// --- waitForNCommitments ---

func TestWaitForNCommitments_SucceedsWithRequiredCount(t *testing.T) {
	const n = 5
	session := &ProtocolSession{
		Operators:   makeTestOps(n),
		commitments: make(map[common.Address][]types.G2Point),
	}

	for i := 0; i < n-1; i++ {
		session.commitments[common.HexToAddress(fmt.Sprintf("0x%040x", i+1))] = []types.G2Point{}
	}

	require.NoError(t, waitForNCommitments(session, n-1, 200*time.Millisecond))
}

func TestWaitForNCommitments_TimesOutIfInsufficient(t *testing.T) {
	const n = 5
	session := &ProtocolSession{
		Operators:   makeTestOps(n),
		commitments: make(map[common.Address][]types.G2Point),
	}

	// Only n-2 commitments present; require n-1 → should timeout.
	for i := 0; i < n-2; i++ {
		session.commitments[common.HexToAddress(fmt.Sprintf("0x%040x", i+1))] = []types.G2Point{}
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
		commitments: make(map[common.Address][]types.G2Point),
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		session.mu.Lock()
		for i := 0; i < n-1; i++ {
			session.commitments[common.HexToAddress(fmt.Sprintf("0x%040x", i+1))] = []types.G2Point{}
		}
		session.mu.Unlock()
	}()

	require.NoError(t, waitForNCommitments(session, n-1, 500*time.Millisecond))

	session.mu.RLock()
	received := len(session.commitments)
	session.mu.RUnlock()
	require.Equal(t, n-1, received, "exactly n-1 commitments should be present; nth never arrived")
}

// --- waitForN (shared helper) ---

func TestWaitForN_ErrorMessageContainsLabel(t *testing.T) {
	session := &ProtocolSession{
		Operators: makeTestOps(3),
		shares:    make(map[common.Address]*fr.Element),
	}

	err := waitForN(session, 2, 80*time.Millisecond, func() int { return 0 }, "widgets")
	require.Error(t, err)
	require.Contains(t, err.Error(), "widgets")
	require.Contains(t, err.Error(), "0/2")
}

// --- numNewOperators validation via waitForN ---

// TestWaitForNShares_NegativeRequiredClampsToZero verifies that a negative required
// value (which would arise from a negative numNewOperators slipping through) is
// clamped to 0 and returns immediately rather than blocking or panicking.
func TestWaitForNShares_NegativeRequiredClampsToZero(t *testing.T) {
	session := &ProtocolSession{
		Operators: makeTestOps(3),
		shares:    make(map[common.Address]*fr.Element),
	}
	// required=-1 should clamp to 0 and succeed instantly.
	require.NoError(t, waitForNShares(session, -1, 200*time.Millisecond))
}

// TestWaitForNShares_RequiredExceedsOperatorsClampsToMax verifies that a required
// value larger than len(operators) is clamped to len(operators), preventing the
// count from exceeding the operator set size, which would cause it to wait for
// more shares than possible and always time out.
func TestWaitForNShares_RequiredExceedsOperatorsClampsToMax(t *testing.T) {
	const n = 3
	session := &ProtocolSession{
		Operators: makeTestOps(n),
		shares:    make(map[common.Address]*fr.Element),
	}

	// Only n-1 shares present, but required is clamped to n (all operators).
	for i := 0; i < n-1; i++ {
		elem := fr.NewElement(uint64(i + 1))
		session.shares[common.HexToAddress(fmt.Sprintf("0x%040x", i+1))] = &elem
	}

	// required=n+5 clamps to n; with only n-1 shares this should timeout.
	err := waitForNShares(session, n+5, 80*time.Millisecond)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timeout waiting for shares")
}
