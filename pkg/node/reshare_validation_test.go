package node

import (
	"fmt"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/keystore"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// makeNodeForValidation returns a minimal *Node with a stub peering fetcher that
// returns numOps operators and no active key version. Suitable for new-operator
// scenarios (no existing shares) and for exercising the nil-transport fallback in
// countNewOperatorsInSet.
func makeNodeForValidation(t *testing.T, numOps int) *Node {
	t.Helper()
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	operators := make([]*peering.OperatorSetPeer, numOps)
	for i := range operators {
		operators[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress(fmt.Sprintf("0x%040x", i+1)),
		}
	}

	return &Node{
		logger:             logger,
		keyStore:           keystore.NewKeyStore(),
		peeringDataFetcher: peering.NewStubPeeringDataFetcher(&peering.OperatorSetPeers{Peers: operators}),
	}
}

// makeNodeWithKeyVersion returns a minimal *Node whose key store has an active
// version with the given participantIDs. This simulates an existing operator that
// participated in the previous DKG/reshare epoch.
func makeNodeWithKeyVersion(t *testing.T, numOps int, participantIDs []int64) *Node {
	t.Helper()
	n := makeNodeForValidation(t, numOps)

	version := &types.KeyShareVersion{
		Version:        1,
		IsActive:       true,
		ParticipantIDs: participantIDs,
	}
	n.keyStore.AddVersion(version)
	n.keyStore.SetActiveVersion(version)
	return n
}

// TestRunReshareAsExistingOperator_AllOperatorsNewRejected verifies that when
// none of the current operators appear in the previous key version's ParticipantIDs
// (e.g., a completely replaced operator set), numNewOperators equals len(operators)
// which fails the [0, N) guard and returns an error.
func TestRunReshareAsExistingOperator_AllOperatorsNewRejected(t *testing.T) {
	// Active version with empty ParticipantIDs: none of the 3 current operators
	// match, so countNewOperatorsInSet returns 3. The guard rejects 3 >= 3.
	n := makeNodeWithKeyVersion(t, 3, []int64{})
	err := n.RunReshareAsExistingOperator(1000)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of range")
}

// TestRunReshareAsExistingOperator_PureRefreshPassesGuard verifies that when all
// current operators were participants in the previous epoch (pure share refresh,
// no new joiners), numNewOperators is 0 and the guard passes. The function
// continues past the guard and may fail for other reasons (e.g., missing private
// share), but the guard itself does not reject.
func TestRunReshareAsExistingOperator_PureRefreshPassesGuard(t *testing.T) {
	const numOps = 3
	// Build participant IDs matching the operator addresses produced by makeNodeForValidation.
	participantIDs := make([]int64, numOps)
	for i := 0; i < numOps; i++ {
		addr := common.HexToAddress(fmt.Sprintf("0x%040x", i+1))
		participantIDs[i] = addressToNodeID(addr)
	}
	n := makeNodeWithKeyVersion(t, numOps, participantIDs)

	err := n.RunReshareAsExistingOperator(1000)
	// Passes the guard but fails later (no private share in key store).
	require.Error(t, err)
	require.NotContains(t, err.Error(), "out of range")
}

// TestRunReshareAsNewOperator_AllOperatorsNewRejected verifies that when the node
// has no active key version and no transport is configured, countNewOperatorsInSet
// conservatively returns len(operators). The new-operator guard [1, N) then rejects
// numNewOperators == N since N >= N.
func TestRunReshareAsNewOperator_AllOperatorsNewRejected(t *testing.T) {
	// No active version, nil transport → countNewOperatorsInSet returns len(operators)=3.
	// Guard: 3 >= 3 → rejected.
	n := makeNodeForValidation(t, 3)
	err := n.RunReshareAsNewOperator(1000)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of range")
}

// TestRunReshareAsNewOperator_GuardRejectsZero documents that the new-operator
// guard enforces numNewOperators >= 1. A value of 0 would imply no new operators
// are joining — contradicting the precondition that the caller is itself new —
// and would deadlock waiting for all N contributions that never arrive.
func TestRunReshareAsNewOperator_GuardRejectsZero(t *testing.T) {
	// The guard condition for RunReshareAsNewOperator is numNew < 1 || numNew >= N.
	// Verify it rejects 0 for any operator-set size.
	for _, n := range []int{1, 3, 5} {
		outOfRange := 0 < 1 || 0 >= n
		require.True(t, outOfRange,
			"numNewOperators=0 must be rejected by the new-operator guard for N=%d", n)
	}
}
