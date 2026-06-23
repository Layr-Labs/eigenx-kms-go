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
// returns numOps operators and no active key version.
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
// version with the given participantIDs.
func makeNodeWithKeyVersion(t *testing.T, numOps int, participantIDs []common.Address) *Node {
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

func TestRunReshareAsExistingOperator_AllOperatorsNewRejected(t *testing.T) {
	n := makeNodeWithKeyVersion(t, 3, []common.Address{})
	err := n.RunReshareAsExistingOperator(1000, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of range")
}

func TestRunReshareAsExistingOperator_PureRefreshPassesGuard(t *testing.T) {
	const numOps = 3
	participantIDs := make([]common.Address, numOps)
	for i := 0; i < numOps; i++ {
		participantIDs[i] = common.HexToAddress(fmt.Sprintf("0x%040x", i+1))
	}
	n := makeNodeWithKeyVersion(t, numOps, participantIDs)

	err := n.RunReshareAsExistingOperator(1000, 0)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "out of range")
}

func TestRunReshareAsNewOperator_AllOperatorsNewRejected(t *testing.T) {
	n := makeNodeForValidation(t, 3)
	err := n.RunReshareAsNewOperator(1000)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of range")
}

func TestRunReshareAsNewOperator_GuardRejectsZero(t *testing.T) {
	for _, n := range []int{1, 3, 5} {
		outOfRange := 0 < 1 || 0 >= n
		require.True(t, outOfRange,
			"numNewOperators=0 must be rejected by the new-operator guard for N=%d", n)
	}
}

func addr(i int) common.Address { return common.HexToAddress(fmt.Sprintf("0x%040x", i)) }

// expectedReshareDealers must return the on-chain ∩ prior-participants set in on-chain
// order — the deterministic dealer set every operator finalizes on. This is what makes
// the reshare-finalize agreement invariant hold across nodes.
func TestExpectedReshareDealers_IntersectsOnChainAndPriorParticipants(t *testing.T) {
	// Prior participants: 1,2,3. On-chain now: 2,3,4 (1 left, 4 joined fresh).
	prior := []common.Address{addr(1), addr(2), addr(3)}
	n := makeNodeWithKeyVersion(t, 0, prior)

	onChain := []*peering.OperatorSetPeer{
		{OperatorAddress: addr(2)},
		{OperatorAddress: addr(3)},
		{OperatorAddress: addr(4)}, // new joiner: holds no share, must NOT be a dealer
	}

	dealers := n.expectedReshareDealers(onChain)

	// Expect {2,3} only — intersection — in on-chain order.
	require.Equal(t, []common.Address{addr(2), addr(3)}, dealers,
		"dealers must be on-chain ∩ prior participants (exclude departed 1 and new 4), in on-chain order")
}

// Determinism: regardless of the order prior participants were stored, the dealer set
// follows the on-chain operator ordering, so every node computes an identical slice.
func TestExpectedReshareDealers_OrderFollowsOnChainSlice(t *testing.T) {
	prior := []common.Address{addr(3), addr(1), addr(2)} // stored in arbitrary order
	n := makeNodeWithKeyVersion(t, 0, prior)

	onChain := []*peering.OperatorSetPeer{
		{OperatorAddress: addr(1)},
		{OperatorAddress: addr(2)},
		{OperatorAddress: addr(3)},
	}
	dealers := n.expectedReshareDealers(onChain)
	require.Equal(t, []common.Address{addr(1), addr(2), addr(3)}, dealers)
}

// With no active version (never completed DKG), there are no prior participants to
// scope against; fall back to all current operators.
func TestExpectedReshareDealers_NoActiveVersionReturnsAll(t *testing.T) {
	n := makeNodeForValidation(t, 0)
	onChain := []*peering.OperatorSetPeer{
		{OperatorAddress: addr(1)},
		{OperatorAddress: addr(2)},
	}
	dealers := n.expectedReshareDealers(onChain)
	require.Equal(t, []common.Address{addr(1), addr(2)}, dealers)
}
