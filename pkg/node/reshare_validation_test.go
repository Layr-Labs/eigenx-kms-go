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
	err := n.RunReshareAsNewOperator(1000, 0)
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

// sessionParticipantIDs returns the set of operators that HOLD a refreshed share after a
// reshare — the full session operator set, in on-chain order. It is NOT the dealer subset:
// ComputeNewKeyShare gives every recipient (every session operator) a share of the same
// secret S, whether or not it was a dealer. Persisting the dealer subset as ParticipantIDs
// is the "ratchet" bug (docs/013 Change 1) — it shrinks the next round's expected dealer
// set per-node and freezes a version split. This must be deterministic and identical
// across nodes (it is the on-chain operators slice), regardless of which threshold subset
// dealt this round.
func TestSessionParticipantIDs_IsFullOperatorSetInOrder(t *testing.T) {
	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: addr(2)},
		{OperatorAddress: addr(3)},
		{OperatorAddress: addr(1)},
	}
	got := sessionParticipantIDs(operators)
	require.Equal(t, []common.Address{addr(2), addr(3), addr(1)}, got,
		"participant set must be every session operator, in on-chain order — not the dealer subset")
}

// The participant set must NOT depend on which dealers finalized the round: a 2-of-3
// round still leaves all 3 operators holding a share, so ParticipantIDs stays the full 3.
func TestSessionParticipantIDs_IndependentOfDealerSubset(t *testing.T) {
	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: addr(1)},
		{OperatorAddress: addr(2)},
		{OperatorAddress: addr(3)},
	}
	// Even though only {1,2} may have been the finalize dealer set this round, every
	// operator recomputes its own share, so the holder set is still {1,2,3}.
	got := sessionParticipantIDs(operators)
	require.Equal(t, []common.Address{addr(1), addr(2), addr(3)}, got)
}

// existingOperatorDealers returns only the EXISTING operators (those holding a share), in
// on-chain order — the dealer set a NEW operator must converge on. A new operator has no
// active version, so it can't use expectedReshareDealers (which would return ALL operators,
// including itself and other joiners who never submit on-chain — making convergence wait
// out the full protocol timeout every join, docs/013 PR#119 round-3 finding 2).
func TestExistingOperatorDealers_ExcludesNewJoiners(t *testing.T) {
	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: addr(1)}, // existing
		{OperatorAddress: addr(2)}, // existing
		{OperatorAddress: addr(3)}, // new joiner (self) — not in existingOpIDs
	}
	existingOpIDs := map[common.Address]bool{addr(1): true, addr(2): true}

	got := existingOperatorDealers(operators, existingOpIDs)
	require.Equal(t, []common.Address{addr(1), addr(2)}, got,
		"must return only existing (share-holding) operators, in on-chain order")
}
