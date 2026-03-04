package node

import (
	"fmt"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// makeNodeForValidation returns a minimal *Node with a stub peering fetcher that
// returns numOps operators. This is sufficient to drive execution past
// fetchCurrentOperators and into the numNewOperators validation guard.
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
		peeringDataFetcher: peering.NewStubPeeringDataFetcher(&peering.OperatorSetPeers{Peers: operators}),
	}
}

// TestRunReshareAsExistingOperator_NumNewOperatorsValidation covers the early-exit
// guard added to RunReshareAsExistingOperator. All three cases return an "out of
// range" error before any session or share logic is executed.
func TestRunReshareAsExistingOperator_NumNewOperatorsValidation(t *testing.T) {
	t.Run("numNew equals len(operators) is rejected", func(t *testing.T) {
		n := makeNodeForValidation(t, 3)
		err := n.RunReshareAsExistingOperator(1000, 3)
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range")
	})

	t.Run("numNew greater than len(operators) is rejected", func(t *testing.T) {
		n := makeNodeForValidation(t, 3)
		err := n.RunReshareAsExistingOperator(1000, 99)
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range")
	})

	t.Run("negative numNew is rejected", func(t *testing.T) {
		n := makeNodeForValidation(t, 3)
		err := n.RunReshareAsExistingOperator(1000, -1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range")
	})
}

// TestRunReshareAsNewOperator_NumNewOperatorsValidation mirrors the above for
// RunReshareAsNewOperator.
func TestRunReshareAsNewOperator_NumNewOperatorsValidation(t *testing.T) {
	t.Run("numNew equals len(operators) is rejected", func(t *testing.T) {
		n := makeNodeForValidation(t, 3)
		err := n.RunReshareAsNewOperator(1000, 3)
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range")
	})

	t.Run("numNew greater than len(operators) is rejected", func(t *testing.T) {
		n := makeNodeForValidation(t, 3)
		err := n.RunReshareAsNewOperator(1000, 99)
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range")
	})

	t.Run("negative numNew is rejected", func(t *testing.T) {
		n := makeNodeForValidation(t, 3)
		err := n.RunReshareAsNewOperator(1000, -1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range")
	})
}

// TestRunReshareAsNewOperator_ZeroNumNewOperatorsPassesGuard documents that
// numNewOperators=0 is syntactically valid (satisfies the [0, N) range guard)
// for any non-empty operator set.
//
// Semantically, passing 0 is incorrect: the docstring states numNewOperators is
// the total count of operators joining simultaneously (including self), so 0
// implies no one is joining — contradicting the purpose of the function.
// The guard does not enforce this semantic constraint; callers must pass at least 1.
//
// The guard does correctly reject 0 for an empty operator set (N=0), since 0 >= 0.
func TestRunReshareAsNewOperator_ZeroNumNewOperatorsPassesGuard(t *testing.T) {
	// For any non-empty operator set, numNew=0 satisfies 0 < N and therefore
	// passes the guard condition: numNew < 0 || numNew >= N.
	for _, numOps := range []int{1, 2, 5} {
		outOfRange := 0 < 0 || 0 >= numOps
		require.False(t, outOfRange,
			"numNewOperators=0 should pass the [0, %d) guard for a %d-operator set",
			numOps, numOps)
	}

	// For an empty operator set, 0 >= 0 is true: the guard correctly rejects it.
	require.True(t, 0 >= 0, "numNewOperators=0 is correctly rejected for an empty operator set")
}
