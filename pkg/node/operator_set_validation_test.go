package node

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestValidateOperatorSetNoNodeIDCollisions_OK(t *testing.T) {
	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: common.HexToAddress("0x1111111111111111111111111111111111111111")},
		{OperatorAddress: common.HexToAddress("0x2222222222222222222222222222222222222222")},
	}

	require.NoError(t, validateOperatorSetNoNodeIDCollisions(operators))
}

func TestValidateOperatorSetNoNodeIDCollisions_Empty(t *testing.T) {
	require.NoError(t, validateOperatorSetNoNodeIDCollisions(nil))
	require.NoError(t, validateOperatorSetNoNodeIDCollisions([]*peering.OperatorSetPeer{}))
}

func TestValidateOperatorSetNoNodeIDCollisions_NilOperator(t *testing.T) {
	operators := []*peering.OperatorSetPeer{nil}
	require.ErrorContains(t, validateOperatorSetNoNodeIDCollisions(operators), "operator is nil")
}

func TestValidateOperatorSetNoNodeIDCollisions_DuplicateAddress(t *testing.T) {
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: addr},
		{OperatorAddress: addr},
	}

	require.ErrorContains(t, validateOperatorSetNoNodeIDCollisions(operators), "duplicate operator address")
}

func TestValidateOperatorSetNoNodeIDCollisions_NodeIDCollision(t *testing.T) {
	// Force all addresses to map to the same node ID.
	prev := addressToNodeID
	t.Cleanup(func() { addressToNodeID = prev })
	addressToNodeID = func(_ common.Address) int64 { return 42 }

	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: common.HexToAddress("0x1111111111111111111111111111111111111111")},
		{OperatorAddress: common.HexToAddress("0x2222222222222222222222222222222222222222")},
	}

	require.ErrorContains(t, validateOperatorSetNoNodeIDCollisions(operators), "derived nodeID collision")
}
