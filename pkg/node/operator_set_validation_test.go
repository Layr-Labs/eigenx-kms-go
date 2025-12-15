package node

import (
	"fmt"
	"math"
	"math/big"
	"sync"
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

func TestValidateOperatorSetNoNodeIDCollisions_LargeOperatorSet(t *testing.T) {
	const n = 250
	operators := make([]*peering.OperatorSetPeer, 0, n)
	for i := 0; i < n; i++ {
		// Deterministic unique addresses (includes the zero address at i=0).
		addr := common.BigToAddress(new(big.Int).SetUint64(uint64(i)))
		operators = append(operators, &peering.OperatorSetPeer{OperatorAddress: addr})
	}

	require.NoError(t, validateOperatorSetNoNodeIDCollisions(operators))
}

func TestValidateOperatorSetNoNodeIDCollisions_ZeroAddress(t *testing.T) {
	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: common.Address{}},
		{OperatorAddress: common.HexToAddress("0x1111111111111111111111111111111111111111")},
	}
	require.NoError(t, validateOperatorSetNoNodeIDCollisions(operators))
}

func TestValidateOperatorSetNoNodeIDCollisions_BoundaryNodeIDsViaSeam(t *testing.T) {
	// Force boundary-ish nodeIDs without needing a preimage on keccak.
	prev := addressToNodeID
	t.Cleanup(func() { addressToNodeID = prev })

	addrLo := common.HexToAddress("0x0000000000000000000000000000000000000001")
	addrHi := common.HexToAddress("0x0000000000000000000000000000000000000002")
	addressToNodeID = func(a common.Address) int64 {
		switch a {
		case addrLo:
			return 0
		case addrHi:
			return math.MaxInt64
		default:
			return 123
		}
	}

	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: addrLo},
		{OperatorAddress: addrHi},
	}

	require.NoError(t, validateOperatorSetNoNodeIDCollisions(operators))
}

func TestValidateOperatorSetNoNodeIDCollisions_ConcurrentCalls(t *testing.T) {
	// This validator should be safe to call concurrently as long as addressToNodeID
	// isn't being mutated (we do not mutate it here).
	const n = 200
	operators := make([]*peering.OperatorSetPeer, 0, n)
	for i := 0; i < n; i++ {
		addr := common.HexToAddress(fmt.Sprintf("0x%040x", i+1))
		operators = append(operators, &peering.OperatorSetPeer{OperatorAddress: addr})
	}

	const goroutines = 16
	const iters = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				require.NoError(t, validateOperatorSetNoNodeIDCollisions(operators))
			}
		}()
	}
	wg.Wait()
}
