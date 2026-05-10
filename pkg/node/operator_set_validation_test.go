package node

import (
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// makeOperators returns a slice of OperatorSetPeers for the given addresses.
func makeOperators(addrs ...common.Address) []*peering.OperatorSetPeer {
	ops := make([]*peering.OperatorSetPeer, len(addrs))
	for i, a := range addrs {
		ops[i] = &peering.OperatorSetPeer{OperatorAddress: a}
	}
	return ops
}

func TestValidateOperatorSetNoDuplicates_OK(t *testing.T) {
	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: common.HexToAddress("0x1111111111111111111111111111111111111111")},
		{OperatorAddress: common.HexToAddress("0x2222222222222222222222222222222222222222")},
	}

	require.NoError(t, validateOperatorSetNoDuplicates(operators))
}

func TestValidateOperatorSetNoDuplicates_Empty(t *testing.T) {
	require.NoError(t, validateOperatorSetNoDuplicates(nil))
	require.NoError(t, validateOperatorSetNoDuplicates([]*peering.OperatorSetPeer{}))
}

func TestValidateOperatorSetNoDuplicates_NilOperator(t *testing.T) {
	operators := []*peering.OperatorSetPeer{nil}
	require.ErrorContains(t, validateOperatorSetNoDuplicates(operators), "operator is nil")
}

func TestValidateOperatorSetNoDuplicates_DuplicateAddress(t *testing.T) {
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: addr},
		{OperatorAddress: addr},
	}

	require.ErrorContains(t, validateOperatorSetNoDuplicates(operators), "duplicate operator address")
}

func TestValidateOperatorSetNoDuplicates_LargeOperatorSet(t *testing.T) {
	const n = 250
	operators := make([]*peering.OperatorSetPeer, 0, n)
	for i := 0; i < n; i++ {
		addr := common.BigToAddress(new(big.Int).SetUint64(uint64(i)))
		operators = append(operators, &peering.OperatorSetPeer{OperatorAddress: addr})
	}

	require.NoError(t, validateOperatorSetNoDuplicates(operators))
}

func TestValidateOperatorSetNoDuplicates_ZeroAddress(t *testing.T) {
	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: common.Address{}},
		{OperatorAddress: common.HexToAddress("0x1111111111111111111111111111111111111111")},
	}
	require.NoError(t, validateOperatorSetNoDuplicates(operators))
}

func TestValidateOperatorSetNoDuplicates_ConcurrentCalls(t *testing.T) {
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
				require.NoError(t, validateOperatorSetNoDuplicates(operators))
			}
		}()
	}
	wg.Wait()
}

// --- validateReshareOperatorOverlap tests ---

func TestValidateReshareOperatorOverlap_EmptyOldParticipants(t *testing.T) {
	addrs := make([]common.Address, 9)
	for i := range addrs {
		addrs[i] = common.HexToAddress(fmt.Sprintf("0x%040x", i+1))
	}

	require.NoError(t, validateReshareOperatorOverlap(nil, makeOperators(addrs...)))
	require.NoError(t, validateReshareOperatorOverlap([]common.Address{}, makeOperators(addrs...)))
}

func TestValidateReshareOperatorOverlap_AllOldPresent(t *testing.T) {
	addrs := make([]common.Address, 9)
	for i := range addrs {
		addrs[i] = common.HexToAddress(fmt.Sprintf("0x%040x", i+1))
	}

	require.NoError(t, validateReshareOperatorOverlap(addrs, makeOperators(addrs...)))
}

func TestValidateReshareOperatorOverlap_ExactThreshold(t *testing.T) {
	// n=9, threshold=6; keep exactly 6 old operators in new set.
	addrs := make([]common.Address, 9)
	for i := range addrs {
		addrs[i] = common.HexToAddress(fmt.Sprintf("0x%040x", i+1))
	}

	// New set: 6 old + 3 brand-new operators
	newAddrs := append(addrs[:6],
		common.HexToAddress("0x000000000000000000000000000000000000000a"),
		common.HexToAddress("0x000000000000000000000000000000000000000b"),
		common.HexToAddress("0x000000000000000000000000000000000000000c"),
	)
	require.NoError(t, validateReshareOperatorOverlap(addrs, makeOperators(newAddrs...)))
}

func TestValidateReshareOperatorOverlap_InsufficientOverlap(t *testing.T) {
	// n=9, threshold=6; only 5 old operators remain.
	addrs := make([]common.Address, 9)
	for i := range addrs {
		addrs[i] = common.HexToAddress(fmt.Sprintf("0x%040x", i+1))
	}

	newOps := makeOperators(addrs[:5]...)
	err := validateReshareOperatorOverlap(addrs, newOps)
	require.ErrorContains(t, err, "insufficient operator overlap")
	require.ErrorContains(t, err, "5 of 9")
}

func TestValidateReshareOperatorOverlap_NoOverlap(t *testing.T) {
	addrs := make([]common.Address, 9)
	for i := range addrs {
		addrs[i] = common.HexToAddress(fmt.Sprintf("0x%040x", i+1))
	}

	// New operators not in old set
	brandNew := makeOperators(
		common.HexToAddress("0x000000000000000000000000000000000000000a"),
		common.HexToAddress("0x000000000000000000000000000000000000000b"),
	)
	err := validateReshareOperatorOverlap(addrs, brandNew)
	require.ErrorContains(t, err, "insufficient operator overlap")
}

func TestValidateReshareOperatorOverlap_SmallSet(t *testing.T) {
	// n=3, threshold=2; removing 2 of 3 should fail, removing 1 should pass.
	addrs := make([]common.Address, 3)
	for i := range addrs {
		addrs[i] = common.HexToAddress(fmt.Sprintf("0x%040x", i+1))
	}

	require.NoError(t, validateReshareOperatorOverlap(addrs, makeOperators(addrs[0], addrs[1])))
	require.Error(t, validateReshareOperatorOverlap(addrs, makeOperators(addrs[0])))
}
