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

// patchAddressToNodeID replaces the addressToNodeID seam with a map-based stub for the
// duration of the test and restores the original on cleanup.
func patchAddressToNodeID(t *testing.T, mapping map[common.Address]int64) {
	t.Helper()
	prev := addressToNodeID
	t.Cleanup(func() { addressToNodeID = prev })
	addressToNodeID = func(a common.Address) int64 { return mapping[a] }
}

// makeOperators returns a slice of OperatorSetPeers for the given addresses.
func makeOperators(addrs ...common.Address) []*peering.OperatorSetPeer {
	ops := make([]*peering.OperatorSetPeer, len(addrs))
	for i, a := range addrs {
		ops[i] = &peering.OperatorSetPeer{OperatorAddress: a}
	}
	return ops
}

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

// --- validateReshareOperatorOverlap tests ---
//
// Notation: n=9 operators → threshold = ⌈18/3⌉ = 6.
// We use a patched addressToNodeID so that known addresses map to IDs 1–9.

func addrsAndMapping(n int) ([]common.Address, map[common.Address]int64) {
	addrs := make([]common.Address, n)
	m := make(map[common.Address]int64, n)
	for i := 0; i < n; i++ {
		a := common.HexToAddress(fmt.Sprintf("0x%040x", i+1))
		addrs[i] = a
		m[a] = int64(i + 1)
	}
	return addrs, m
}

func TestValidateReshareOperatorOverlap_EmptyOldParticipants(t *testing.T) {
	_, mapping := addrsAndMapping(9)
	patchAddressToNodeID(t, mapping)
	addrs, _ := addrsAndMapping(9)

	require.NoError(t, validateReshareOperatorOverlap(nil, makeOperators(addrs...)))
	require.NoError(t, validateReshareOperatorOverlap([]int64{}, makeOperators(addrs...)))
}

func TestValidateReshareOperatorOverlap_AllOldPresent(t *testing.T) {
	addrs, mapping := addrsAndMapping(9)
	patchAddressToNodeID(t, mapping)

	oldIDs := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9}
	require.NoError(t, validateReshareOperatorOverlap(oldIDs, makeOperators(addrs...)))
}

func TestValidateReshareOperatorOverlap_ExactThreshold(t *testing.T) {
	// n=9, threshold=6; keep exactly 6 old operators in new set.
	addrs, mapping := addrsAndMapping(9)
	patchAddressToNodeID(t, mapping)

	oldIDs := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9}
	// New set: 6 old + 3 brand-new operators (IDs 10-12, not in oldIDs).
	newAddrs := append(addrs[:6], // old operators 1-6
		common.HexToAddress("0x000000000000000000000000000000000000000a"),
		common.HexToAddress("0x000000000000000000000000000000000000000b"),
		common.HexToAddress("0x000000000000000000000000000000000000000c"),
	)
	require.NoError(t, validateReshareOperatorOverlap(oldIDs, makeOperators(newAddrs...)))
}

func TestValidateReshareOperatorOverlap_InsufficientOverlap(t *testing.T) {
	// n=9, threshold=6; only 5 old operators remain.
	addrs, mapping := addrsAndMapping(9)
	patchAddressToNodeID(t, mapping)

	oldIDs := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9}
	newOps := makeOperators(addrs[:5]...) // only old operators 1-5
	err := validateReshareOperatorOverlap(oldIDs, newOps)
	require.ErrorContains(t, err, "insufficient operator overlap")
	require.ErrorContains(t, err, "5 of 9")
}

func TestValidateReshareOperatorOverlap_NoOverlap(t *testing.T) {
	// Entirely new operator set — zero overlap.
	addrs, mapping := addrsAndMapping(9)
	patchAddressToNodeID(t, mapping)

	oldIDs := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9}
	// New operators have addresses not in mapping, so addressToNodeID returns 0 for all.
	brandNew := makeOperators(
		common.HexToAddress("0x000000000000000000000000000000000000000a"),
		common.HexToAddress("0x000000000000000000000000000000000000000b"),
	)
	_ = addrs // silence unused warning
	err := validateReshareOperatorOverlap(oldIDs, brandNew)
	require.ErrorContains(t, err, "insufficient operator overlap")
}

func TestValidateReshareOperatorOverlap_SmallSet(t *testing.T) {
	// n=3, threshold=⌈6/3⌉=2; removing 2 of 3 should fail, removing 1 should pass.
	addrs, mapping := addrsAndMapping(3)
	patchAddressToNodeID(t, mapping)

	oldIDs := []int64{1, 2, 3}

	require.NoError(t, validateReshareOperatorOverlap(oldIDs, makeOperators(addrs[0], addrs[1])))
	require.Error(t, validateReshareOperatorOverlap(oldIDs, makeOperators(addrs[0])))
}
