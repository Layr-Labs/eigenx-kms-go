package util

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestAddressToNodeID_Invariants(t *testing.T) {
	addr1 := common.HexToAddress("0x1234567890123456789012345678901234567890")
	addr2 := common.HexToAddress("0xABCDEF1234567890ABCDEF1234567890ABCDEF12")

	// Non-negative
	id1 := AddressToNodeID(addr1)
	require.GreaterOrEqual(t, id1, int64(0))

	// Deterministic
	require.Equal(t, id1, AddressToNodeID(addr1))

	// Different addresses produce different IDs (for these fixtures)
	id2 := AddressToNodeID(addr2)
	require.GreaterOrEqual(t, id2, int64(0))
	require.NotEqual(t, id1, id2)
}


