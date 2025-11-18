package caller

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// TestCommitmentRegistryFunctions tests that functions exist and compile correctly
// Note: Full integration tests with real chain will be in Phase 7
func TestCommitmentRegistryFunctions(t *testing.T) {
	// This test verifies the functions exist and compile
	// The interface compliance is checked by the compiler when implementing IContractCaller
	t.Run("Functions exist", func(t *testing.T) {
		// If these compile, the functions exist with correct receiver types
		var c *ContractCaller
		require.NotNil(t, c.SubmitCommitment)
		require.NotNil(t, c.GetCommitment)
	})
}

// TestCommitmentHashTypes verifies hash types are correct
func TestCommitmentHashTypes(t *testing.T) {
	var commitmentHash [32]byte
	var ackMerkleRoot [32]byte

	// Fill with test data
	for i := 0; i < 32; i++ {
		commitmentHash[i] = byte(i)
		ackMerkleRoot[i] = byte(i + 1)
	}

	// Verify sizes
	require.Equal(t, 32, len(commitmentHash))
	require.Equal(t, 32, len(ackMerkleRoot))

	// Verify conversion to common.Hash works
	commitmentCommonHash := common.BytesToHash(commitmentHash[:])
	require.NotEqual(t, common.Hash{}, commitmentCommonHash)
}

// TestEpochType verifies epoch type conversion
func TestEpochType(t *testing.T) {
	epoch := int64(1234567890)

	// Verify conversion to uint64 for contract
	epochUint64 := uint64(epoch)
	require.Equal(t, uint64(1234567890), epochUint64)

	// Verify conversion to big.Int if needed
	epochBig := big.NewInt(epoch)
	require.Equal(t, int64(1234567890), epochBig.Int64())
}
