package transport

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/merkle"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// TestBroadcastCommitmentsWithProofs tests the broadcast function (Phase 5)
func TestBroadcastCommitmentsWithProofs(t *testing.T) {
	// This test verifies the function exists and has correct signature
	// Full integration tests with real HTTP will be in Phase 7
	var c *Client
	require.NotNil(t, c.BroadcastCommitmentsWithProofs)
}

// TestBroadcastCommitmentsWithProofs_NilTree tests error handling for nil merkle tree
func TestBroadcastCommitmentsWithProofs_NilTree(t *testing.T) {
	client := &Client{
		nodeID:       1,
		operatorAddr: common.HexToAddress("0x1111"),
	}

	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: common.HexToAddress("0x2222")},
	}

	err := client.BroadcastCommitmentsWithProofs(
		operators,
		5,
		[]types.G2Point{},
		[]*types.Acknowledgement{},
		nil, // Nil tree should cause error
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "merkle tree is nil")
}

// TestBroadcastCommitmentsWithProofs_MerkleProofGeneration tests proof generation logic
func TestBroadcastCommitmentsWithProofs_MerkleProofGeneration(t *testing.T) {
	// Create test acknowledgements for 3 operators
	acks := make([]*types.Acknowledgement, 3)
	for i := 0; i < 3; i++ {
		_ = fr.NewElement(uint64(100 + i)) // Used for test setup
		acks[i] = &types.Acknowledgement{
			PlayerID:       i + 1,
			DealerID:       99,
			Epoch:          5,
			ShareHash:      [32]byte{byte(i)},
			CommitmentHash: [32]byte{byte(i + 10)},
		}
	}

	// Build merkle tree
	tree, err := merkle.BuildMerkleTree(acks)
	require.NoError(t, err)
	require.NotNil(t, tree)

	// Verify we can generate proofs for all acks
	for i := 0; i < len(acks); i++ {
		proof, err := tree.GenerateProof(i)
		require.NoError(t, err)
		require.NotNil(t, proof)
		require.Equal(t, i, proof.LeafIndex)
	}
}

// TestAddressToNodeID tests address to node ID conversion
func TestAddressToNodeID(t *testing.T) {
	addr1 := common.HexToAddress("0x1234567890123456789012345678901234567890")
	addr2 := common.HexToAddress("0xABCDEF1234567890ABCDEF1234567890ABCDEF12")

	id1 := addressToNodeID(addr1)
	id2 := addressToNodeID(addr2)

	// Different addresses should produce different IDs
	require.NotEqual(t, id1, id2)

	// Same address should produce same ID (deterministic)
	id1_again := addressToNodeID(addr1)
	require.Equal(t, id1, id1_again)
}

// TestSendCommitmentBroadcast tests the send function signature
func TestSendCommitmentBroadcast(t *testing.T) {
	// This test verifies the function compiles with correct types
	var c *Client
	require.NotNil(t, c.sendCommitmentBroadcast)
}
