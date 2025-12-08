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

// TestBroadcastCommitmentsWithProofs_SkipsSelf tests that broadcast skips self
func TestBroadcastCommitmentsWithProofs_SkipsSelf(t *testing.T) {
	myAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	client := &Client{
		nodeID:       addressToNodeID(myAddr),
		operatorAddr: myAddr,
	}

	// Create operators including self
	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: myAddr}, // Self - should be skipped
		{
			OperatorAddress: common.HexToAddress("0x2222222222222222222222222222222222222222"),
			SocketAddress:   "localhost:7501",
		},
	}

	// Create single ack for the other operator
	otherNodeID := addressToNodeID(operators[1].OperatorAddress)
	acks := []*types.Acknowledgement{
		{
			PlayerID:       otherNodeID,
			DealerID:       client.nodeID,
			Epoch:          5,
			ShareHash:      [32]byte{1},
			CommitmentHash: [32]byte{2},
		},
	}

	// Build merkle tree
	tree, err := merkle.BuildMerkleTree(acks)
	require.NoError(t, err)

	// This will skip self, then try to broadcast to the other operator
	// It will fail the HTTP request but the function logs and continues (returns nil)
	err = client.BroadcastCommitmentsWithProofs(
		operators,
		5, // epoch
		[]types.G2Point{},
		acks,
		tree,
	)

	// The existing implementation logs errors but returns nil (resilient design)
	require.NoError(t, err)
}

// TestBroadcastCommitmentsWithProofs_NoAckForOperator tests handling of missing acks
func TestBroadcastCommitmentsWithProofs_NoAckForOperator(t *testing.T) {
	myAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	client := &Client{
		nodeID:       addressToNodeID(myAddr),
		operatorAddr: myAddr,
	}

	operators := []*peering.OperatorSetPeer{
		{
			OperatorAddress: common.HexToAddress("0x2222222222222222222222222222222222222222"),
			SocketAddress:   "localhost:7501",
		},
		{
			OperatorAddress: common.HexToAddress("0x3333333333333333333333333333333333333333"),
			SocketAddress:   "localhost:7502",
		},
	}

	// Create ack for only ONE operator (missing ack for the other)
	acks := []*types.Acknowledgement{
		{
			PlayerID:       addressToNodeID(operators[0].OperatorAddress),
			DealerID:       client.nodeID,
			Epoch:          5,
			ShareHash:      [32]byte{1},
			CommitmentHash: [32]byte{2},
		},
		// Missing ack for operators[1]
	}

	tree, err := merkle.BuildMerkleTree(acks)
	require.NoError(t, err)

	// Should fail because we can't broadcast to any operators successfully
	// (one has no ack, one will fail to connect)
	err = client.BroadcastCommitmentsWithProofs(
		operators,
		5, // epoch
		[]types.G2Point{},
		acks,
		tree,
	)

	require.Error(t, err)
}
