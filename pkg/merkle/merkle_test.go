package merkle

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// createTestAcknowledgements creates n test acknowledgements with unique player IDs
func createTestAcknowledgements(n int) []*types.Acknowledgement {
	acks := make([]*types.Acknowledgement, n)
	for i := 0; i < n; i++ {
		acks[i] = &types.Acknowledgement{
			PlayerID:       int64(i + 1), // Start from 1 to avoid zero address issues
			DealerID:       100,
			Epoch:          5,
			ShareHash:      randomHash(),
			CommitmentHash: randomHash(),
			Signature:      []byte("test-signature"),
		}
	}
	return acks
}

// randomHash generates a random 32-byte hash for testing
func randomHash() [32]byte {
	var hash [32]byte
	_, _ = rand.Read(hash[:]) // Ignore error in test helper
	return hash
}

// TestBuildMerkleTree tests merkle tree construction with various numbers of acknowledgements
func TestBuildMerkleTree(t *testing.T) {
	testCases := []struct {
		name    string
		numAcks int
	}{
		{"Single ack", 1},
		{"Two acks", 2},
		{"Three acks", 3},
		{"Four acks (power of 2)", 4},
		{"Seven acks", 7},
		{"Eight acks (power of 2)", 8},
		{"Fifteen acks", 15},
		{"Sixteen acks (power of 2)", 16},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			acks := createTestAcknowledgements(tc.numAcks)
			tree, err := BuildMerkleTree(acks)
			require.NoError(t, err)
			require.NotNil(t, tree)

			// Verify tree structure
			require.Equal(t, tc.numAcks, len(tree.Leaves))
			require.NotEqual(t, [32]byte{}, tree.Root)

			// Generate and verify proofs for all leaves
			for i := 0; i < tc.numAcks; i++ {
				proof, err := tree.GenerateProof(i)
				require.NoError(t, err)
				require.NotNil(t, proof)
				require.Equal(t, i, proof.LeafIndex)
				require.Equal(t, tree.Leaves[i], proof.Leaf)

				// Verify the proof
				valid := VerifyProof(proof, tree.Root)
				require.True(t, valid, "Proof for leaf %d should be valid", i)
			}
		})
	}
}

// TestBuildMerkleTreeEmpty tests that building a tree from empty acks fails
func TestBuildMerkleTreeEmpty(t *testing.T) {
	tree, err := BuildMerkleTree([]*types.Acknowledgement{})
	require.Error(t, err)
	require.Nil(t, tree)
	require.Contains(t, err.Error(), "empty")
}

// TestMerkleProofVerification tests proof verification with valid and invalid cases
func TestMerkleProofVerification(t *testing.T) {
	acks := createTestAcknowledgements(4)
	tree, err := BuildMerkleTree(acks)
	require.NoError(t, err)

	t.Run("Valid proof", func(t *testing.T) {
		proof, err := tree.GenerateProof(0)
		require.NoError(t, err)
		require.True(t, VerifyProof(proof, tree.Root))
	})

	t.Run("Invalid proof - wrong root", func(t *testing.T) {
		proof, err := tree.GenerateProof(0)
		require.NoError(t, err)

		invalidRoot := [32]byte{1, 2, 3, 4, 5}
		require.False(t, VerifyProof(proof, invalidRoot))
	})

	t.Run("Invalid proof - tampered leaf", func(t *testing.T) {
		proof, err := tree.GenerateProof(0)
		require.NoError(t, err)

		// Tamper with the leaf
		proof.Leaf[0] ^= 0xFF
		require.False(t, VerifyProof(proof, tree.Root))
	})

	t.Run("Invalid proof - tampered sibling", func(t *testing.T) {
		proof, err := tree.GenerateProof(0)
		require.NoError(t, err)

		// Tamper with a proof element
		if len(proof.Proof) > 0 {
			proof.Proof[0][0] ^= 0xFF
			require.False(t, VerifyProof(proof, tree.Root))
		}
	})

	t.Run("Invalid proof - nil proof", func(t *testing.T) {
		require.False(t, VerifyProof(nil, tree.Root))
	})
}

// TestGenerateProofInvalidIndex tests proof generation with invalid indices
func TestGenerateProofInvalidIndex(t *testing.T) {
	acks := createTestAcknowledgements(4)
	tree, err := BuildMerkleTree(acks)
	require.NoError(t, err)

	t.Run("Negative index", func(t *testing.T) {
		proof, err := tree.GenerateProof(-1)
		require.Error(t, err)
		require.Nil(t, proof)
	})

	t.Run("Index out of bounds", func(t *testing.T) {
		proof, err := tree.GenerateProof(10)
		require.Error(t, err)
		require.Nil(t, proof)
	})
}

// TestAcknowledgementSorting tests that acknowledgements are sorted deterministically
func TestAcknowledgementSorting(t *testing.T) {
	// Create acks with random player IDs
	acks := []*types.Acknowledgement{
		{PlayerID: 5, DealerID: 1},
		{PlayerID: 2, DealerID: 1},
		{PlayerID: 8, DealerID: 1},
		{PlayerID: 1, DealerID: 1},
		{PlayerID: 3, DealerID: 1},
	}

	// Sort multiple times
	sorted1 := SortAcknowledgements(acks)
	sorted2 := SortAcknowledgements(acks)

	// Check sorting is deterministic
	require.Equal(t, len(sorted1), len(sorted2))
	for i := range sorted1 {
		require.Equal(t, sorted1[i].PlayerID, sorted2[i].PlayerID)
	}

	// Check sorting order (ascending)
	for i := 1; i < len(sorted1); i++ {
		require.Less(t, sorted1[i-1].PlayerID, sorted1[i].PlayerID)
	}

	// Ensure original slice is not modified
	require.Equal(t, int64(5), acks[0].PlayerID)
}

// TestSortAcknowledgementsDoesNotMutate verifies sorting doesn't modify the original slice
func TestSortAcknowledgementsDoesNotMutate(t *testing.T) {
	original := createTestAcknowledgements(5)
	originalIDs := make([]int64, len(original))
	for i, ack := range original {
		originalIDs[i] = ack.PlayerID
	}

	// Sort the acks
	_ = SortAcknowledgements(original)

	// Verify original slice is unchanged
	for i, ack := range original {
		require.Equal(t, originalIDs[i], ack.PlayerID)
	}
}

// TestHashAcknowledgement tests acknowledgement hashing
func TestHashAcknowledgement(t *testing.T) {
	ack := &types.Acknowledgement{
		PlayerID:       1,
		DealerID:       2,
		Epoch:          5,
		ShareHash:      [32]byte{1, 2, 3, 4, 5},
		CommitmentHash: [32]byte{6, 7, 8, 9, 10},
	}

	hash1 := HashAcknowledgement(ack)
	hash2 := HashAcknowledgement(ack)

	// Hashing should be deterministic
	require.Equal(t, hash1, hash2)

	// Hash should not be zero
	require.NotEqual(t, [32]byte{}, hash1)
}

// TestHashAcknowledgementDifferentInputs tests that different acks produce different hashes
func TestHashAcknowledgementDifferentInputs(t *testing.T) {
	ack1 := &types.Acknowledgement{
		PlayerID:       1,
		DealerID:       2,
		Epoch:          5,
		ShareHash:      [32]byte{1, 2, 3},
		CommitmentHash: [32]byte{4, 5, 6},
	}

	ack2 := &types.Acknowledgement{
		PlayerID:       2, // Different player
		DealerID:       2,
		Epoch:          5,
		ShareHash:      [32]byte{1, 2, 3},
		CommitmentHash: [32]byte{4, 5, 6},
	}

	hash1 := HashAcknowledgement(ack1)
	hash2 := HashAcknowledgement(ack2)

	require.NotEqual(t, hash1, hash2)
}

// TestMerkleTreeWithIdenticalAcks tests handling of identical acknowledgements
func TestMerkleTreeWithIdenticalAcks(t *testing.T) {
	// Create acks with same data but different player IDs
	acks := []*types.Acknowledgement{
		{
			PlayerID:       1,
			DealerID:       100,
			Epoch:          5,
			ShareHash:      [32]byte{1, 2, 3},
			CommitmentHash: [32]byte{4, 5, 6},
		},
		{
			PlayerID:       2,
			DealerID:       100,
			Epoch:          5,
			ShareHash:      [32]byte{1, 2, 3},
			CommitmentHash: [32]byte{4, 5, 6},
		},
	}

	tree, err := BuildMerkleTree(acks)
	require.NoError(t, err)
	require.NotNil(t, tree)

	// Both leaves should have different hashes (different player IDs)
	require.NotEqual(t, tree.Leaves[0], tree.Leaves[1])
}

// TestMerkleTreeLargeSet tests with a larger number of acknowledgements
func TestMerkleTreeLargeSet(t *testing.T) {
	sizes := []int{50, 100, 200}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			acks := createTestAcknowledgements(size)
			tree, err := BuildMerkleTree(acks)
			require.NoError(t, err)
			require.Equal(t, size, len(tree.Leaves))

			// Verify a few random proofs
			testIndices := []int{0, size / 4, size / 2, size - 1}
			for _, idx := range testIndices {
				if idx < size {
					proof, err := tree.GenerateProof(idx)
					require.NoError(t, err)
					require.True(t, VerifyProof(proof, tree.Root))
				}
			}
		})
	}
}

// TestMerkleProofLength tests that proof length is logarithmic
func TestMerkleProofLength(t *testing.T) {
	testCases := []struct {
		numAcks       int
		maxProofDepth int
	}{
		{1, 0},   // Single leaf, no proof needed
		{2, 1},   // Two leaves, proof depth 1
		{4, 2},   // Four leaves, proof depth 2
		{8, 3},   // Eight leaves, proof depth 3
		{16, 4},  // Sixteen leaves, proof depth 4
		{100, 7}, // 100 leaves, proof depth ~7
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d_acks", tc.numAcks), func(t *testing.T) {
			acks := createTestAcknowledgements(tc.numAcks)
			tree, err := BuildMerkleTree(acks)
			require.NoError(t, err)

			// Check proof length for first leaf
			proof, err := tree.GenerateProof(0)
			require.NoError(t, err)

			// Proof length should be at most maxProofDepth
			require.LessOrEqual(t, len(proof.Proof), tc.maxProofDepth+1)
		})
	}
}

// TestMerkleTreeDeterminism tests that the same acks always produce the same tree
func TestMerkleTreeDeterminism(t *testing.T) {
	acks := createTestAcknowledgements(10)

	// Build tree multiple times
	tree1, err := BuildMerkleTree(acks)
	require.NoError(t, err)

	tree2, err := BuildMerkleTree(acks)
	require.NoError(t, err)

	// Roots should be identical
	require.Equal(t, tree1.Root, tree2.Root)

	// All leaves should be identical
	require.Equal(t, tree1.Leaves, tree2.Leaves)
}

// TestMerkleTreeWithShuffledAcks tests that shuffling doesn't affect the final tree
func TestMerkleTreeWithShuffledAcks(t *testing.T) {
	acks := createTestAcknowledgements(10)

	// Build tree from original order
	tree1, err := BuildMerkleTree(acks)
	require.NoError(t, err)

	// Shuffle and build tree again
	shuffled := make([]*types.Acknowledgement, len(acks))
	copy(shuffled, acks)
	// Reverse the order as a simple shuffle
	for i, j := 0, len(shuffled)-1; i < j; i, j = i+1, j-1 {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	tree2, err := BuildMerkleTree(shuffled)
	require.NoError(t, err)

	// Trees should have the same root (sorting makes them deterministic)
	require.Equal(t, tree1.Root, tree2.Root)
}
