package merkle

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// BuildMerkleTree creates a binary merkle tree from acknowledgements.
// The acknowledgements are sorted by player address before building the tree
// to ensure deterministic ordering across all operators.
//
// The tree uses keccak256 hashing for Solidity compatibility.
// If there's an odd number of nodes at any level, the last node is duplicated.
func BuildMerkleTree(acks []*types.Acknowledgement) (*MerkleTree, error) {
	if len(acks) == 0 {
		return nil, fmt.Errorf("cannot build merkle tree from empty acknowledgement list")
	}

	// Sort acknowledgements by player address for deterministic ordering
	sortedAcks := SortAcknowledgements(acks)

	// Hash all leaves
	leaves := make([][32]byte, len(sortedAcks))
	for i, ack := range sortedAcks {
		leaves[i] = HashAcknowledgement(ack)
	}

	// Build tree levels bottom-up
	levels := make([][][32]byte, 0)
	levels = append(levels, leaves)

	currentLevel := leaves
	for len(currentLevel) > 1 {
		nextLevel := make([][32]byte, 0)

		for i := 0; i < len(currentLevel); i += 2 {
			var left, right [32]byte
			left = currentLevel[i]

			// If odd number of nodes, duplicate the last one
			if i+1 < len(currentLevel) {
				right = currentLevel[i+1]
			} else {
				right = currentLevel[i]
			}

			// Hash the pair: keccak256(left || right)
			parent := hashPair(left, right)
			nextLevel = append(nextLevel, parent)
		}

		levels = append(levels, nextLevel)
		currentLevel = nextLevel
	}

	// The last level should contain only the root
	if len(currentLevel) != 1 {
		return nil, fmt.Errorf("merkle tree construction failed: final level has %d nodes instead of 1", len(currentLevel))
	}

	root := currentLevel[0]

	return &MerkleTree{
		Leaves: leaves,
		Root:   root,
		levels: levels,
	}, nil
}

// GenerateProof creates a merkle proof for the leaf at the given index.
// The proof consists of sibling hashes along the path from leaf to root.
func (mt *MerkleTree) GenerateProof(leafIndex int) (*MerkleProof, error) {
	if leafIndex < 0 || leafIndex >= len(mt.Leaves) {
		return nil, fmt.Errorf("leaf index %d out of bounds (tree has %d leaves)", leafIndex, len(mt.Leaves))
	}

	proof := make([][32]byte, 0)
	index := leafIndex

	// Traverse from leaf to root, collecting sibling hashes
	for level := 0; level < len(mt.levels)-1; level++ {
		currentLevel := mt.levels[level]

		// Find sibling index
		var siblingIndex int
		if index%2 == 0 {
			// Node is on the left, sibling is on the right
			siblingIndex = index + 1
		} else {
			// Node is on the right, sibling is on the left
			siblingIndex = index - 1
		}

		// Handle case where this is the last node (odd number of nodes)
		if siblingIndex >= len(currentLevel) {
			siblingIndex = index // Duplicate the node
		}

		proof = append(proof, currentLevel[siblingIndex])

		// Move to parent index in next level
		index = index / 2
	}

	return &MerkleProof{
		LeafIndex: leafIndex,
		Leaf:      mt.Leaves[leafIndex],
		Proof:     proof,
	}, nil
}

// VerifyProof verifies that a leaf is included in the merkle tree with the given root.
// It recomputes the root hash using the proof and checks if it matches the expected root.
func VerifyProof(proof *MerkleProof, root [32]byte) bool {
	if proof == nil {
		return false
	}

	// Start with the leaf hash
	currentHash := proof.Leaf
	index := proof.LeafIndex

	// Traverse up the tree using the proof
	for _, siblingHash := range proof.Proof {
		if index%2 == 0 {
			// Current node is on the left, sibling is on the right
			currentHash = hashPair(currentHash, siblingHash)
		} else {
			// Current node is on the right, sibling is on the left
			currentHash = hashPair(siblingHash, currentHash)
		}

		// Move to parent index
		index = index / 2
	}

	// Check if computed root matches expected root
	return currentHash == root
}

// HashAcknowledgement creates a keccak256 hash of an acknowledgement for use as a merkle leaf.
// The hash format will eventually match the Solidity implementation:
// keccak256(abi.encodePacked(player, dealer, epoch, shareHash, commitmentHash))
//
// Note: Currently hashing only available fields (player, dealer, commitmentHash).
// This will be updated in Phase 3 when Epoch and ShareHash fields are added to Acknowledgement.
func HashAcknowledgement(ack *types.Acknowledgement) [32]byte {
	// Convert player and dealer IDs to addresses
	// Note: In the actual system, these should be real Ethereum addresses
	// For now, we convert the integer IDs to addresses
	playerAddr := common.BigToAddress(big.NewInt(int64(ack.PlayerID)))
	dealerAddr := common.BigToAddress(big.NewInt(int64(ack.DealerID)))

	// Pack available fields for hashing
	// Format: player (20 bytes) || dealer (20 bytes) || commitmentHash (32 bytes)
	// TODO Phase 3: Add epoch (32 bytes) and shareHash (32 bytes) when fields are added
	data := make([]byte, 0, 20+20+32)
	data = append(data, playerAddr.Bytes()...)
	data = append(data, dealerAddr.Bytes()...)
	data = append(data, ack.CommitmentHash[:]...)

	// Compute keccak256 hash
	hash := crypto.Keccak256Hash(data)
	return [32]byte(hash)
}

// SortAcknowledgements sorts acknowledgements by player ID in ascending order.
// This ensures deterministic merkle tree construction across all operators.
func SortAcknowledgements(acks []*types.Acknowledgement) []*types.Acknowledgement {
	// Create a copy to avoid modifying the original slice
	sorted := make([]*types.Acknowledgement, len(acks))
	copy(sorted, acks)

	// Sort by player ID (ascending)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].PlayerID < sorted[j].PlayerID
	})

	return sorted
}

// hashPair computes keccak256(left || right) for two 32-byte hashes.
// This is used for hashing pairs of nodes when building the merkle tree.
func hashPair(left, right [32]byte) [32]byte {
	data := make([]byte, 64)
	copy(data[0:32], left[:])
	copy(data[32:64], right[:])

	hash := crypto.Keccak256Hash(data)
	return [32]byte(hash)
}
