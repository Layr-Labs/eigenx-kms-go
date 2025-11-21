package merkle

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/crypto"
	merkletree "github.com/wealdtech/go-merkletree/v2"
	"github.com/wealdtech/go-merkletree/v2/keccak256"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// MerkleTree represents a binary merkle tree built from acknowledgements.
// The tree uses keccak256 hashing for Solidity compatibility.
type MerkleTree struct {
	// Leaves contains the original leaf hashes (sorted)
	Leaves [][32]byte

	// Root is the merkle root hash
	Root [32]byte

	// internalTree stores the go-merkletree instance for proof generation
	internalTree *merkletree.MerkleTree
}

// MerkleProof represents a proof that a leaf is included in the tree.
// The proof consists of sibling hashes along the path from leaf to root.
type MerkleProof struct {
	// LeafIndex is the index of the leaf in the sorted leaves array
	LeafIndex int

	// Leaf is the hash of the leaf being proven
	Leaf [32]byte

	// Proof contains the sibling hashes from leaf to root
	// proof[0] is the sibling of the leaf, proof[len-1] is near the root
	Proof [][32]byte
}

// BuildMerkleTree creates a binary merkle tree from acknowledgements using go-merkletree.
// The acknowledgements are sorted by player address before building the tree
// to ensure deterministic ordering across all operators.
//
// The tree uses keccak256 hashing for Solidity compatibility.
func BuildMerkleTree(acks []*types.Acknowledgement) (*MerkleTree, error) {
	if len(acks) == 0 {
		return nil, fmt.Errorf("cannot build merkle tree from empty acknowledgement list")
	}

	// Sort acknowledgements by player ID for deterministic ordering
	sortedAcks := SortAcknowledgements(acks)

	// Hash all leaves
	leaves := make([][]byte, len(sortedAcks))
	leafHashes := make([][32]byte, len(sortedAcks))
	for i, ack := range sortedAcks {
		hash := HashAcknowledgement(ack)
		leaves[i] = hash[:]
		leafHashes[i] = hash
	}

	// Build merkle tree using go-merkletree with keccak256
	tree, err := merkletree.NewUsing(leaves, keccak256.New(), false)
	if err != nil {
		return nil, fmt.Errorf("failed to build merkle tree: %w", err)
	}

	root := tree.Root()
	var root32 [32]byte
	copy(root32[:], root)

	return &MerkleTree{
		Leaves:       leafHashes,
		Root:         root32,
		internalTree: tree,
	}, nil
}

// GenerateProof creates a merkle proof for the leaf at the given index.
// The proof consists of sibling hashes along the path from leaf to root.
func (mt *MerkleTree) GenerateProof(leafIndex int) (*MerkleProof, error) {
	if leafIndex < 0 || leafIndex >= len(mt.Leaves) {
		return nil, fmt.Errorf("leaf index %d out of bounds (tree has %d leaves)", leafIndex, len(mt.Leaves))
	}

	// Generate proof using go-merkletree
	proof, err := mt.internalTree.GenerateProof(mt.Leaves[leafIndex][:], 0)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	// Convert proof hashes to [][32]byte format
	proofHashes := make([][32]byte, len(proof.Hashes))
	for i, hash := range proof.Hashes {
		var hash32 [32]byte
		copy(hash32[:], hash)
		proofHashes[i] = hash32
	}

	return &MerkleProof{
		LeafIndex: leafIndex,
		Leaf:      mt.Leaves[leafIndex],
		Proof:     proofHashes,
	}, nil
}

// VerifyProof verifies that a leaf is included in the merkle tree with the given root.
// It recomputes the root hash using the proof and checks if it matches the expected root.
func VerifyProof(proof *MerkleProof, root [32]byte) bool {
	if proof == nil {
		return false
	}

	// Convert proof back to go-merkletree format
	proofHashes := make([][]byte, len(proof.Proof))
	for i, hash := range proof.Proof {
		proofHashes[i] = hash[:]
	}

	merkleProof := &merkletree.Proof{
		Hashes: proofHashes,
		Index:  uint64(proof.LeafIndex),
	}

	// Verify using go-merkletree with keccak256
	verified, err := merkletree.VerifyProofUsing(proof.Leaf[:], false, merkleProof, [][]byte{root[:]}, keccak256.New())
	if err != nil {
		return false
	}

	return verified
}

// HashAcknowledgement creates a keccak256 hash of an acknowledgement for use as a merkle leaf.
// The hash format matches the Solidity implementation:
// keccak256(abi.encodePacked(playerID, dealerID, epoch, shareHash, commitmentHash))
//
// Note: This uses integer IDs. For production Solidity compatibility, use Ethereum addresses.
func HashAcknowledgement(ack *types.Acknowledgement) [32]byte {
	// Pack all fields for hashing
	// Format: playerID (8 bytes) || dealerID (8 bytes) || epoch (32 bytes) || shareHash (32 bytes) || commitmentHash (32 bytes)
	data := make([]byte, 0, 8+8+32+32+32)

	// Encode playerID (8 bytes, big endian)
	playerBytes := make([]byte, 8)
	playerBig := big.NewInt(int64(ack.PlayerID))
	playerBig.FillBytes(playerBytes)
	data = append(data, playerBytes...)

	// Encode dealerID (8 bytes, big endian)
	dealerBytes := make([]byte, 8)
	dealerBig := big.NewInt(int64(ack.DealerID))
	dealerBig.FillBytes(dealerBytes)
	data = append(data, dealerBytes...)

	// Encode epoch (32 bytes, big endian)
	epochBytes := make([]byte, 32)
	epochBig := big.NewInt(ack.Epoch)
	epochBig.FillBytes(epochBytes)
	data = append(data, epochBytes...)

	// Append shareHash and commitmentHash
	data = append(data, ack.ShareHash[:]...)
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
