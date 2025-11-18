package merkle

// MerkleTree represents a binary merkle tree built from acknowledgements.
// The tree uses keccak256 hashing for Solidity compatibility.
type MerkleTree struct {
	// Leaves contains the original leaf hashes (sorted)
	Leaves [][32]byte

	// Root is the merkle root hash
	Root [32]byte

	// levels stores all tree levels for proof generation
	// levels[0] = leaves, levels[len-1] = root
	levels [][][32]byte
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
