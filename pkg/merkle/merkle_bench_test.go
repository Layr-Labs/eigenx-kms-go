package merkle

import (
	"fmt"
	"testing"
)

// BenchmarkMerkleTreeBuild benchmarks merkle tree construction with various sizes
func BenchmarkMerkleTreeBuild(b *testing.B) {
	sizes := []int{10, 50, 100, 200}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Acks_%d", size), func(b *testing.B) {
			acks := createTestAcknowledgements(size)
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = BuildMerkleTree(acks)
			}
		})
	}
}

// BenchmarkMerkleProofGeneration benchmarks proof generation
func BenchmarkMerkleProofGeneration(b *testing.B) {
	sizes := []int{10, 50, 100, 200}

	for _, size := range sizes {
		acks := createTestAcknowledgements(size)
		tree, _ := BuildMerkleTree(acks)

		b.Run(fmt.Sprintf("Acks_%d", size), func(b *testing.B) {
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = tree.GenerateProof(i % size)
			}
		})
	}
}

// BenchmarkMerkleProofVerification benchmarks proof verification
func BenchmarkMerkleProofVerification(b *testing.B) {
	sizes := []int{10, 50, 100, 200}

	for _, size := range sizes {
		acks := createTestAcknowledgements(size)
		tree, _ := BuildMerkleTree(acks)
		proof, _ := tree.GenerateProof(0)

		b.Run(fmt.Sprintf("Acks_%d", size), func(b *testing.B) {
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = VerifyProof(proof, tree.Root)
			}
		})
	}
}

// BenchmarkHashAcknowledgement benchmarks acknowledgement hashing
func BenchmarkHashAcknowledgement(b *testing.B) {
	ack := createTestAcknowledgements(1)[0]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HashAcknowledgement(ack)
	}
}

// BenchmarkSortAcknowledgements benchmarks acknowledgement sorting
func BenchmarkSortAcknowledgements(b *testing.B) {
	sizes := []int{10, 50, 100, 200}

	for _, size := range sizes {
		acks := createTestAcknowledgements(size)

		b.Run(fmt.Sprintf("Acks_%d", size), func(b *testing.B) {
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = SortAcknowledgements(acks)
			}
		})
	}
}
