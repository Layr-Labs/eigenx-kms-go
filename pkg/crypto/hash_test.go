package crypto

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

// TestHashShareForAck tests share hashing functionality
func TestHashShareForAck(t *testing.T) {
	// Create a test share
	share := fr.NewElement(12345)

	// Hash the share
	hash1 := HashShareForAck(&share)
	hash2 := HashShareForAck(&share)

	// Hashing should be deterministic
	require.Equal(t, hash1, hash2, "Hash should be deterministic")

	// Hash should not be zero
	require.NotEqual(t, [32]byte{}, hash1, "Hash should not be zero")
}

// TestHashShareForAck_DifferentShares tests that different shares produce different hashes
func TestHashShareForAck_DifferentShares(t *testing.T) {
	share1 := fr.NewElement(12345)
	share2 := fr.NewElement(67890)

	hash1 := HashShareForAck(&share1)
	hash2 := HashShareForAck(&share2)

	require.NotEqual(t, hash1, hash2, "Different shares should produce different hashes")
}

// TestHashAcknowledgementForMerkle tests acknowledgement hashing for merkle trees
func TestHashAcknowledgementForMerkle(t *testing.T) {
	ack := &types.Acknowledgement{
		PlayerID:       1,
		DealerID:       2,
		Epoch:          5,
		ShareHash:      [32]byte{1, 2, 3, 4, 5},
		CommitmentHash: [32]byte{6, 7, 8, 9, 10},
	}

	hash1 := HashAcknowledgementForMerkle(ack)
	hash2 := HashAcknowledgementForMerkle(ack)

	// Hashing should be deterministic
	require.Equal(t, hash1, hash2, "Hash should be deterministic")

	// Hash should not be zero
	require.NotEqual(t, [32]byte{}, hash1, "Hash should not be zero")
}

// TestHashAcknowledgementForMerkle_DifferentInputs tests that different acks produce different hashes
func TestHashAcknowledgementForMerkle_DifferentInputs(t *testing.T) {
	baseAck := &types.Acknowledgement{
		PlayerID:       1,
		DealerID:       2,
		Epoch:          5,
		ShareHash:      [32]byte{1, 2, 3},
		CommitmentHash: [32]byte{4, 5, 6},
	}

	// Test different player IDs
	t.Run("Different PlayerID", func(t *testing.T) {
		ack1 := *baseAck
		ack2 := *baseAck
		ack2.PlayerID = 3

		hash1 := HashAcknowledgementForMerkle(&ack1)
		hash2 := HashAcknowledgementForMerkle(&ack2)

		require.NotEqual(t, hash1, hash2)
	})

	// Test different dealer IDs
	t.Run("Different DealerID", func(t *testing.T) {
		ack1 := *baseAck
		ack2 := *baseAck
		ack2.DealerID = 99

		hash1 := HashAcknowledgementForMerkle(&ack1)
		hash2 := HashAcknowledgementForMerkle(&ack2)

		require.NotEqual(t, hash1, hash2)
	})

	// Test different epochs
	t.Run("Different Epoch", func(t *testing.T) {
		ack1 := *baseAck
		ack2 := *baseAck
		ack2.Epoch = 10

		hash1 := HashAcknowledgementForMerkle(&ack1)
		hash2 := HashAcknowledgementForMerkle(&ack2)

		require.NotEqual(t, hash1, hash2)
	})

	// Test different share hashes
	t.Run("Different ShareHash", func(t *testing.T) {
		ack1 := *baseAck
		ack2 := *baseAck
		ack2.ShareHash = [32]byte{10, 11, 12}

		hash1 := HashAcknowledgementForMerkle(&ack1)
		hash2 := HashAcknowledgementForMerkle(&ack2)

		require.NotEqual(t, hash1, hash2)
	})

	// Test different commitment hashes
	t.Run("Different CommitmentHash", func(t *testing.T) {
		ack1 := *baseAck
		ack2 := *baseAck
		ack2.CommitmentHash = [32]byte{20, 21, 22}

		hash1 := HashAcknowledgementForMerkle(&ack1)
		hash2 := HashAcknowledgementForMerkle(&ack2)

		require.NotEqual(t, hash1, hash2)
	})
}

// TestKeccak256Hash_NonZero verifies keccak256 produces non-zero output
func TestKeccak256Hash_NonZero(t *testing.T) {
	data := []byte("test data")
	hash := keccak256Hash(data)

	require.NotEqual(t, [32]byte{}, hash, "Hash should not be zero")
}

// TestKeccak256Hash_Determinism tests hash determinism
func TestKeccak256Hash_Determinism(t *testing.T) {
	data := []byte("test data")

	hash1 := keccak256Hash(data)
	hash2 := keccak256Hash(data)

	require.Equal(t, hash1, hash2, "Hash should be deterministic")
}

// TestKeccak256Hash_DifferentData tests that different data produces different hashes
func TestKeccak256Hash_DifferentData(t *testing.T) {
	data1 := []byte("test data 1")
	data2 := []byte("test data 2")

	hash1 := keccak256Hash(data1)
	hash2 := keccak256Hash(data2)

	require.NotEqual(t, hash1, hash2, "Different data should produce different hashes")
}

// TestHashShareForAck_ZeroShare tests hashing a zero share
func TestHashShareForAck_ZeroShare(t *testing.T) {
	share := fr.NewElement(0)

	hash := HashShareForAck(&share)

	// Even zero share should produce a valid hash
	require.NotEqual(t, [32]byte{}, hash, "Zero share should still produce a hash")
}

// TestHashShareForAck_LargeShare tests hashing a large share value
func TestHashShareForAck_LargeShare(t *testing.T) {
	// Create a large share value
	share := fr.NewElement(999999999999999999)

	hash := HashShareForAck(&share)

	require.NotEqual(t, [32]byte{}, hash, "Large share should produce a hash")
}
