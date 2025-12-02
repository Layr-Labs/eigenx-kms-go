package node

import (
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/merkle"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestVerifyOperatorBroadcast tests broadcast verification (Phase 6)
func TestVerifyOperatorBroadcast(t *testing.T) {
	t.Run("Verify function exists", func(t *testing.T) {
		node := &Node{}
		require.NotNil(t, node.VerifyOperatorBroadcast)
	})

	t.Run("Nil broadcast error", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		node := &Node{
			logger:         logger,
			activeSessions: make(map[int64]*ProtocolSession),
		}

		err := node.VerifyOperatorBroadcast(12345, nil, common.Address{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "broadcast is nil")
	})

	t.Run("Session not found error", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		node := &Node{
			logger:         logger,
			activeSessions: make(map[int64]*ProtocolSession),
		}

		broadcast := &types.CommitmentBroadcast{
			FromOperatorID:   2,
			Epoch:            5,
			Commitments:      []types.G2Point{},
			Acknowledgements: []*types.Acknowledgement{},
		}

		err := node.VerifyOperatorBroadcast(99999, broadcast, common.Address{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "session not found")
	})

	t.Run("My ack not found error", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		myAddr := common.HexToAddress("0x0000000000000000000000000000000000000001")

		session := &ProtocolSession{
			SessionTimestamp:  12345,
			shares:            make(map[int]*fr.Element),
			commitments:       make(map[int][]types.G2Point),
			acks:              make(map[int]map[int]*types.Acknowledgement),
			verifiedOperators: make(map[int]bool),
		}

		node := &Node{
			logger:          logger,
			OperatorAddress: myAddr,
			activeSessions:  map[int64]*ProtocolSession{12345: session},
		}

		// Broadcast with no ack for my node (use different player ID)
		broadcast := &types.CommitmentBroadcast{
			FromOperatorID: 2,
			Epoch:          5,
			Commitments:    []types.G2Point{},
			Acknowledgements: []*types.Acknowledgement{
				{PlayerID: 999}, // Different player ID than my node
			},
		}

		err := node.VerifyOperatorBroadcast(12345, broadcast, common.Address{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "my ack not found")
	})

	t.Run("No share received error", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		myAddr := common.HexToAddress("0x0000000000000000000000000000000000000001")
		myNodeID := addressToNodeID(myAddr)

		session := &ProtocolSession{
			SessionTimestamp:  12345,
			shares:            make(map[int]*fr.Element), // Empty shares
			commitments:       make(map[int][]types.G2Point),
			acks:              make(map[int]map[int]*types.Acknowledgement),
			verifiedOperators: make(map[int]bool),
		}

		node := &Node{
			logger:          logger,
			OperatorAddress: myAddr,
			activeSessions:  map[int64]*ProtocolSession{12345: session},
		}

		// Broadcast with my ack but no share received
		broadcast := &types.CommitmentBroadcast{
			FromOperatorID: 2,
			Epoch:          5,
			Commitments:    []types.G2Point{},
			Acknowledgements: []*types.Acknowledgement{
				{PlayerID: myNodeID, ShareHash: [32]byte{1, 2, 3}}, // Use correct node ID
			},
		}

		err := node.VerifyOperatorBroadcast(12345, broadcast, common.Address{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no share received")
	})

	t.Run("Share hash mismatch error", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		myAddr := common.HexToAddress("0x0000000000000000000000000000000000000001")
		myNodeID := addressToNodeID(myAddr)

		// Create a real share
		realShare := fr.NewElement(12345)
		expectedHash := crypto.HashShareForAck(&realShare)

		session := &ProtocolSession{
			SessionTimestamp: 12345,
			shares: map[int]*fr.Element{
				2: &realShare, // Share from operator 2
			},
			commitments:       make(map[int][]types.G2Point),
			acks:              make(map[int]map[int]*types.Acknowledgement),
			verifiedOperators: make(map[int]bool),
		}

		node := &Node{
			logger:          logger,
			OperatorAddress: myAddr,
			activeSessions:  map[int64]*ProtocolSession{12345: session},
		}

		// Broadcast with wrong shareHash
		wrongHash := [32]byte{99, 99, 99}
		require.NotEqual(t, expectedHash, wrongHash, "Test setup error: hashes should be different")

		broadcast := &types.CommitmentBroadcast{
			FromOperatorID: 2,
			Epoch:          5,
			Commitments:    []types.G2Point{},
			Acknowledgements: []*types.Acknowledgement{
				{
					PlayerID:  myNodeID,  // Use correct node ID
					ShareHash: wrongHash, // Wrong hash!
				},
			},
			MerkleProof: [][32]byte{{1}}, // Non-empty proof
		}

		err := node.VerifyOperatorBroadcast(12345, broadcast, common.Address{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "share hash mismatch")
	})

	t.Run("Successful verification", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		myAddr := common.HexToAddress("0x0000000000000000000000000000000000000001")
		myNodeID := addressToNodeID(myAddr)

		// Create a real share
		realShare := fr.NewElement(12345)
		correctShareHash := crypto.HashShareForAck(&realShare)

		session := &ProtocolSession{
			SessionTimestamp: 12345,
			shares: map[int]*fr.Element{
				2: &realShare,
			},
			commitments:       make(map[int][]types.G2Point),
			acks:              make(map[int]map[int]*types.Acknowledgement),
			verifiedOperators: make(map[int]bool),
		}

		node := &Node{
			logger:          logger,
			OperatorAddress: myAddr,
			activeSessions:  map[int64]*ProtocolSession{12345: session},
		}

		broadcast := &types.CommitmentBroadcast{
			FromOperatorID: 2,
			Epoch:          5,
			Commitments:    []types.G2Point{},
			Acknowledgements: []*types.Acknowledgement{
				{
					PlayerID:       myNodeID,         // Use correct node ID
					ShareHash:      correctShareHash, // Correct hash
					CommitmentHash: [32]byte{},
					Epoch:          5,
					DealerID:       2,
				},
			},
			MerkleProof: [][32]byte{{1, 2, 3}}, // Non-empty proof
		}

		err := node.VerifyOperatorBroadcast(12345, broadcast, common.Address{})
		require.NoError(t, err)

		// Verify operator was marked as verified
		session.mu.RLock()
		verified := session.verifiedOperators[2]
		session.mu.RUnlock()
		require.True(t, verified, "Operator should be marked as verified")
	})
}

// TestWaitForVerifications tests waiting for all verifications (Phase 6)
func TestWaitForVerifications(t *testing.T) {
	t.Run("Function exists", func(t *testing.T) {
		node := &Node{}
		require.NotNil(t, node.WaitForVerifications)
	})

	t.Run("Session not found", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		node := &Node{
			logger:         logger,
			activeSessions: make(map[int64]*ProtocolSession),
		}

		err := node.WaitForVerifications(99999, 1*time.Second)
		require.Error(t, err)
		require.Contains(t, err.Error(), "session not found")
	})

	t.Run("Timeout waiting for verifications", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		session := &ProtocolSession{
			SessionTimestamp: 12345,
			Operators: []*peering.OperatorSetPeer{
				{}, {}, {}, // 3 operators total
			},
			verifiedOperators: make(map[int]bool),
		}

		node := &Node{
			logger:         logger,
			activeSessions: map[int64]*ProtocolSession{12345: session},
		}

		// Only verify 1 operator (need 2 for 3 total)
		session.verifiedOperators[1] = true

		err := node.WaitForVerifications(12345, 100*time.Millisecond)
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout waiting for verifications")
		require.Contains(t, err.Error(), "verified 1/2")
	})

	t.Run("All operators verified", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		session := &ProtocolSession{
			SessionTimestamp: 12345,
			Operators: []*peering.OperatorSetPeer{
				{}, {}, {}, // 3 operators total (need 2 verifications)
			},
			verifiedOperators: make(map[int]bool),
		}

		node := &Node{
			logger:         logger,
			activeSessions: map[int64]*ProtocolSession{12345: session},
		}

		// Verify 2 operators (enough for 3 total)
		session.verifiedOperators[1] = true
		session.verifiedOperators[2] = true

		err := node.WaitForVerifications(12345, 2*time.Second)
		require.NoError(t, err)
	})
}

// TestHashAcknowledgementForMerkle_Integration tests the hash function with real data (Phase 6)
func TestHashAcknowledgementForMerkle_Integration(t *testing.T) {
	share := fr.NewElement(99999)
	ack := &types.Acknowledgement{
		PlayerID:       1,
		DealerID:       2,
		Epoch:          5,
		ShareHash:      crypto.HashShareForAck(&share),
		CommitmentHash: [32]byte{10, 11, 12},
	}

	hash := crypto.HashAcknowledgementForMerkle(ack)
	require.NotEqual(t, [32]byte{}, hash, "Hash should not be zero")

	// Hash should be deterministic
	hash2 := crypto.HashAcknowledgementForMerkle(ack)
	require.Equal(t, hash, hash2)
}

// TestMerkleProofVerification_Integration tests proof verification (Phase 6)
func TestMerkleProofVerification_Integration(t *testing.T) {
	// Create test acks
	acks := make([]*types.Acknowledgement, 3)
	for i := 0; i < 3; i++ {
		share := fr.NewElement(uint64(100 + i))
		acks[i] = &types.Acknowledgement{
			PlayerID:       i + 1,
			DealerID:       99,
			Epoch:          5,
			ShareHash:      crypto.HashShareForAck(&share),
			CommitmentHash: [32]byte{byte(i)},
		}
	}

	// Build tree
	tree, err := merkle.BuildMerkleTree(acks)
	require.NoError(t, err)

	// Generate and verify proof for first ack
	proof, err := tree.GenerateProof(0)
	require.NoError(t, err)

	valid := merkle.VerifyProof(proof, tree.Root)
	require.True(t, valid, "Proof should be valid")

	// Invalid proof should fail
	invalidProof := &merkle.MerkleProof{
		Leaf:  proof.Leaf,
		Proof: [][32]byte{{99, 99, 99}}, // Wrong proof
	}
	invalid := merkle.VerifyProof(invalidProof, tree.Root)
	require.False(t, invalid, "Invalid proof should fail")
}
