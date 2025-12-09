package testutil

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
)

// CreateTestOperators creates test operators from ChainConfig data
func CreateTestOperators(t *testing.T, numOperators int) []*peering.OperatorSetPeer {
	if t != nil && numOperators > 5 {
		t.Fatalf("Cannot create more than 5 operators (limited by ChainConfig)")
	}

	projectRoot := tests.GetProjectRootPath()
	chainConfig, err := tests.ReadChainConfig(projectRoot)
	if err != nil {
		if t != nil {
			t.Fatalf("Failed to read chain config: %v", err)
		}
		return nil
	}

	addresses := []string{
		chainConfig.OperatorAccountAddress1,
		chainConfig.OperatorAccountAddress2,
		chainConfig.OperatorAccountAddress3,
		chainConfig.OperatorAccountAddress4,
		chainConfig.OperatorAccountAddress5,
	}

	operators := make([]*peering.OperatorSetPeer, numOperators)
	for i := 0; i < numOperators; i++ {
		operators[i] = &peering.OperatorSetPeer{
			OperatorAddress: common.HexToAddress(addresses[i]),
			SocketAddress:   "http://localhost:" + string(rune(9000+i)),
		}
	}

	return operators
}

// CreateTestAcknowledgements creates n test acknowledgements with specified epoch and dealer
func CreateTestAcknowledgements(t *testing.T, n int, epoch int64, dealerID int) []*types.Acknowledgement {
	acks := make([]*types.Acknowledgement, n)
	for i := 0; i < n; i++ {
		share := CreateTestShare(uint64(100 + i))
		acks[i] = &types.Acknowledgement{
			PlayerID:       i + 1,
			DealerID:       dealerID,
			Epoch:          epoch,
			ShareHash:      crypto.HashShareForAck(share),
			CommitmentHash: [32]byte{byte(i), byte(i + 1), byte(i + 2)},
			Signature:      []byte("test-signature"),
		}
	}
	return acks
}

// CreateTestShare creates a test share with a specific value
func CreateTestShare(value uint64) *fr.Element {
	share := fr.NewElement(value)
	return &share
}

// CreateTestCommitments creates n test commitments (G2 points)
func CreateTestCommitments(t *testing.T, n int) []types.G2Point {
	// Get G2 generator
	g2Gen := new(bls12381.G2Affine)
	_, _, _, *g2Gen = bls12381.Generators()

	commitments := make([]types.G2Point, n)
	for i := 0; i < n; i++ {
		// random g2 point
		randomElement, err := new(fr.Element).SetRandom()
		if err != nil {
			t.Fatalf("Failed to create random element: %v", err)
		}
		commitment, err := crypto.ScalarMulG2(crypto.G2Generator, randomElement)
		if err != nil {
			t.Fatalf("Failed to create commitment: %v", err)
		}
		commitments[i] = *commitment
	}
	return commitments
}
