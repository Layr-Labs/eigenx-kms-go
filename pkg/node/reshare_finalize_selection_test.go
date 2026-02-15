package node

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
)

func Test_collectVerifiedSharesForFinalize(t *testing.T) {
	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		{OperatorAddress: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		{OperatorAddress: common.HexToAddress("0x0000000000000000000000000000000000000003")},
	}

	id1 := addressToNodeID(operators[0].OperatorAddress)
	id2 := addressToNodeID(operators[1].OperatorAddress)
	id3 := addressToNodeID(operators[2].OperatorAddress)

	shares := map[int64]*fr.Element{
		id1: new(fr.Element).SetUint64(10),
		id2: new(fr.Element).SetUint64(20),
		id3: new(fr.Element).SetUint64(30),
	}
	commitments := map[int64][]types.G2Point{
		id1: {{CompressedBytes: []byte{1}}},
		id2: {{CompressedBytes: []byte{2}}},
		// id3 intentionally omitted to ensure missing commitment excludes share
	}

	verifyFn := func(dealerID int64, _ *fr.Element, _ []types.G2Point) bool {
		// Mark dealer 2 as invalid even though it has share/commitment.
		return dealerID != id2
	}

	validShares, participantIDs := collectVerifiedSharesForFinalize(operators, shares, commitments, verifyFn)

	if len(validShares) != 1 {
		t.Fatalf("expected exactly 1 valid share, got %d", len(validShares))
	}
	if _, ok := validShares[id1]; !ok {
		t.Fatal("expected dealer 1 to be selected as valid")
	}
	if _, ok := validShares[id2]; ok {
		t.Fatal("expected dealer 2 to be excluded due to failed verification")
	}
	if _, ok := validShares[id3]; ok {
		t.Fatal("expected dealer 3 to be excluded due to missing commitments")
	}
	if len(participantIDs) != 1 || participantIDs[0] != id1 {
		t.Fatalf("unexpected participantIDs ordering/content: %+v", participantIDs)
	}
}
