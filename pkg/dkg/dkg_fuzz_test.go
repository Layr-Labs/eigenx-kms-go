package dkg

import (
	"math/big"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// helper to build a deterministic operator list of size n.
func testOperators(n int) []*peering.OperatorSetPeer {
	ops := make([]*peering.OperatorSetPeer, 0, n)
	for i := 0; i < n; i++ {
		addr := common.BigToAddress(bigIntFromInt(i + 1))
		ops = append(ops, &peering.OperatorSetPeer{OperatorAddress: addr})
	}
	return ops
}

// bigIntFromInt provides a small helper to avoid importing math/big repeatedly.
func bigIntFromInt(v int) *big.Int {
	return big.NewInt(int64(v))
}

func FuzzGenerateVerifyAndFinalize(f *testing.F) {
	f.Add(3)
	f.Add(4)
	f.Add(5)

	f.Fuzz(func(t *testing.T, n int) {
		if n < 3 {
			n = 3
		}
		if n > 8 {
			n = 8
		}

		operators := testOperators(n)
		threshold := CalculateThreshold(len(operators))

		// Use the first operator as the dealer for this fuzz run.
		dealerID := addressToNodeID(operators[0].OperatorAddress)
		d := NewDKG(dealerID, threshold, operators)

		shares, commitments, err := d.GenerateShares()
		require.NoError(t, err)
		require.Len(t, commitments, threshold)

		// Every participant should verify its own share against the commitments.
		for _, op := range operators {
			opID := addressToNodeID(op.OperatorAddress)
			verifier := NewDKG(opID, threshold, operators)
			share, ok := shares[opID]
			require.True(t, ok, "missing share for operator")
			require.True(t, verifier.VerifyShare(opID, share, commitments), "share failed verification")
		}

		// Finalize and ensure the private share is the sum of all shares we computed.
		participantIDs := make([]int, 0, len(shares))
		for id := range shares {
			participantIDs = append(participantIDs, id)
		}

		keyVersion := d.FinalizeKeyShare(shares, [][]types.G2Point{commitments}, participantIDs)
		require.NotNil(t, keyVersion)
		require.NotNil(t, keyVersion.PrivateShare)

		expected := new(fr.Element).SetZero()
		for _, share := range shares {
			expected.Add(expected, share)
		}
		require.True(t, expected.Equal(keyVersion.PrivateShare), "finalized private share mismatch")
	})
}
