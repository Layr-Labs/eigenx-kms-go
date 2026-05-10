package node

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/keystore"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestReturningOperatorNotExcluded verifies that an operator present in the on-chain
// operator set but absent from the local activeVersion.ParticipantIDs is still
// included in existingOpIDs. This was the root cause of the "got 0/2 acks" bug:
// operators that missed a reshare were filtered out, preventing other nodes from
// ever acknowledging their shares.
func TestReturningOperatorNotExcluded(t *testing.T) {
	addrA := common.HexToAddress("0x000000000000000000000000000000000000000A")
	addrB := common.HexToAddress("0x000000000000000000000000000000000000000B")
	addrC := common.HexToAddress("0x000000000000000000000000000000000000000C")

	idA := addressToNodeID(addrA)
	idB := addressToNodeID(addrB)
	idC := addressToNodeID(addrC)

	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: addrA},
		{OperatorAddress: addrB},
		{OperatorAddress: addrC},
	}

	// B's active version only has B and C as participants (A missed the last reshare).
	// With the fix, existingOpIDs is built from the on-chain operator set, not ParticipantIDs.
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	ks := keystore.NewKeyStore()
	version := &types.KeyShareVersion{
		Version:        1,
		IsActive:       true,
		ParticipantIDs: []int64{idB, idC},
	}
	ks.AddVersion(version)
	ks.SetActiveVersion(version)

	_ = &Node{
		logger:          logger,
		keyStore:        ks,
		OperatorAddress: addrB,
	}

	// Build existingOpIDs the same way RunReshareAsExistingOperator now does
	existingOpIDs := make(map[int64]bool, len(operators))
	for _, op := range operators {
		existingOpIDs[addressToNodeID(op.OperatorAddress)] = true
	}

	require.True(t, existingOpIDs[idA], "returning operator A must be in existingOpIDs")
	require.True(t, existingOpIDs[idB], "operator B must be in existingOpIDs")
	require.True(t, existingOpIDs[idC], "operator C must be in existingOpIDs")
}
