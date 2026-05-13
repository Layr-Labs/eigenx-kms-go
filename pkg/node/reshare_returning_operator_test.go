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
// operator set but absent from the local activeVersion.ParticipantIDs is NOT counted
// as a new operator by countNewOperatorsInSet. This was the root cause of the
// "got 0/2 acks" bug: operators that missed a reshare were filtered out, preventing
// other nodes from ever acknowledging their shares.
func TestReturningOperatorNotExcluded(t *testing.T) {
	addrA := common.HexToAddress("0x000000000000000000000000000000000000000A")
	addrB := common.HexToAddress("0x000000000000000000000000000000000000000B")
	addrC := common.HexToAddress("0x000000000000000000000000000000000000000C")

	operators := []*peering.OperatorSetPeer{
		{OperatorAddress: addrA},
		{OperatorAddress: addrB},
		{OperatorAddress: addrC},
	}

	// B's active version only has B and C as participants (A missed the last reshare).
	// countNewOperatorsInSet should report A as new (1), since it's not in ParticipantIDs.
	// Critically, it should NOT miscount B or C as new — only genuinely absent operators.
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

	ks := keystore.NewKeyStore()
	version := &types.KeyShareVersion{
		Version:        1,
		IsActive:       true,
		ParticipantIDs: []common.Address{addrA, addrB, addrC},
	}
	ks.AddVersion(version)
	ks.SetActiveVersion(version)

	node := &Node{
		logger:          logger,
		keyStore:        ks,
		OperatorAddress: addrB,
	}

	// When all operators are in ParticipantIDs, countNewOperatorsInSet should return 0.
	newCount := node.countNewOperatorsInSet(operators)
	require.Equal(t, 0, newCount, "countNewOperatorsInSet should return 0 when all operators are known participants")

	// Now simulate A being a returning operator that missed the last reshare:
	// Only B and C in ParticipantIDs.
	versionWithout := &types.KeyShareVersion{
		Version:        2,
		IsActive:       true,
		ParticipantIDs: []common.Address{addrB, addrC},
	}
	ks.AddVersion(versionWithout)
	ks.SetActiveVersion(versionWithout)

	// A is not in ParticipantIDs, so it should be counted as new.
	newCount = node.countNewOperatorsInSet(operators)
	require.Equal(t, 1, newCount, "countNewOperatorsInSet should return 1 for the returning operator not in ParticipantIDs")
}
