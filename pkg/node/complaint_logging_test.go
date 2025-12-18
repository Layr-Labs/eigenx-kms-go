package node

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestLogInvalidShareComplaint_EmitsStructuredLog(t *testing.T) {
	core, observed := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	n := &Node{
		OperatorAddress: common.HexToAddress("0x1111111111111111111111111111111111111111"),
		logger:          logger,
	}

	share := fr.NewElement(123)
	commitments := []types.G2Point{
		{CompressedBytes: []byte{1, 2, 3}},
		{CompressedBytes: []byte{4, 5, 6}},
	}

	n.logInvalidShareComplaint("dkg", 999, 7, 42, &share, commitments)

	entries := observed.All()
	require.Len(t, entries, 1)
	require.Equal(t, "ComplaintRecord: invalid share", entries[0].Message)

	ctx := entries[0].ContextMap()
	require.Equal(t, "dkg", ctx["protocol"])
	require.Equal(t, n.OperatorAddress.Hex(), ctx["operator_address"])
	require.Equal(t, int64(7), ctx["receiver_node_id"])
	require.Equal(t, int64(999), ctx["session_timestamp"])
	require.Equal(t, int64(42), ctx["dealer_id"])
	require.Equal(t, int64(2), ctx["commitment_count"])
	require.NotEmpty(t, ctx["share_hash"])
	require.NotEmpty(t, ctx["commitment_hash"])
	require.NotEmpty(t, ctx["share"])
}
