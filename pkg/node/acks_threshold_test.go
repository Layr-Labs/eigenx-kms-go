package node

import (
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestWaitForAcks_Threshold(t *testing.T) {
	ops := make([]*peering.OperatorSetPeer, 5)
	for i := range ops {
		ops[i] = &peering.OperatorSetPeer{}
	}

	session := &ProtocolSession{
		Operators: ops,
		acks:      make(map[int64]map[int64]*types.Acknowledgement),
	}

	dealerID := int64(123)
	session.acks[dealerID] = make(map[int64]*types.Acknowledgement)

	// Add 3 acks.
	session.acks[dealerID][1] = &types.Acknowledgement{}
	session.acks[dealerID][2] = &types.Acknowledgement{}
	session.acks[dealerID][3] = &types.Acknowledgement{}

	// With 5 operators, maxPossible is 4. Requiring 3 should succeed quickly.
	require.NoError(t, waitForAcks(session, dealerID, 3, 200*time.Millisecond))
}

func TestWaitForAcks_TimesOutIfInsufficient(t *testing.T) {
	ops := make([]*peering.OperatorSetPeer, 5)
	for i := range ops {
		ops[i] = &peering.OperatorSetPeer{}
	}

	session := &ProtocolSession{
		Operators: ops,
		acks:      make(map[int64]map[int64]*types.Acknowledgement),
	}

	dealerID := int64(123)
	session.acks[dealerID] = make(map[int64]*types.Acknowledgement)

	// Only 1 ack present.
	session.acks[dealerID][1] = &types.Acknowledgement{}

	err := waitForAcks(session, dealerID, 3, 80*time.Millisecond)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timeout waiting for acks")
}



