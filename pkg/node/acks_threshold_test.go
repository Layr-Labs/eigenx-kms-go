package node

import (
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestWaitForAcks_Threshold(t *testing.T) {
	ops := make([]*peering.OperatorSetPeer, 5)
	for i := range ops {
		ops[i] = &peering.OperatorSetPeer{}
	}

	session := &ProtocolSession{
		Operators: ops,
		acks:      make(map[common.Address]map[common.Address]*types.Acknowledgement),
	}

	dealerAddr := common.HexToAddress("0x7B")
	session.acks[dealerAddr] = make(map[common.Address]*types.Acknowledgement)

	// Add 3 acks.
	session.acks[dealerAddr][common.HexToAddress("0x01")] = &types.Acknowledgement{}
	session.acks[dealerAddr][common.HexToAddress("0x02")] = &types.Acknowledgement{}
	session.acks[dealerAddr][common.HexToAddress("0x03")] = &types.Acknowledgement{}

	// With 5 operators, maxPossible is 4. Requiring 3 should succeed quickly.
	require.NoError(t, waitForAcks(session, dealerAddr, 3, 200*time.Millisecond))
}

func TestWaitForAcks_TimesOutIfInsufficient(t *testing.T) {
	ops := make([]*peering.OperatorSetPeer, 5)
	for i := range ops {
		ops[i] = &peering.OperatorSetPeer{}
	}

	session := &ProtocolSession{
		Operators: ops,
		acks:      make(map[common.Address]map[common.Address]*types.Acknowledgement),
	}

	dealerAddr := common.HexToAddress("0x7B")
	session.acks[dealerAddr] = make(map[common.Address]*types.Acknowledgement)

	// Only 1 ack present.
	session.acks[dealerAddr][common.HexToAddress("0x01")] = &types.Acknowledgement{}

	err := waitForAcks(session, dealerAddr, 3, 80*time.Millisecond)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timeout waiting for acks")
}
