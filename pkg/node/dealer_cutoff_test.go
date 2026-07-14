package node

import (
	"context"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"go.uber.org/zap"
)

func TestResolveCutoffL2_MapsL1DeadlineToL2Height(t *testing.T) {
	l, _ := zap.NewDevelopment()

	// L1 interval=10, buffer=2 (Anvil) => deadline = triggerBlock + (10-2) = trigger+8.
	// Stub: L1 deadline block's timestamp is 1_700_000_096; the first L2 block at/after
	// that timestamp is 5000.
	const triggerBlock = int64(100)
	interval := config.GetReshareBlockIntervalForChain(config.ChainId_EthereumAnvil)
	buffer := config.GetReshareCutoffBufferForChain(config.ChainId_EthereumAnvil)
	wantDeadline := uint64(triggerBlock) + uint64(interval-buffer)

	var gotDeadlineArg uint64
	stub := &contractCaller.MockContractCallerStub{
		HeaderTimestampAtFunc: func(ctx context.Context, blockNumber uint64) (uint64, error) {
			gotDeadlineArg = blockNumber
			return 1_700_000_096, nil
		},
		FirstBlockAtOrAfterTimestampFunc: func(ctx context.Context, ts uint64) (uint64, error) {
			if ts != 1_700_000_096 {
				t.Fatalf("expected target ts 1700000096, got %d", ts)
			}
			return 5000, nil
		},
	}

	n := &Node{
		logger:               l,
		ChainID:              config.ChainId_EthereumAnvil,
		platformConfigCaller: stub, // L1-bound caller (see Step 3 for selection)
		baseContractCaller:   stub,
	}

	got, err := n.resolveCutoffL2(context.Background(), triggerBlock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotDeadlineArg != wantDeadline {
		t.Fatalf("expected L1 timestamp lookup at deadline block %d, got %d", wantDeadline, gotDeadlineArg)
	}
	if got != 5000 {
		t.Fatalf("expected cutoffL2 = 5000, got %d", got)
	}
}
