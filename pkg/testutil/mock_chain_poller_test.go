package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/blockHandler"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
)

func TestMockChainPoller(t *testing.T) {
	testLogger, _ := logger.NewLogger(&logger.LoggerConfig{Debug: false})

	bh := blockHandler.NewBlockHandler(testLogger)
	poller := NewMockChainPoller([]blockHandler.IBlockHandler{bh}, 5, testLogger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start poller
	if err := poller.Start(ctx); err != nil {
		t.Fatalf("Failed to start poller: %v", err)
	}

	// Channel to receive blocks
	receivedBlocks := make(chan uint64, 10)
	go func() {
		bh.ListenToChannel(ctx, func(block *ethereum.EthereumBlock) {
			receivedBlocks <- block.Number.Value()
		})
	}()

	// Emit first block at number 5
	if err := poller.EmitBlockAtNumber(5); err != nil {
		t.Fatalf("Failed to emit block: %v", err)
	}

	// Wait for block
	select {
	case blockNum := <-receivedBlocks:
		if blockNum != 5 {
			t.Errorf("Expected block 5, got %d", blockNum)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for block")
	}

	// Emit next block (should be 10)
	if err := poller.EmitBlock(); err != nil {
		t.Fatalf("Failed to emit block: %v", err)
	}

	select {
	case blockNum := <-receivedBlocks:
		if blockNum != 10 {
			t.Errorf("Expected block 10, got %d", blockNum)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for block")
	}

	// Check current block
	if current := poller.GetCurrentBlock(); current != 10 {
		t.Errorf("Expected current block 10, got %d", current)
	}

	poller.Stop()
	t.Logf("✓ MockChainPoller test passed")
}
