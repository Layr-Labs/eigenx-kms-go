package blockHandler

import (
	"context"
	"sync"
	"testing"
	"time"

	EVMChainPoller "github.com/Layr-Labs/chain-indexer/pkg/chainPollers/evm"
	"github.com/Layr-Labs/chain-indexer/pkg/chainPollers/persistence/memory"
	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	chainIndexerConfig "github.com/Layr-Labs/chain-indexer/pkg/config"
	"github.com/Layr-Labs/chain-indexer/pkg/contractStore/inMemoryContractStore"
	"github.com/Layr-Labs/chain-indexer/pkg/transactionLogParser"
	"github.com/Layr-Labs/eigenx-kms-go/internal/tests"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

const (
	L1RpcUrl = "http://127.0.0.1:8545"
)

func Test_BlockHandler(t *testing.T) {
	t.Run("ReceiveFromPoller", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		// Create block handler
		bh := NewBlockHandler(logger)

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Track received blocks
		var receivedBlocks []uint64
		var mu sync.Mutex

		// Start listening to channel
		go bh.ListenToChannel(ctx, func(block *ethereum.EthereumBlock) {
			mu.Lock()
			defer mu.Unlock()
			receivedBlocks = append(receivedBlocks, block.Number.Value())
			t.Logf("Received block %d", block.Number.Value())
		})

		// Give listener time to start
		time.Sleep(50 * time.Millisecond)

		// Simulate poller sending blocks
		testBlocks := []uint64{1, 2, 5, 10, 15}
		for _, blockNum := range testBlocks {
			block := &ethereum.EthereumBlock{
				Number:    ethereum.EthereumQuantity(blockNum),
				Hash:      ethereum.EthereumHexString("0x123"),
				Timestamp: ethereum.EthereumQuantity(time.Now().Unix()),
			}

			err := bh.HandleBlock(ctx, block)
			if err != nil {
				t.Fatalf("HandleBlock failed: %v", err)
			}
		}

		// Wait for processing
		time.Sleep(200 * time.Millisecond)

		// Verify all blocks received
		mu.Lock()
		defer mu.Unlock()

		if len(receivedBlocks) != len(testBlocks) {
			t.Errorf("Expected %d blocks, got %d", len(testBlocks), len(receivedBlocks))
		}

		for i, expected := range testBlocks {
			if i >= len(receivedBlocks) {
				t.Errorf("Missing block %d", expected)
				continue
			}
			if receivedBlocks[i] != expected {
				t.Errorf("Block %d: expected %d, got %d", i, expected, receivedBlocks[i])
			}
		}

		t.Logf("✓ Successfully received and processed %d blocks", len(receivedBlocks))
	})

	t.Run("MultipleListeners", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		// Create multiple block handlers
		numHandlers := 3
		handlers := make([]*BlockHandler, numHandlers)
		receivedCounts := make([]int, numHandlers)
		var mu sync.Mutex

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Create and start multiple handlers
		for i := 0; i < numHandlers; i++ {
			handlers[i] = NewBlockHandler(logger)
			handlerIdx := i

			go handlers[i].ListenToChannel(ctx, func(block *ethereum.EthereumBlock) {
				mu.Lock()
				receivedCounts[handlerIdx]++
				mu.Unlock()
				t.Logf("Handler %d received block %d", handlerIdx, block.Number.Value())
			})
		}

		// Give listeners time to start
		time.Sleep(50 * time.Millisecond)

		// Send blocks to each handler
		numBlocks := 5
		for i := 0; i < numHandlers; i++ {
			for blockNum := uint64(1); blockNum <= uint64(numBlocks); blockNum++ {
				block := &ethereum.EthereumBlock{
					Number:    ethereum.EthereumQuantity(blockNum),
					Hash:      ethereum.EthereumHexString("0x123"),
					Timestamp: ethereum.EthereumQuantity(time.Now().Unix()),
				}

				err := handlers[i].HandleBlock(ctx, block)
				if err != nil {
					t.Fatalf("HandleBlock failed for handler %d: %v", i, err)
				}

				// Small delay to prevent channel overflow
				time.Sleep(5 * time.Millisecond)
			}
		}

		// Wait for processing
		time.Sleep(200 * time.Millisecond)

		// Verify each handler received all blocks
		mu.Lock()
		defer mu.Unlock()

		for i, count := range receivedCounts {
			if count != numBlocks {
				t.Errorf("Handler %d: expected %d blocks, got %d", i, numBlocks, count)
			}
		}

		t.Logf("✓ All %d handlers successfully received %d blocks each", numHandlers, numBlocks)
	})

	t.Run("ChannelFull", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		// Create block handler with buffer
		bh := NewBlockHandler(logger)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Don't start listener (blocks will accumulate in channel)

		// Send more blocks than channel capacity (100)
		// HandleBlock uses a select with default, so it won't block or error
		// when channel is full - it just drops blocks with a warning
		blocksToSend := 110

		for i := 0; i < blocksToSend; i++ {
			block := &ethereum.EthereumBlock{
				Number:    ethereum.EthereumQuantity(i),
				Hash:      ethereum.EthereumHexString("0x123"),
				Timestamp: ethereum.EthereumQuantity(time.Now().Unix()),
			}

			_ = bh.HandleBlock(ctx, block)
		}

		// Channel should have 100 blocks (its capacity)
		t.Logf("✓ Sent %d blocks (channel capacity 100, overflow dropped)", blocksToSend)

		// Now start listener and verify blocks can be received
		receivedCount := 0
		var receiveMu sync.Mutex

		go bh.ListenToChannel(ctx, func(block *ethereum.EthereumBlock) {
			receiveMu.Lock()
			receivedCount++
			receiveMu.Unlock()
		})

		time.Sleep(300 * time.Millisecond)

		receiveMu.Lock()
		defer receiveMu.Unlock()

		// Should receive up to 100 blocks (channel capacity)
		if receivedCount > 0 && receivedCount <= 100 {
			t.Logf("✓ Received %d blocks from buffer", receivedCount)
		} else {
			t.Errorf("Expected to receive 1-100 blocks, got %d", receivedCount)
		}
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		bh := NewBlockHandler(logger)

		ctx, cancel := context.WithCancel(context.Background())

		// Track if listener stopped
		listenerStopped := make(chan bool, 1)
		receivedCount := 0

		go func() {
			bh.ListenToChannel(ctx, func(block *ethereum.EthereumBlock) {
				receivedCount++
			})
			listenerStopped <- true
		}()

		// Give listener time to start
		time.Sleep(50 * time.Millisecond)

		// Send a few blocks
		for i := 0; i < 3; i++ {
			block := &ethereum.EthereumBlock{
				Number:    ethereum.EthereumQuantity(i),
				Hash:      ethereum.EthereumHexString("0x123"),
				Timestamp: ethereum.EthereumQuantity(time.Now().Unix()),
			}
			_ = bh.HandleBlock(ctx, block)
		}

		time.Sleep(100 * time.Millisecond)

		// Cancel context
		cancel()

		// Wait for listener to stop
		select {
		case <-listenerStopped:
			t.Logf("✓ Listener stopped after context cancellation (processed %d blocks)", receivedCount)
		case <-time.After(2 * time.Second):
			t.Error("Listener did not stop after context cancellation")
		}
	})

	t.Run("BlockOrdering", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		bh := NewBlockHandler(logger)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Track received blocks in order
		var receivedBlocks []uint64
		var mu sync.Mutex

		go bh.ListenToChannel(ctx, func(block *ethereum.EthereumBlock) {
			mu.Lock()
			defer mu.Unlock()
			receivedBlocks = append(receivedBlocks, block.Number.Value())
		})

		// Give listener time to start
		time.Sleep(50 * time.Millisecond)

		// Send blocks in order
		expectedOrder := []uint64{1, 2, 3, 5, 10, 15, 20, 25, 30}
		for _, blockNum := range expectedOrder {
			block := &ethereum.EthereumBlock{
				Number:    ethereum.EthereumQuantity(blockNum),
				Hash:      ethereum.EthereumHexString("0x123"),
				Timestamp: ethereum.EthereumQuantity(time.Now().Unix()),
			}

			err := bh.HandleBlock(ctx, block)
			if err != nil {
				t.Fatalf("HandleBlock failed: %v", err)
			}

			// Small delay to ensure ordering
			time.Sleep(10 * time.Millisecond)
		}

		// Wait for processing
		time.Sleep(200 * time.Millisecond)

		// Verify ordering
		mu.Lock()
		defer mu.Unlock()

		if len(receivedBlocks) != len(expectedOrder) {
			t.Fatalf("Expected %d blocks, got %d", len(expectedOrder), len(receivedBlocks))
		}

		for i, expected := range expectedOrder {
			if receivedBlocks[i] != expected {
				t.Errorf("Block %d: expected %d, got %d (ordering violated)", i, expected, receivedBlocks[i])
			}
		}

		t.Logf("✓ All %d blocks received in correct order", len(receivedBlocks))
	})

	t.Run("HandlerFunction", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		bh := NewBlockHandler(logger)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Track handler calls
		type blockCall struct {
			number    uint64
			hash      string
			timestamp uint64
		}
		var calls []blockCall
		var mu sync.Mutex

		go bh.ListenToChannel(ctx, func(block *ethereum.EthereumBlock) {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, blockCall{
				number:    block.Number.Value(),
				hash:      string(block.Hash),
				timestamp: block.Timestamp.Value(),
			})
		})

		time.Sleep(50 * time.Millisecond)

		// Send test block with specific data
		testBlock := &ethereum.EthereumBlock{
			Number:    ethereum.EthereumQuantity(42),
			Hash:      ethereum.EthereumHexString("0xabcdef"),
			Timestamp: ethereum.EthereumQuantity(1234567890),
		}

		err := bh.HandleBlock(ctx, testBlock)
		if err != nil {
			t.Fatalf("HandleBlock failed: %v", err)
		}

		time.Sleep(100 * time.Millisecond)

		// Verify handler received correct data
		mu.Lock()
		defer mu.Unlock()

		if len(calls) != 1 {
			t.Fatalf("Expected 1 handler call, got %d", len(calls))
		}

		call := calls[0]
		if call.number != 42 {
			t.Errorf("Expected block number 42, got %d", call.number)
		}
		if call.hash != "0xabcdef" {
			t.Errorf("Expected hash 0xabcdef, got %s", call.hash)
		}
		if call.timestamp != 1234567890 {
			t.Errorf("Expected timestamp 1234567890, got %d", call.timestamp)
		}

		t.Logf("✓ Handler function received correct block data")
	})

	t.Run("ConcurrentWrites", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		bh := NewBlockHandler(logger)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Track received blocks
		receivedCount := 0
		var mu sync.Mutex

		go bh.ListenToChannel(ctx, func(block *ethereum.EthereumBlock) {
			mu.Lock()
			receivedCount++
			mu.Unlock()
		})

		time.Sleep(50 * time.Millisecond)

		// Concurrent writers (5 writers * 10 blocks = 50 total, well under 100 capacity)
		numWriters := 5
		blocksPerWriter := 10
		var wg sync.WaitGroup

		for w := 0; w < numWriters; w++ {
			wg.Add(1)
			go func(writerID int) {
				defer wg.Done()
				for i := 0; i < blocksPerWriter; i++ {
					blockNum := uint64(writerID*blocksPerWriter + i)
					block := &ethereum.EthereumBlock{
						Number:    ethereum.EthereumQuantity(blockNum),
						Hash:      ethereum.EthereumHexString("0x123"),
						Timestamp: ethereum.EthereumQuantity(time.Now().Unix()),
					}

					_ = bh.HandleBlock(ctx, block)

					// Small delay to prevent overwhelming the channel
					time.Sleep(2 * time.Millisecond)
				}
			}(w)
		}

		wg.Wait()

		// Wait for processing
		time.Sleep(300 * time.Millisecond)

		mu.Lock()
		defer mu.Unlock()

		expectedTotal := numWriters * blocksPerWriter
		if receivedCount != expectedTotal {
			t.Errorf("Expected %d blocks, got %d", expectedTotal, receivedCount)
		} else {
			t.Logf("✓ Successfully handled %d concurrent writes from %d writers", receivedCount, numWriters)
		}
	})

	t.Run("Poller with anvil", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		l, err := logger.NewLogger(&logger.LoggerConfig{
			Debug: false,
		})
		if err != nil {
			t.Fatalf("Failed to create logger: %v", err)
		}

		root := tests.GetProjectRootPath()
		t.Logf("Project root path: %s", root)

		chainConfig, err := tests.ReadChainConfig(root)
		if err != nil {
			t.Fatalf("Failed to read chain config: %v", err)
		}
		_ = chainConfig

		l1EthereumClient := ethereum.NewEthereumClient(&ethereum.EthereumClientConfig{
			BaseUrl:   L1RpcUrl,
			BlockType: ethereum.BlockType_Latest,
		}, l)

		ethClient, err := l1EthereumClient.GetEthereumContractCaller()
		if err != nil {
			l.Sugar().Fatalf("failed to get Ethereum contract caller: %v", err)
		}
		_ = ethClient

		// ------------------------------------------------------------------------
		// Setup anvil
		// ------------------------------------------------------------------------
		anvilWg := &sync.WaitGroup{}
		anvilWg.Add(1)
		startErrorsChan := make(chan error, 1)

		anvilCtx, anvilCancel := context.WithDeadline(ctx, time.Now().Add(30*time.Second))
		defer anvilCancel()

		_ = tests.KillallAnvils()

		t.Logf("Starting anvil with RPC URL: %s", L1RpcUrl)
		l1Anvil, err := tests.StartL1Anvil(root, ctx)
		if err != nil {
			t.Fatalf("Failed to start L1 Anvil: %v", err)
		}
		go tests.WaitForAnvil(anvilWg, anvilCtx, t, l1EthereumClient, startErrorsChan)

		anvilWg.Wait()
		close(startErrorsChan)
		for err := range startErrorsChan {
			if err != nil {
				t.Errorf("Failed to start Anvil: %v", err)
			}
		}
		anvilCancel()
		t.Logf("Anvil is running")

		hasErrors := false

		_, err = caller.NewContractCaller(ethClient, nil, l)
		if err != nil {
			t.Fatalf("Failed to create contract caller: %v", err)
		}

		// Create block handler
		bh := NewBlockHandler(l)

		// we're not going to parse logs, but these are required for the chain poller
		cs := inMemoryContractStore.NewInMemoryContractStore(nil, l)
		logParser := transactionLogParser.NewTransactionLogParser(cs, l)

		pollerStore := memory.NewInMemoryChainPollerPersistence()
		poller, err := EVMChainPoller.NewEVMChainPoller(
			l1EthereumClient,
			logParser,
			&EVMChainPoller.EVMChainPollerConfig{
				ChainId:         chainIndexerConfig.ChainId(31337),
				PollingInterval: time.Second,
			},
			pollerStore, bh, l)
		if err != nil {
			hasErrors = true
			cancel()
		}

		receivedBlocks := 0
		go bh.ListenToChannel(ctx, func(block *ethereum.EthereumBlock) {
			t.Logf("Block Handler received block %d", block.Number.Value())
			receivedBlocks++
			if receivedBlocks >= 5 {
				t.Logf("Received %d blocks, cancelling test", receivedBlocks)
				cancel()
			}
		})

		if err := poller.Start(ctx); err != nil {
			hasErrors = true
			cancel()
		}

		// ------------------------------------------------------------------------
		// Wait and cleanup
		// ------------------------------------------------------------------------
		select {
		case <-time.After(240 * time.Second):
			cancel()
			t.Errorf("Test timed out after 240 seconds")
		case <-ctx.Done():
			t.Logf("Test completed")
		}

		assert.False(t, hasErrors)
		assert.GreaterOrEqual(t, receivedBlocks, 5, "Expected to receive at least 5 blocks")
		_ = tests.KillAnvil(l1Anvil)
	})
}
