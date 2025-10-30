package testutil

import (
	"context"
	"sync"
	"time"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/blockHandler"
	"go.uber.org/zap"
)

// MockChainPoller implements IChainPoller for testing
// It broadcasts blocks to multiple handlers without actually polling the chain
type MockChainPoller struct {
	blockHandlers []blockHandler.IBlockHandler
	logger        *zap.Logger
	currentBlock  uint64
	blockInterval uint64 // How many blocks to increment per emission
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
}

// NewMockChainPoller creates a new mock chain poller that broadcasts to multiple handlers
// blockInterval determines how many blocks to skip per emission (e.g., 5 for every 5th block)
func NewMockChainPoller(
	blockHandlers []blockHandler.IBlockHandler,
	blockInterval uint64,
	logger *zap.Logger,
) *MockChainPoller {
	return &MockChainPoller{
		blockHandlers: blockHandlers,
		logger:        logger,
		currentBlock:  0,
		blockInterval: blockInterval,
	}
}

// Start implements IChainPoller.Start
// It starts the mock poller but doesn't automatically emit blocks
func (m *MockChainPoller) Start(ctx context.Context) error {
	m.mu.Lock()
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.mu.Unlock()

	m.logger.Sugar().Info("MockChainPoller started")
	return nil
}

// Stop stops the mock poller
func (m *MockChainPoller) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancel != nil {
		m.cancel()
		m.logger.Sugar().Info("MockChainPoller stopped")
	}
}

// EmitBlock emits a single block to all registered block handlers
// The block number is automatically incremented based on blockInterval
func (m *MockChainPoller) EmitBlock() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ctx == nil {
		return nil
	}

	// Increment to next interval boundary
	m.currentBlock += m.blockInterval

	block := &ethereum.EthereumBlock{
		Number:       ethereum.EthereumQuantity(m.currentBlock),
		Hash:         ethereum.EthereumHexString(generateBlockHash(m.currentBlock)),
		Timestamp:    ethereum.EthereumQuantity(time.Now().Unix()),
		ParentHash:   ethereum.EthereumHexString(generateBlockHash(m.currentBlock - 1)),
		Nonce:        ethereum.EthereumHexString("0x0000000000000000"),
		Transactions: []*ethereum.EthereumTransaction{},
	}

	m.logger.Sugar().Debugf("MockChainPoller emitting block %d to %d handlers", m.currentBlock, len(m.blockHandlers))

	// Broadcast block to all handlers
	for i, handler := range m.blockHandlers {
		if err := handler.HandleBlock(m.ctx, block); err != nil {
			m.logger.Sugar().Warnf("Failed to send block %d to handler %d: %v", m.currentBlock, i, err)
		}
	}

	return nil
}

// EmitBlockAtNumber emits a block with a specific block number to all handlers
// This is useful for testing specific interval boundaries
func (m *MockChainPoller) EmitBlockAtNumber(blockNumber uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ctx == nil {
		return nil
	}

	m.currentBlock = blockNumber

	block := &ethereum.EthereumBlock{
		Number:       ethereum.EthereumQuantity(blockNumber),
		Hash:         ethereum.EthereumHexString(generateBlockHash(blockNumber)),
		Timestamp:    ethereum.EthereumQuantity(time.Now().Unix()),
		ParentHash:   ethereum.EthereumHexString(generateBlockHash(blockNumber - 1)),
		Nonce:        ethereum.EthereumHexString("0x0000000000000000"),
		Transactions: []*ethereum.EthereumTransaction{},
	}

	m.logger.Sugar().Debugf("MockChainPoller emitting block %d to %d handlers", blockNumber, len(m.blockHandlers))

	// Broadcast block to all handlers
	for i, handler := range m.blockHandlers {
		if err := handler.HandleBlock(m.ctx, block); err != nil {
			m.logger.Sugar().Warnf("Failed to send block %d to handler %d: %v", blockNumber, i, err)
		}
	}

	return nil
}

// GetCurrentBlock returns the current block number
func (m *MockChainPoller) GetCurrentBlock() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentBlock
}

// SetCurrentBlock sets the current block number (useful for test setup)
func (m *MockChainPoller) SetCurrentBlock(blockNumber uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentBlock = blockNumber
}

// generateBlockHash generates a deterministic block hash for testing
func generateBlockHash(blockNumber uint64) string {
	// Simple deterministic hash generation for testing
	return "0x" + padLeft(uint64ToHex(blockNumber), 64)
}

func uint64ToHex(n uint64) string {
	if n == 0 {
		return "0"
	}
	hex := ""
	for n > 0 {
		digit := n % 16
		if digit < 10 {
			hex = string(rune('0'+digit)) + hex
		} else {
			hex = string(rune('a'+digit-10)) + hex
		}
		n /= 16
	}
	return hex
}

func padLeft(s string, length int) string {
	if len(s) >= length {
		return s
	}
	return string(make([]byte, length-len(s))) + s
}
