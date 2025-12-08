package blockHandler

import (
	"context"

	chainPoller "github.com/Layr-Labs/chain-indexer/pkg/chainPollers"
	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"go.uber.org/zap"
)

type IBlockHandler interface {
	chainPoller.IBlockHandler
	ListenToChannel(ctx context.Context, handleFunc func(*ethereum.EthereumBlock))
}

type BlockHandler struct {
	BlockChannel chan *ethereum.EthereumBlock
	logger       *zap.Logger
}

func NewBlockHandler(
	logger *zap.Logger,
) *BlockHandler {
	return &BlockHandler{
		// 100 block capacity should be more than enough to handle finalized blocks
		BlockChannel: make(chan *ethereum.EthereumBlock, 100),
		logger:       logger,
	}
}

func (h *BlockHandler) ListenToChannel(ctx context.Context, handleFunc func(*ethereum.EthereumBlock)) {
	for {
		select {
		// read blocks from the channel and call handleFunc
		case block := <-h.BlockChannel:
			h.logger.Sugar().Infof("BlockHandler received block %d from channel", block.Number)
			handleFunc(block)
		case <-ctx.Done():
			h.logger.Sugar().Info("BlockHandler channel listener exiting due to context done")
			return
		}
	}
}

func (h *BlockHandler) HandleBlock(ctx context.Context, block *ethereum.EthereumBlock) error {
	// Process block
	select {
	case h.BlockChannel <- block:
		h.logger.Sugar().Debugf("Block %d sent to channel", block.Number)
	case <-ctx.Done():
		h.logger.Sugar().Warnf("Context done before sending block %d to channel", block.Number)
	default:
		h.logger.Sugar().Warnf("Block channel is full, dropping block %d", block.Number)
	}
	return nil
}

func (h *BlockHandler) HandleLog(ctx context.Context, logWithBlock *chainPoller.LogWithBlock) error {
	// we dont care about logs, so just return nil
	return nil
}

func (h *BlockHandler) HandleReorgBlock(ctx context.Context, blockNumber uint64) {
	// we'll be indexing finalized blocks only, so no reorgs
}
