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
	ListenToLogChannel(ctx context.Context, handleFunc func(*chainPoller.LogWithBlock))
}

type BlockHandler struct {
	BlockChannel chan *ethereum.EthereumBlock
	LogChannel   chan *chainPoller.LogWithBlock
	logger       *zap.Logger
}

func NewBlockHandler(
	logger *zap.Logger,
) *BlockHandler {
	return &BlockHandler{
		// 100 block capacity should be more than enough to handle finalized blocks
		BlockChannel: make(chan *ethereum.EthereumBlock, 100),
		// 100 log capacity should be more than enough to handle decoded logs
		LogChannel: make(chan *chainPoller.LogWithBlock, 100),
		logger:     logger,
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

func (h *BlockHandler) ListenToLogChannel(ctx context.Context, handleFunc func(*chainPoller.LogWithBlock)) {
	for {
		select {
		// read logs from the channel and call handleFunc
		case logWithBlock := <-h.LogChannel:
			eventName := ""
			if logWithBlock.Log != nil {
				eventName = logWithBlock.Log.EventName
			}
			h.logger.Sugar().Debugf("BlockHandler received log %q from channel", eventName)
			handleFunc(logWithBlock)
		case <-ctx.Done():
			h.logger.Sugar().Info("BlockHandler log channel listener exiting due to context done")
			return
		}
	}
}

func (h *BlockHandler) HandleLog(ctx context.Context, logWithBlock *chainPoller.LogWithBlock) error {
	// deliver the decoded log to the log channel for consumption by listeners
	select {
	case h.LogChannel <- logWithBlock:
		h.logger.Sugar().Debug("Log sent to channel")
	case <-ctx.Done():
		h.logger.Sugar().Warn("Context done before sending log to channel")
	default:
		eventName := ""
		if logWithBlock != nil && logWithBlock.Log != nil {
			eventName = logWithBlock.Log.EventName
		}
		h.logger.Sugar().Warnw("Log channel is full, dropping log", "eventName", eventName)
	}
	return nil
}

func (h *BlockHandler) HandleReorgBlock(ctx context.Context, blockNumber uint64) {
	// we'll be indexing finalized blocks only, so no reorgs
}
