// Package chainpolleradapter bridges the node's own persistence layer
// (persistence.INodePersistence) to the chain-indexer's
// chainPoller.IChainPollerPersistence interface. It is the ONLY place in the
// codebase that imports both the chain-indexer types and the node persistence
// package, keeping the persistence package free of any chain-indexer
// dependency.
package chainpolleradapter

import (
	"context"

	chainPoller "github.com/Layr-Labs/chain-indexer/pkg/chainPollers"
	chainPollerPersistence "github.com/Layr-Labs/chain-indexer/pkg/chainPollers/persistence"
	"github.com/Layr-Labs/chain-indexer/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence"
)

// Adapter wraps an INodePersistence and satisfies the chain-indexer
// chainPoller.IChainPollerPersistence interface.
type Adapter struct {
	p persistence.INodePersistence
}

// Ensure Adapter satisfies the chain-indexer interface at compile time.
var _ chainPoller.IChainPollerPersistence = (*Adapter)(nil)

// NewChainPollerPersistenceAdapter constructs an Adapter over the given node
// persistence layer.
func NewChainPollerPersistenceAdapter(p persistence.INodePersistence) *Adapter {
	return &Adapter{p: p}
}

// toNode translates a chain-indexer block record into a node-local record.
func toNode(block *chainPoller.BlockRecord) *persistence.BlockRecord {
	if block == nil {
		return nil
	}
	return &persistence.BlockRecord{
		Number:     block.Number,
		Hash:       block.Hash,
		ParentHash: block.ParentHash,
		Timestamp:  block.Timestamp,
		ChainId:    uint64(block.ChainId),
	}
}

// fromNode translates a node-local block record into a chain-indexer record.
func fromNode(record *persistence.BlockRecord) *chainPoller.BlockRecord {
	if record == nil {
		return nil
	}
	return &chainPoller.BlockRecord{
		Number:     record.Number,
		Hash:       record.Hash,
		ParentHash: record.ParentHash,
		Timestamp:  record.Timestamp,
		ChainId:    config.ChainId(record.ChainId),
	}
}

// GetLastProcessedBlock returns the last processed block for a chain. The node
// layer signals "not found" with (nil, nil); the chain-indexer contract
// requires the sentinel persistence.ErrNotFound instead (matching the
// library's in-memory implementation), so we translate accordingly.
func (a *Adapter) GetLastProcessedBlock(ctx context.Context, chainId config.ChainId) (*chainPoller.BlockRecord, error) {
	record, err := a.p.GetLastProcessedBlockRecord(uint64(chainId))
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, chainPollerPersistence.ErrNotFound
	}
	return fromNode(record), nil
}

// SaveBlock persists block information for reorg detection and advances the
// last-processed pointer.
func (a *Adapter) SaveBlock(ctx context.Context, block *chainPoller.BlockRecord) error {
	return a.p.SaveBlockRecord(toNode(block))
}

// GetBlock retrieves block information by block number. Translates the node
// layer's (nil, nil) "not found" into the chain-indexer sentinel
// persistence.ErrNotFound.
func (a *Adapter) GetBlock(ctx context.Context, chainId config.ChainId, blockNumber uint64) (*chainPoller.BlockRecord, error) {
	record, err := a.p.GetBlockRecord(uint64(chainId), blockNumber)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, chainPollerPersistence.ErrNotFound
	}
	return fromNode(record), nil
}

// DeleteBlock removes block information from storage (reorg handling).
func (a *Adapter) DeleteBlock(ctx context.Context, chainId config.ChainId, blockNumber uint64) error {
	return a.p.DeleteBlockRecord(uint64(chainId), blockNumber)
}

// Close is a no-op. The node owns the lifecycle of the underlying persistence
// layer, so the adapter must not close the shared store.
func (a *Adapter) Close() error {
	return nil
}
