package chainpolleradapter

import (
	"context"
	"testing"

	chainPoller "github.com/Layr-Labs/chain-indexer/pkg/chainPollers"
	chainPollerPersistence "github.com/Layr-Labs/chain-indexer/pkg/chainPollers/persistence"
	"github.com/Layr-Labs/chain-indexer/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/persistence/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdapter_RoundTrip(t *testing.T) {
	ctx := context.Background()
	nodePersistence := memory.NewMemoryPersistence()
	defer func() { _ = nodePersistence.Close() }()

	adapter := NewChainPollerPersistenceAdapter(nodePersistence)
	const chainId = config.ChainId(1)

	// Fresh store: not found contract must match the library's memory impl,
	// which returns chainPollerPersistence.ErrNotFound (a sentinel error), not
	// (nil, nil).
	last, err := adapter.GetLastProcessedBlock(ctx, chainId)
	assert.Nil(t, last)
	assert.ErrorIs(t, err, chainPollerPersistence.ErrNotFound)

	got, err := adapter.GetBlock(ctx, chainId, 100)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, chainPollerPersistence.ErrNotFound)

	block1 := &chainPoller.BlockRecord{Number: 100, Hash: "0xaaa", ParentHash: "0x999", Timestamp: 1000, ChainId: chainId}
	block2 := &chainPoller.BlockRecord{Number: 101, Hash: "0xbbb", ParentHash: "0xaaa", Timestamp: 1012, ChainId: chainId}

	require.NoError(t, adapter.SaveBlock(ctx, block1))
	require.NoError(t, adapter.SaveBlock(ctx, block2))

	// Last processed is the last-saved block, round-tripped through the node layer.
	last, err = adapter.GetLastProcessedBlock(ctx, chainId)
	require.NoError(t, err)
	require.NotNil(t, last)
	assert.Equal(t, block2.Number, last.Number)
	assert.Equal(t, block2.Hash, last.Hash)
	assert.Equal(t, block2.ParentHash, last.ParentHash)
	assert.Equal(t, block2.Timestamp, last.Timestamp)
	assert.Equal(t, chainId, last.ChainId)

	// Specific block round-trip.
	got, err = adapter.GetBlock(ctx, chainId, 100)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, block1.Hash, got.Hash)
	assert.Equal(t, chainId, got.ChainId)

	// Delete then confirm the not-found contract again.
	require.NoError(t, adapter.DeleteBlock(ctx, chainId, 100))
	got, err = adapter.GetBlock(ctx, chainId, 100)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, chainPollerPersistence.ErrNotFound)

	// DeleteBlock is idempotent.
	require.NoError(t, adapter.DeleteBlock(ctx, chainId, 100))
}

func TestAdapter_CloseIsNoOp(t *testing.T) {
	nodePersistence := memory.NewMemoryPersistence()
	defer func() { _ = nodePersistence.Close() }()

	adapter := NewChainPollerPersistenceAdapter(nodePersistence)

	// Close must be a no-op: the underlying node persistence stays usable.
	require.NoError(t, adapter.Close())

	err := adapter.SaveBlock(context.Background(), &chainPoller.BlockRecord{
		Number: 1, Hash: "0x1", ChainId: config.ChainId(1),
	})
	require.NoError(t, err)
}
