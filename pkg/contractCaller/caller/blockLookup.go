package caller

import (
	"context"
	"fmt"
	"math/big"
)

// HeaderTimestampAt returns the Unix timestamp of the block at blockNumber.
// blockNumber == 0 reads the latest head.
func (cc *ContractCaller) HeaderTimestampAt(ctx context.Context, blockNumber uint64) (uint64, error) {
	var num *big.Int
	if blockNumber != 0 {
		num = new(big.Int).SetUint64(blockNumber)
	}
	header, err := cc.ethclient.HeaderByNumber(ctx, num)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch header for block %d: %w", blockNumber, err)
	}
	return header.Time, nil
}

// FirstBlockAtOrAfterTimestamp returns the lowest block number whose timestamp
// is >= targetTimestamp. It errors if the current head's timestamp is still
// below the target (the caller must wait for the chain to advance and retry).
func (cc *ContractCaller) FirstBlockAtOrAfterTimestamp(ctx context.Context, targetTimestamp uint64) (uint64, error) {
	headNum, err := cc.ethclient.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch head header: %w", err)
	}
	head := headNum.Number.Uint64()
	return firstBlockAtOrAfterTimestamp(ctx, targetTimestamp, head, cc.HeaderTimestampAt)
}

// firstBlockAtOrAfterTimestamp is the pure binary search, injectable for tests.
// tsAt(ctx, n) returns block n's timestamp (n==0 => head).
func firstBlockAtOrAfterTimestamp(
	ctx context.Context,
	target uint64,
	head uint64,
	tsAt func(context.Context, uint64) (uint64, error),
) (uint64, error) {
	headTs, err := tsAt(ctx, head)
	if err != nil {
		return 0, err
	}
	if headTs < target {
		return 0, fmt.Errorf("head block %d timestamp %d is below target %d; chain not advanced yet", head, headTs, target)
	}
	// Binary search for the lowest n in [1, head] with tsAt(n) >= target.
	// The search deliberately excludes block 0 (genesis): a genesis timestamp is
	// always below any real cutoff target we resolve, so block 0 can never be the
	// answer, and starting at 1 keeps the range to actual post-genesis blocks.
	lo, hi := uint64(1), head
	for lo < hi {
		mid := lo + (hi-lo)/2
		ts, err := tsAt(ctx, mid)
		if err != nil {
			return 0, err
		}
		if ts >= target {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo, nil
}
