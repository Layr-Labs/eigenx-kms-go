package caller

import (
	"context"
	"fmt"
	"testing"
)

// fakeChain maps block number -> timestamp; head is the max block.
type fakeChain struct {
	ts   map[uint64]uint64
	head uint64
}

func (f *fakeChain) tsAt(ctx context.Context, n uint64) (uint64, error) {
	if n == 0 {
		n = f.head
	}
	v, ok := f.ts[n]
	if !ok {
		return 0, fmt.Errorf("missing trie node for block %d", n)
	}
	return v, nil
}

func TestFirstBlockAtOrAfterTimestamp(t *testing.T) {
	// blocks 1..10, 2s apart starting at t=1000
	fc := &fakeChain{ts: map[uint64]uint64{}, head: 10}
	for n := uint64(1); n <= 10; n++ {
		fc.ts[n] = 1000 + (n-1)*2 // 1000,1002,...,1018
	}

	cases := []struct {
		target uint64
		want   uint64
	}{
		{1000, 1},  // exact first
		{1001, 2},  // between 1 and 2 -> 2
		{1002, 2},  // exact
		{1017, 10}, // 1016(block 9)<1017 -> first >= is block 10 (1018)
		{1016, 9},  // exact block 9
		{1018, 10},
	}
	for _, c := range cases {
		got, err := firstBlockAtOrAfterTimestamp(context.Background(), c.target, fc.head, fc.tsAt)
		if err != nil {
			t.Fatalf("target %d: unexpected error %v", c.target, err)
		}
		if got != c.want {
			t.Fatalf("target %d: got block %d, want %d", c.target, got, c.want)
		}
	}
}

func TestFirstBlockAtOrAfterTimestamp_HeadNotReached(t *testing.T) {
	fc := &fakeChain{ts: map[uint64]uint64{1: 1000, 2: 1002}, head: 2}
	_, err := firstBlockAtOrAfterTimestamp(context.Background(), 5000, fc.head, fc.tsAt)
	if err == nil {
		t.Fatal("expected error when head timestamp < target, got nil")
	}
}

func TestFirstBlockAtOrAfterTimestamp_HeadZero(t *testing.T) {
	// head == 0 means no blocks beyond genesis exist. The [1, head] search would
	// otherwise return a bogus block 1 for a nonexistent block; the guard must
	// return an error instead.
	fc := &fakeChain{ts: map[uint64]uint64{}, head: 0}
	if _, err := firstBlockAtOrAfterTimestamp(context.Background(), 1000, fc.head, fc.tsAt); err == nil {
		t.Fatal("expected error when head is 0, got nil")
	}
}
