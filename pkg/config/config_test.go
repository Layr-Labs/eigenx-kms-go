package config

import "testing"

func TestGetReshareCutoffBufferForChain(t *testing.T) {
	cases := []struct {
		chain ChainId
		want  int64
	}{
		{ChainId_EthereumMainnet, 2},
		{ChainId_EthereumSepolia, 2},
		{ChainId_EthereumAnvil, 2},
		{ChainId(999999), 2}, // default
	}
	for _, c := range cases {
		if got := GetReshareCutoffBufferForChain(c.chain); got != c.want {
			t.Fatalf("chain %v: got buffer %d, want %d", c.chain, got, c.want)
		}
	}
}

func TestCutoffBufferStrictlyInsideInterval(t *testing.T) {
	// The cutoff (interval - buffer) must leave >=1 block of room and be > interval/2
	// so dealers have time to submit before it.
	for _, chain := range []ChainId{ChainId_EthereumMainnet, ChainId_EthereumSepolia, ChainId_EthereumAnvil} {
		interval := GetReshareBlockIntervalForChain(chain)
		buffer := GetReshareCutoffBufferForChain(chain)
		if buffer <= 0 || buffer >= interval {
			t.Fatalf("chain %v: buffer %d not strictly inside interval %d", chain, buffer, interval)
		}
	}
}
