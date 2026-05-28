package config

import "testing"

func TestIsProductionChain(t *testing.T) {
	cases := []struct {
		name string
		id   ChainId
		want bool
	}{
		{"mainnet", ChainId_EthereumMainnet, true},
		{"sepolia", ChainId_EthereumSepolia, false},
		{"ethereum anvil", ChainId_EthereumAnvil, false},
		{"base sepolia", ChainId_BaseSepolia, false},
		{"base anvil", ChainId_BaseAnvil, false},
		{"unknown id", ChainId(424242), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsProductionChain(tc.id); got != tc.want {
				t.Fatalf("IsProductionChain(%d) = %v, want %v", tc.id, got, tc.want)
			}
		})
	}
}
