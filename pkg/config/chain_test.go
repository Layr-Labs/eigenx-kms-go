package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_IsProductionChain(t *testing.T) {
	tests := []struct {
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, IsProductionChain(tt.id))
		})
	}
}
