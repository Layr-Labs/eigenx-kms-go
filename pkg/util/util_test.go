package util

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestAddressToNodeID_Invariants(t *testing.T) {
	addr1 := common.HexToAddress("0x1234567890123456789012345678901234567890")
	addr2 := common.HexToAddress("0xABCDEF1234567890ABCDEF1234567890ABCDEF12")

	// Non-negative
	id1 := AddressToNodeID(addr1)
	require.GreaterOrEqual(t, id1, int64(0))

	// Deterministic
	require.Equal(t, id1, AddressToNodeID(addr1))

	// Different addresses produce different IDs (for these fixtures)
	id2 := AddressToNodeID(addr2)
	require.GreaterOrEqual(t, id2, int64(0))
	require.NotEqual(t, id1, id2)
}

func TestValidateAppID_Boundaries(t *testing.T) {
	tests := []struct {
		name    string
		appID   string
		wantErr bool
	}{
		{name: "empty", appID: "", wantErr: true},
		{name: "4 chars (too short)", appID: "abcd", wantErr: true},
		{name: "5 chars (minimum valid)", appID: "abcde", wantErr: false},
		{name: "255 chars (max valid)", appID: strings.Repeat("a", 255), wantErr: false},
		{name: "256 chars (too long)", appID: strings.Repeat("a", 256), wantErr: true},
		{name: "contains space", appID: "hello world", wantErr: true},
		{name: "contains newline", appID: "hello\nworld", wantErr: true},
		{name: "contains slash", appID: "app/id", wantErr: true},
		{name: "all valid chars", appID: "My-App_1.0", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAppID(tt.appID)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
