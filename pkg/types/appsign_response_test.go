package types

import (
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// TestAppSignResponse_OperatorAddressIsCanonical guards against the aliasing
// regression where AppSignResponse.OperatorAddress was a string. Two payloads
// that differ only in hex casing must decode to the same common.Address so a
// collector can't be tricked into counting a single responder twice.
func TestAppSignResponse_OperatorAddressIsCanonical(t *testing.T) {
	// Same address, three encodings: lower-case, upper-case (EIP-55-ish), no 0x prefix on inner hex.
	encodings := []string{
		`{"operator_address":"0xabcdef1234567890abcdef1234567890abcdef12","partial_signature":{"compressed_bytes":null}}`,
		`{"operator_address":"0xABCDEF1234567890ABCDEF1234567890ABCDEF12","partial_signature":{"compressed_bytes":null}}`,
		`{"operator_address":"0xAbCdEf1234567890aBcDeF1234567890AbCdEf12","partial_signature":{"compressed_bytes":null}}`,
	}

	expected := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")

	for i, raw := range encodings {
		var resp AppSignResponse
		require.NoError(t, json.Unmarshal([]byte(raw), &resp), "encoding %d", i)
		require.Equal(t, expected, resp.OperatorAddress, "encoding %d must decode to canonical address", i)
	}
}

// TestAppSignResponse_RoundTrip checks that the OperatorAddress survives a
// marshal/unmarshal cycle and remains comparable with ==.
func TestAppSignResponse_RoundTrip(t *testing.T) {
	addr := common.HexToAddress("0x9095535f04796d223A83c0e1346e7C1D9C6EE6f3")

	enc, err := json.Marshal(AppSignResponse{OperatorAddress: addr})
	require.NoError(t, err)

	var decoded AppSignResponse
	require.NoError(t, json.Unmarshal(enc, &decoded))
	require.Equal(t, addr, decoded.OperatorAddress)
	require.True(t, addr == decoded.OperatorAddress, "common.Address values must be == comparable")
}
