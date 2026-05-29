package types

import (
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// Test_AppSignResponse_OperatorAddressIsCanonical guards against the aliasing
// regression where AppSignResponse.OperatorAddress was a string. Two payloads
// that differ only in hex casing must decode to the same common.Address so a
// collector can't be tricked into counting a single responder twice.
//
// The wire keys are the unexported default ("OperatorAddress",
// "PartialSignature") — see the AppSignResponse type doc for why we keep them
// rather than switching to snake_case json tags.
func Test_AppSignResponse_OperatorAddressIsCanonical(t *testing.T) {
	// Same address, three encodings: lower-case, upper-case (EIP-55-ish), no 0x prefix on inner hex.
	encodings := []string{
		`{"OperatorAddress":"0xabcdef1234567890abcdef1234567890abcdef12","PartialSignature":{"CompressedBytes":null}}`,
		`{"OperatorAddress":"0xABCDEF1234567890ABCDEF1234567890ABCDEF12","PartialSignature":{"CompressedBytes":null}}`,
		`{"OperatorAddress":"0xAbCdEf1234567890aBcDeF1234567890AbCdEf12","PartialSignature":{"CompressedBytes":null}}`,
	}

	expected := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")

	for i, raw := range encodings {
		var resp AppSignResponse
		require.NoError(t, json.Unmarshal([]byte(raw), &resp), "encoding %d", i)
		require.Equal(t, expected, resp.OperatorAddress, "encoding %d must decode to canonical address", i)
	}
}

// Test_AppSignResponse_WireKeysAreStable pins the wire format so that the
// type-safety change to common.Address does not accidentally rename the
// JSON keys and break operators running pre-PR builds.
func Test_AppSignResponse_WireKeysAreStable(t *testing.T) {
	addr := common.HexToAddress("0x9095535f04796d223A83c0e1346e7C1D9C6EE6f3")

	enc, err := json.Marshal(AppSignResponse{OperatorAddress: addr})
	require.NoError(t, err)

	var wireFields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(enc, &wireFields))

	_, hasOperatorAddress := wireFields["OperatorAddress"]
	_, hasPartialSignature := wireFields["PartialSignature"]
	require.True(t, hasOperatorAddress, "wire key must remain 'OperatorAddress' (no json tag rename)")
	require.True(t, hasPartialSignature, "wire key must remain 'PartialSignature' (no json tag rename)")

	_, hasSnakeOperator := wireFields["operator_address"]
	_, hasSnakePartial := wireFields["partial_signature"]
	require.False(t, hasSnakeOperator, "must not regress to snake_case 'operator_address' wire key")
	require.False(t, hasSnakePartial, "must not regress to snake_case 'partial_signature' wire key")
}

// Test_AppSignResponse_RoundTrip checks that the OperatorAddress survives a
// marshal/unmarshal cycle and remains comparable with ==.
func Test_AppSignResponse_RoundTrip(t *testing.T) {
	addr := common.HexToAddress("0x9095535f04796d223A83c0e1346e7C1D9C6EE6f3")

	enc, err := json.Marshal(AppSignResponse{OperatorAddress: addr})
	require.NoError(t, err)

	var decoded AppSignResponse
	require.NoError(t, json.Unmarshal(enc, &decoded))
	require.Equal(t, addr, decoded.OperatorAddress)
	require.True(t, addr == decoded.OperatorAddress, "common.Address values must be == comparable")
}
