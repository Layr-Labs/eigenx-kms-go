package util

import (
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/require"
)

func FuzzEncodeStringRoundTrip(f *testing.F) {
	f.Add("")
	f.Add("hello")
	f.Add("こんにちは") // unicode

	// ABI codec for a single string parameter.
	stringType, _ := abi.NewType("string", "", nil)
	args := abi.Arguments{{Type: stringType}}

	f.Fuzz(func(t *testing.T, s string) {
		// Keep memory bounded for fuzzing.
		if len(s) > 4096 {
			s = s[:4096]
		}

		encoded, err := EncodeString(s)
		require.NoError(t, err)

		// Round-trip decode and compare.
		out, err := args.Unpack(encoded)
		require.NoError(t, err)
		require.Len(t, out, 1)

		decoded, ok := out[0].(string)
		require.True(t, ok)
		require.Equal(t, s, decoded)
	})
}


