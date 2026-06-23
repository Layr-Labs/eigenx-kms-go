package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveConnection(t *testing.T) {
	const sepoliaAVS = "0x47c9806e7DC4e6fE9a0a2399831F32d06DaE5730"

	t.Run("environment preset fills avs and operator-set-id", func(t *testing.T) {
		avs, setID, err := resolveConnection("sepolia", "", false, 0, false)
		require.NoError(t, err)
		require.Equal(t, sepoliaAVS, avs)
		require.Equal(t, uint32(0), setID)
	})

	t.Run("explicit avs-address overrides preset", func(t *testing.T) {
		avs, setID, err := resolveConnection("sepolia", "0xABC", true, 0, false)
		require.NoError(t, err)
		require.Equal(t, "0xABC", avs)
		require.Equal(t, uint32(0), setID)
	})

	t.Run("explicit operator-set-id overrides preset", func(t *testing.T) {
		avs, setID, err := resolveConnection("sepolia", "", false, 2, true)
		require.NoError(t, err)
		require.Equal(t, sepoliaAVS, avs)
		require.Equal(t, uint32(2), setID)
	})

	t.Run("no environment, explicit avs is used", func(t *testing.T) {
		avs, setID, err := resolveConnection("", "0xABC", true, 0, false)
		require.NoError(t, err)
		require.Equal(t, "0xABC", avs)
		require.Equal(t, uint32(0), setID)
	})

	t.Run("no environment, explicit operator-set-id is used", func(t *testing.T) {
		avs, setID, err := resolveConnection("", "0xABC", true, 5, true)
		require.NoError(t, err)
		require.Equal(t, "0xABC", avs)
		require.Equal(t, uint32(5), setID)
	})

	t.Run("no environment and no avs is an error", func(t *testing.T) {
		_, _, err := resolveConnection("", "", false, 0, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "avs-address is required")
	})

	t.Run("unknown environment is an error listing supported names", func(t *testing.T) {
		_, _, err := resolveConnection("mainnet", "", false, 0, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown environment")
		require.Contains(t, err.Error(), "sepolia")
	})
}

func TestSupportedEnvironmentsString(t *testing.T) {
	got := supportedEnvironmentsString()
	require.True(t, strings.Contains(got, "sepolia"), "should list sepolia, got %q", got)
}
