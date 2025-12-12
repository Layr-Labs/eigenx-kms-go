package util

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func FuzzValidateAppID(f *testing.F) {
	f.Add("")
	f.Add("a")
	f.Add("abcd")
	f.Add("abcde")
	f.Add("valid-app-id")

	f.Fuzz(func(t *testing.T, appID string) {
		err := ValidateAppID(appID)
		if appID == "" {
			require.Error(t, err)
			return
		}
		if len(appID) < 5 {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
	})
}

func FuzzAddressToNodeIDDeterministic(f *testing.F) {
	f.Add(make([]byte, 20))
	f.Add([]byte("01234567890123456789"))

	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 20 {
			return
		}
		addr := common.BytesToAddress(b[:20])

		id1 := AddressToNodeID(addr)
		id2 := AddressToNodeID(addr)
		require.Equal(t, id1, id2)
	})
}

func FuzzStringToECDSAPrivateKeyAndDeriveAddressRoundTrip(f *testing.F) {
	// Use a known-valid private key seed.
	f.Add(make([]byte, 32))
	f.Add([]byte("seed"))

	f.Fuzz(func(t *testing.T, seed []byte) {
		// Normalize to 32 bytes for secp256k1 private key material.
		// Use keccak so arbitrary-length seeds become a uniform 32-byte value.
		h := crypto.Keccak256(seed)
		require.Len(t, h, 32)

		// Hex encode (sometimes with 0x prefix) to feed StringToECDSAPrivateKey.
		hexKey := hex.EncodeToString(h)
		keyStr := hexKey
		if len(seed)%2 == 0 {
			keyStr = "0x" + hexKey
		}

		pk, err := StringToECDSAPrivateKey(keyStr)
		if err != nil {
			// Many 32-byte values are rejected by the curve as invalid keys; that's fine.
			return
		}
		require.NotNil(t, pk)

		addr1, err := DeriveAddressFromECDSAPrivateKey(pk)
		require.NoError(t, err)

		addr2 := crypto.PubkeyToAddress(pk.PublicKey)
		require.Equal(t, addr2, addr1)

		// Also ensure the string-based helper matches.
		addr3, err := DeriveAddressFromECDSAPrivateKeyString(keyStr)
		require.NoError(t, err)
		require.Equal(t, addr1, addr3)
	})
}

func FuzzMapFilterReduceFlattenBasics(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Keep sizes small.
		if len(data) > 256 {
			data = data[:256]
		}

		// Map: byte -> int (and ensure output doesn't alias input).
		mapped := Map(data, func(b byte, idx uint64) int {
			return int(b) + int(idx%7)
		})
		require.Len(t, mapped, len(data))
		if len(mapped) > 0 {
			orig := data[0]
			mapped[0]++
			require.Equal(t, orig, data[0], "Map output must not alias input")
		}

		// Filter: keep even ints.
		evens := Filter(mapped, func(v int) bool { return v%2 == 0 })
		for _, v := range evens {
			require.Equal(t, 0, v%2)
		}

		// Reduce: sum should match manual sum.
		sum := Reduce(mapped, func(acc int, next int) int { return acc + next }, 0)
		manual := 0
		for _, v := range mapped {
			manual += v
		}
		require.Equal(t, manual, sum)

		// Flatten: split data into chunks and verify concatenation equals original.
		chunks := make([][]byte, 0, 4)
		for i := 0; i < len(data); i += 7 {
			end := i + 7
			if end > len(data) {
				end = len(data)
			}
			chunks = append(chunks, data[i:end])
		}
		flat := Flatten(chunks)
		require.Equal(t, data, flat)
	})
}
