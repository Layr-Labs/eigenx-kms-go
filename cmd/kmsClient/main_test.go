package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestLoadECDSAKey(t *testing.T) {
	// A freshly generated key gives us a known-good hex encoding and address
	// to round-trip through loadECDSAKey.
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	keyHex := hex.EncodeToString(ethcrypto.FromECDSA(key))
	wantAddr := ethcrypto.PubkeyToAddress(key.PublicKey)

	t.Run("loads key from hex string", func(t *testing.T) {
		got, err := loadECDSAKey(keyHex, "")
		require.NoError(t, err)
		require.Equal(t, wantAddr, ethcrypto.PubkeyToAddress(got.PublicKey))
	})

	t.Run("tolerates 0x prefix and surrounding whitespace", func(t *testing.T) {
		got, err := loadECDSAKey("  0x"+keyHex+"\n", "")
		require.NoError(t, err)
		require.Equal(t, wantAddr, ethcrypto.PubkeyToAddress(got.PublicKey))
	})

	t.Run("loads key from file with trailing newline", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.hex")
		require.NoError(t, os.WriteFile(path, []byte(keyHex+"\n"), 0600))

		got, err := loadECDSAKey("", path)
		require.NoError(t, err)
		require.Equal(t, wantAddr, ethcrypto.PubkeyToAddress(got.PublicKey))
	})

	t.Run("hex string takes priority over file", func(t *testing.T) {
		// File holds a DIFFERENT valid key; the string value must win.
		other, err := ethcrypto.GenerateKey()
		require.NoError(t, err)
		path := filepath.Join(t.TempDir(), "other.hex")
		require.NoError(t, os.WriteFile(path, []byte(hex.EncodeToString(ethcrypto.FromECDSA(other))), 0600))

		got, err := loadECDSAKey(keyHex, path)
		require.NoError(t, err)
		require.Equal(t, wantAddr, ethcrypto.PubkeyToAddress(got.PublicKey),
			"hex string key must take priority over the file")
	})

	t.Run("errors when neither flag is set", func(t *testing.T) {
		_, err := loadECDSAKey("", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "required")
	})

	t.Run("errors on malformed hex", func(t *testing.T) {
		_, err := loadECDSAKey("not-valid-hex-zzzz", "")
		require.Error(t, err)
	})

	t.Run("errors when file does not exist", func(t *testing.T) {
		_, err := loadECDSAKey("", filepath.Join(t.TempDir(), "does-not-exist.hex"))
		require.Error(t, err)
	})
}

func TestWriteSecretFile(t *testing.T) {
	t.Run("creates new file with mode 0600", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secret.bin")

		require.NoError(t, writeSecretFile(path, []byte("hello")))

		fi, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), fi.Mode().Perm())

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, []byte("hello"), got)
	})

	t.Run("tightens permissions on pre-existing 0644 file", func(t *testing.T) {
		// This is the regression that os.WriteFile alone would miss:
		// os.WriteFile does not alter the mode of an existing file, so a
		// pre-existing 0644 file would keep 0644 after a secret write.
		path := filepath.Join(t.TempDir(), "secret.bin")
		require.NoError(t, os.WriteFile(path, []byte("stale"), 0644))
		fi, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0644), fi.Mode().Perm(), "pre-condition: file starts at 0644")

		require.NoError(t, writeSecretFile(path, []byte("fresh")))

		fi, err = os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), fi.Mode().Perm(), "mode must be tightened to 0600")

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, []byte("fresh"), got)
	})
}

func TestPrepareOutputPath(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	tests := []struct {
		name        string
		input       string
		wantErr     string // substring; empty means no error expected
		wantCleaned string // only checked when wantErr == ""
	}{
		{
			name:    "empty path is rejected",
			input:   "",
			wantErr: "output path is empty",
		},
		{
			name:    "trailing slash rejected as directory",
			input:   "output/",
			wantErr: "is a directory",
		},
		{
			name:    "root path rejected",
			input:   "/",
			wantErr: "is a directory",
		},
		{
			name:        "relative path is resolved to absolute",
			input:       "relative/path.bin",
			wantCleaned: filepath.Join(cwd, "relative", "path.bin"),
		},
		{
			name:        "valid absolute path returned as-is",
			input:       "/valid/abs/path.bin",
			wantCleaned: "/valid/abs/path.bin",
		},
		{
			name:        "absolute path is cleaned of redundant separators",
			input:       "/valid//abs/./path.bin",
			wantCleaned: "/valid/abs/path.bin",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := prepareOutputPath(tc.input)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.True(t, strings.Contains(err.Error(), tc.wantErr),
					"error %q should contain %q", err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantCleaned, got)
		})
	}
}
