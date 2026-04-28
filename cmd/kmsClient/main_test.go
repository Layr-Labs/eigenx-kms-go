package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

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
