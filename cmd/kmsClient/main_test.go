package main

import (
	"os"
	"path/filepath"
	"strings"
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
