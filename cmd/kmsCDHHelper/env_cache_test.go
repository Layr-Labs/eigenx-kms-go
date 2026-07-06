package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeEnv_SecretWinsOverPublic(t *testing.T) {
	public := `{"LOG_LEVEL":"info","SHARED":"public-value"}`
	secret := []byte(`{"DB_PASSWORD":"hunter2","SHARED":"secret-value"}`)

	env, err := mergeEnv(public, secret)
	require.NoError(t, err)

	assert.Equal(t, "info", env["LOG_LEVEL"], "public-only key preserved")
	assert.Equal(t, "hunter2", env["DB_PASSWORD"], "secret-only key preserved")
	assert.Equal(t, "secret-value", env["SHARED"], "secret must override public on collision")
	assert.Len(t, env, 3)
}

func TestMergeEnv_EmptyPublic(t *testing.T) {
	env, err := mergeEnv("", []byte(`{"A":"1","B":"2"}`))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"A": "1", "B": "2"}, env)
}

func TestMergeEnv_PublicOnly_EmptySecret(t *testing.T) {
	// A public-only release (no encrypted_env) passes an empty secretPlaintext.
	// The public env must come through and there must be no JSON-parse error.
	env, err := mergeEnv(`{"LOG_LEVEL":"info","ENVIRONMENT":"prod"}`, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"LOG_LEVEL": "info", "ENVIRONMENT": "prod"}, env)

	env, err = mergeEnv(`{"LOG_LEVEL":"info"}`, []byte{})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"LOG_LEVEL": "info"}, env)
}

func TestMergeEnv_BothEmpty(t *testing.T) {
	env, err := mergeEnv("", nil)
	require.NoError(t, err)
	assert.Empty(t, env)
}

func TestMergeEnv_RejectsNonObjectSecret(t *testing.T) {
	// A bare string (the old single-secret shape) is no longer valid — the
	// decrypted blob must be a JSON object so keys are addressable.
	_, err := mergeEnv("", []byte(`"just-a-string"`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JSON string map")
}

func TestMergeEnv_RejectsBadPublic(t *testing.T) {
	_, err := mergeEnv(`{not json}`, []byte(`{"A":"1"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public_env")
}

func TestEmitKey_MissingKeyFailsLoud(t *testing.T) {
	// A pod-spec sealed var whose name isn't in the release env is a
	// misconfiguration; emitKey must error rather than inject "".
	err := emitKey(map[string]string{"A": "1"}, "NOPE")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not present in app env")
}

func TestEmitKey_AppPrivateKeySentinel(t *testing.T) {
	// The root-key request path returns a one-entry map keyed by the sentinel
	// (see retrieveAndDecrypt); emitKey must serve it like any other key so the
	// app_private_key hex reaches stdout unchanged.
	rootHex := "852555c344147396974349e16f65c08dbf11b0d109e9df97afe2cfd41a84c5f34572a80bcb3053ac0ebec1693e539274"

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	err := emitKey(map[string]string{appPrivateKeyKey: rootHex}, appPrivateKeyKey)
	w.Close()
	os.Stdout = old
	require.NoError(t, err)

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	assert.Equal(t, rootHex, buf.String())
}

func TestCacheRoundTrip(t *testing.T) {
	// Point the cache at a temp dir so the test doesn't touch /run/eigenx.
	orig := envCacheDir
	tmp := t.TempDir()
	setEnvCacheDir(tmp)
	defer setEnvCacheDir(orig)

	appID := "0xabc123app"
	want := map[string]string{"DB_PASSWORD": "hunter2", "API_KEY": "sk-xyz"}

	// Miss before any write.
	_, ok, err := loadCachedEnv(appID)
	require.NoError(t, err)
	assert.False(t, ok, "expected cache miss before store")

	require.NoError(t, storeCachedEnv(appID, want))

	got, ok, err := loadCachedEnv(appID)
	require.NoError(t, err)
	require.True(t, ok, "expected cache hit after store")
	assert.Equal(t, want, got)

	// File is owner-only on tmpfs.
	info, err := os.Stat(filepath.Join(tmp, "0xabc123app.json"))
	require.NoError(t, err)
	assert.Equal(t, cacheFileMode, info.Mode().Perm())
}

func TestCachePath_SanitizesAppID(t *testing.T) {
	orig := envCacheDir
	setEnvCacheDir("/run/eigenx")
	defer setEnvCacheDir(orig)

	// A path-separator in app_id must not escape the cache dir.
	p := cachePath("../../etc/evil")
	assert.True(t, filepath.Dir(p) == "/run/eigenx", "cache path must stay in envCacheDir, got %s", p)
}
