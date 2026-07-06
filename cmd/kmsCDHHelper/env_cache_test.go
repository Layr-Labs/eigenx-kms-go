package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
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

func TestCacheable_AppPrivateKeyNeverCached(t *testing.T) {
	// The root key must bypass the tmpfs env cache entirely (never read, never
	// written); any other key is cacheable. This is the invariant both cache
	// sites in run() gate on.
	assert.False(t, cacheable(appPrivateKeyKey), "app_private_key root must never be cached")
	assert.True(t, cacheable("DB_PASSWORD"), "ordinary env keys are cacheable")
	assert.True(t, cacheable("API_KEY"), "ordinary env keys are cacheable")
}

func TestEmitAppPrivateKey_RefusesUnverified(t *testing.T) {
	// The root key must never be emitted on the degraded (unverified) recovery
	// path, even when the bytes have a valid length.
	result := &kmsClient.SecretsResult{
		AppPrivateKey: types.G1Point{CompressedBytes: make([]byte, appPrivateKeyG1Bytes)},
		Verified:      false,
	}
	_, err := emitAppPrivateKey(result, "0xapp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not verified")
}

func TestEmitAppPrivateKey_RejectsWrongLength(t *testing.T) {
	// A verified result whose key isn't a 48-byte compressed G1 point is
	// malformed and must be rejected rather than emitted. Covers the empty case.
	for _, n := range []int{0, 32, 47, 49} {
		result := &kmsClient.SecretsResult{
			AppPrivateKey: types.G1Point{CompressedBytes: make([]byte, n)},
			Verified:      true,
		}
		_, err := emitAppPrivateKey(result, "0xapp")
		require.Errorf(t, err, "expected error for %d-byte key", n)
		assert.Contains(t, err.Error(), "want 48")
	}
}

func TestEmitAppPrivateKey_EmitsVerified48Byte(t *testing.T) {
	raw := make([]byte, appPrivateKeyG1Bytes)
	for i := range raw {
		raw[i] = byte(i)
	}
	result := &kmsClient.SecretsResult{
		AppPrivateKey: types.G1Point{CompressedBytes: raw},
		Verified:      true,
	}
	out, err := emitAppPrivateKey(result, "0xapp")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{appPrivateKeyKey: hex.EncodeToString(raw)}, out)
	assert.False(t, strings.Contains(out[appPrivateKeyKey], " "), "hex must be bare")
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
