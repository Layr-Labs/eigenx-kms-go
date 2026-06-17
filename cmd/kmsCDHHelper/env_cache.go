package main

// Per-app environment assembly + a per-pod-boot cache.
//
// The eigenx CDH plugin calls this helper once per sealed env var in the pod
// spec. Each invocation is a fresh process, so to keep attestation to ONE round
// trip per pod (not one per env var) the first call caches the whole merged
// environment to a tmpfs file and every later call for the same app serves its
// requested key straight from that cache.
//
// The cache holds plaintext secrets at rest, so it MUST live on memory-backed
// tmpfs inside the SEV-SNP guest (never the disk image), with owner-only perms.
// /run is tmpfs in the podVM. The file is scoped per app_id and naturally
// cleared on pod restart (tmpfs is volatile), giving per-boot freshness.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// envCacheDir is on tmpfs (/run) so cached plaintext never lands on the
// persistent disk image and is wiped on every pod boot. It is a var (not a
// const) only so tests can redirect it via setEnvCacheDir; production never
// changes it.
var envCacheDir = "/run/eigenx"

// setEnvCacheDir redirects the cache location (tests only).
func setEnvCacheDir(dir string) { envCacheDir = dir }

// cacheFileMode / cacheDirMode keep the plaintext cache readable only by the
// helper's uid (it runs as root in the guest; nothing else should read it).
const (
	cacheFileMode os.FileMode = 0o600
	cacheDirMode  os.FileMode = 0o700
)

// mergeEnv overlays the decrypted secret env on top of the release's public
// env. Both are JSON objects of string→string. public_env is plaintext config
// from the on-chain release; secretPlaintext is the IBE-decrypted encrypted_env.
// Secret keys win on collision so a public default can never shadow a secret.
//
// Either side may be empty. publicEnvJSON is "" when the release pins no public
// env; secretPlaintext is empty when the release has no encrypted_env (a
// public-only release). A release with neither yields an empty map. When
// present, each side must be a JSON object: the env is a flat key→value map,
// which is what lets CDH address individual variables by name.
func mergeEnv(publicEnvJSON string, secretPlaintext []byte) (map[string]string, error) {
	env := map[string]string{}

	if strings.TrimSpace(publicEnvJSON) != "" {
		var pub map[string]string
		if err := json.Unmarshal([]byte(publicEnvJSON), &pub); err != nil {
			return nil, fmt.Errorf("public_env is not a JSON string map: %w", err)
		}
		for k, v := range pub {
			env[k] = v
		}
	}

	if len(secretPlaintext) > 0 {
		var sec map[string]string
		if err := json.Unmarshal(secretPlaintext, &sec); err != nil {
			return nil, fmt.Errorf("decrypted encrypted_env is not a JSON string map: %w", err)
		}
		for k, v := range sec { // secret overrides public
			env[k] = v
		}
	}

	return env, nil
}

// emitKey writes the value for key to stdout (the unseal_secret return that
// kata-agent substitutes into the one sealed env var that triggered this call).
// A missing key is a hard error: the deployer listed a sealed env var whose
// name isn't in the release env, which is a misconfiguration, not an empty
// secret — failing loud beats silently injecting "".
func emitKey(env map[string]string, key string) error {
	val, ok := env[key]
	if !ok {
		return fmt.Errorf("key %q not present in app env (release has %d keys)", key, len(env))
	}
	if _, err := os.Stdout.Write([]byte(val)); err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	return nil
}

func cachePath(appID string) string {
	// app_id is an Ethereum address (0x + 40 hex) in production and a short
	// slug under fakeKMS; both are filesystem-safe. Sanitize anyway so a
	// surprising app_id can't escape envCacheDir via path separators.
	safe := strings.NewReplacer("/", "_", "..", "_", string(os.PathSeparator), "_").Replace(appID)
	return filepath.Join(envCacheDir, safe+".json")
}

// loadCachedEnv returns the cached merged env for appID if a prior call this
// pod boot already fetched it. ok=false (nil error) means cache miss — the
// caller should attest + fetch. A shared (read) flock is held across the read
// so a concurrent first-call writer can't be observed mid-write.
func loadCachedEnv(appID string) (env map[string]string, ok bool, err error) {
	f, err := os.Open(cachePath(appID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer func() { _ = f.Close() }()

	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH); err != nil {
		return nil, false, fmt.Errorf("flock(shared): %w", err)
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()

	dec := json.NewDecoder(f)
	if err := dec.Decode(&env); err != nil {
		// A corrupt/partial cache file shouldn't wedge the pod forever: treat
		// it as a miss so the caller re-fetches and overwrites it.
		return nil, false, nil
	}
	return env, true, nil
}

// storeCachedEnv writes the merged env to the per-app tmpfs cache atomically
// (temp file + rename) under an exclusive flock, so a reader either sees the
// old file or the fully-written new one, never a partial write.
func storeCachedEnv(appID string, env map[string]string) error {
	if err := os.MkdirAll(envCacheDir, cacheDirMode); err != nil {
		return fmt.Errorf("mkdir %s: %w", envCacheDir, err)
	}

	final := cachePath(appID)

	// Serialize writers on a lock file co-located with the target. We lock a
	// dedicated .lock (not the target) so the atomic rename below can't swap
	// the inode out from under a held descriptor.
	lock, err := os.OpenFile(final+".lock", os.O_CREATE|os.O_RDWR, cacheFileMode)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("flock(exclusive): %w", err)
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()

	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal env: %w", err)
	}

	tmp, err := os.CreateTemp(envCacheDir, ".env-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename

	if err := tmp.Chmod(cacheFileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("rename temp into place: %w", err)
	}
	return nil
}
