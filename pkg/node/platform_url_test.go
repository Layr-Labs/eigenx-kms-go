package node

import (
	"context"
	"errors"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type fakeCallerWithAvsConfig struct {
	contractCaller.MockContractCallerStub // embeds all no-op methods (incl. the Task 3 GetAvsConfig)
	cfg                                   *caller.AvsConfig
	err                                   error
}

func (f *fakeCallerWithAvsConfig) GetAvsConfig(ctx context.Context, avsAddress string) (*caller.AvsConfig, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.cfg, nil
}

func TestRefreshPlatformConfig_UpdatesCache(t *testing.T) {
	fake := &fakeCallerWithAvsConfig{cfg: &caller.AvsConfig{PlatformRpcUrl: "p.example:9002"}}
	n := &Node{baseContractCaller: fake, AVSAddress: "0xavs", logger: zap.NewNop()}
	require.Equal(t, "", n.PlatformRpcURL())
	n.refreshPlatformConfig(context.Background())
	require.Equal(t, "p.example:9002", n.PlatformRpcURL())

	fake.cfg = &caller.AvsConfig{PlatformRpcUrl: "q.example:9002"}
	n.refreshPlatformConfig(context.Background())
	require.Equal(t, "q.example:9002", n.PlatformRpcURL())
}

// TestRefreshPlatformConfig_ErrorLeavesCache verifies that a failed GetAvsConfig
// read leaves the previously-cached URL intact (it must not clear the cache).
func TestRefreshPlatformConfig_ErrorLeavesCache(t *testing.T) {
	fake := &fakeCallerWithAvsConfig{cfg: &caller.AvsConfig{PlatformRpcUrl: "p.example:9002"}}
	n := &Node{baseContractCaller: fake, AVSAddress: "0xavs", logger: zap.NewNop()}
	n.refreshPlatformConfig(context.Background())
	require.Equal(t, "p.example:9002", n.PlatformRpcURL())

	// Flip the fake to return an error; the cache must retain the prior URL.
	fake.err = errors.New("boom")
	n.refreshPlatformConfig(context.Background())
	require.Equal(t, "p.example:9002", n.PlatformRpcURL())
}

// TestRefreshPlatformConfig_UnsafeURLIgnored verifies that a fetched URL with a
// dangerous scheme (e.g. file://, or the grpc-go single-colon unix:path form) is
// ignored and the cached value is unchanged.
func TestRefreshPlatformConfig_UnsafeURLIgnored(t *testing.T) {
	unsafeURLs := []string{
		"file:///etc/passwd",
		// grpc-go single-colon unix target (no //) — must also be blocked.
		"unix:/var/run/docker.sock",
		"unix:///var/run/docker.sock",
	}
	for _, unsafe := range unsafeURLs {
		t.Run(unsafe, func(t *testing.T) {
			fake := &fakeCallerWithAvsConfig{cfg: &caller.AvsConfig{PlatformRpcUrl: "p.example:9002"}}
			n := &Node{baseContractCaller: fake, AVSAddress: "0xavs", logger: zap.NewNop()}
			n.refreshPlatformConfig(context.Background())
			require.Equal(t, "p.example:9002", n.PlatformRpcURL())

			// A dangerous scheme must be rejected, leaving the good cached URL in place.
			fake.cfg = &caller.AvsConfig{PlatformRpcUrl: unsafe}
			n.refreshPlatformConfig(context.Background())
			require.Equal(t, "p.example:9002", n.PlatformRpcURL())
		})
	}
}

// TestIsSafePlatformURL directly exercises the scheme classifier, including both
// unix: forms (single-colon grpc-go target and unix:// URL) which must be rejected.
func TestIsSafePlatformURL(t *testing.T) {
	rejected := []string{
		"file:///etc/passwd",
		"unix:/x",
		"unix:///x",
		"unix://x",
		"unix-abstract://x",
		"http://example.com",
		"https://example.com",
	}
	for _, u := range rejected {
		require.False(t, isSafePlatformURL(u), "expected %q to be rejected", u)
	}

	accepted := []string{
		"p.example:9002",
		"dns:///p.example:9002",
	}
	for _, u := range accepted {
		require.True(t, isSafePlatformURL(u), "expected %q to be accepted", u)
	}
}
