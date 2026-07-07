package node

import (
	"context"
	"errors"
	"testing"

	chainPoller "github.com/Layr-Labs/chain-indexer/pkg/chainPollers"
	"github.com/Layr-Labs/chain-indexer/pkg/transactionLogParser/log"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/registrarabi"
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

// TestRefreshPlatformConfig_EmptyURLClearsCache verifies that an empty URL fetched
// from chain clears the previously-cached target (fails closed rather than dialing a
// stale endpoint).
func TestRefreshPlatformConfig_EmptyURLClearsCache(t *testing.T) {
	fake := &fakeCallerWithAvsConfig{cfg: &caller.AvsConfig{PlatformRpcUrl: "p.example:9002"}}
	n := &Node{baseContractCaller: fake, AVSAddress: "0xavs", logger: zap.NewNop()}

	// Seed a non-empty URL via a good refresh.
	n.refreshPlatformConfig(context.Background())
	require.Equal(t, "p.example:9002", n.PlatformRpcURL())

	// Chain now reports an empty URL; the refresh must clear the cache.
	fake.cfg = &caller.AvsConfig{PlatformRpcUrl: ""}
	n.refreshPlatformConfig(context.Background())
	require.Equal(t, "", n.PlatformRpcURL())
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

// logWithURL builds an AvsConfigSet LogWithBlock carrying the given platformRpcUrl.
func logWithURL(url string) *chainPoller.LogWithBlock {
	return &chainPoller.LogWithBlock{
		Log: &log.DecodedLog{
			EventName:  registrarabi.AvsConfigSetEventName,
			OutputData: map[string]interface{}{"platformRpcUrl": url},
		},
	}
}

func TestHandlePlatformConfigLog(t *testing.T) {
	tests := []struct {
		name    string
		seed    string // pre-seeded cached URL
		lwb     *chainPoller.LogWithBlock
		wantURL string
	}{
		{
			name:    "valid url updates cache",
			seed:    "",
			lwb:     logWithURL("p.example:9002"),
			wantURL: "p.example:9002",
		},
		{
			name:    "valid url replaces existing",
			seed:    "old.example:9002",
			lwb:     logWithURL("new.example:9002"),
			wantURL: "new.example:9002",
		},
		{
			name:    "nil LogWithBlock ignored",
			seed:    "keep.example:9002",
			lwb:     nil,
			wantURL: "keep.example:9002",
		},
		{
			name:    "nil inner log ignored",
			seed:    "keep.example:9002",
			lwb:     &chainPoller.LogWithBlock{Log: nil},
			wantURL: "keep.example:9002",
		},
		{
			name: "non-AvsConfigSet event ignored",
			seed: "keep.example:9002",
			lwb: &chainPoller.LogWithBlock{Log: &log.DecodedLog{
				EventName:  "SomethingElse",
				OutputData: map[string]interface{}{"platformRpcUrl": "evil.example:9002"},
			}},
			wantURL: "keep.example:9002",
		},
		{
			name: "missing platformRpcUrl key ignored",
			seed: "keep.example:9002",
			lwb: &chainPoller.LogWithBlock{Log: &log.DecodedLog{
				EventName:  registrarabi.AvsConfigSetEventName,
				OutputData: map[string]interface{}{"operatorSetId": uint32(0)},
			}},
			wantURL: "keep.example:9002",
		},
		{
			name: "non-string platformRpcUrl ignored",
			seed: "keep.example:9002",
			lwb: &chainPoller.LogWithBlock{Log: &log.DecodedLog{
				EventName:  registrarabi.AvsConfigSetEventName,
				OutputData: map[string]interface{}{"platformRpcUrl": 42},
			}},
			wantURL: "keep.example:9002",
		},
		{
			name:    "unsafe file url ignored",
			seed:    "keep.example:9002",
			lwb:     logWithURL("file:///etc/passwd"),
			wantURL: "keep.example:9002",
		},
		{
			name:    "unsafe unix url ignored",
			seed:    "keep.example:9002",
			lwb:     logWithURL("unix:/var/run/docker.sock"),
			wantURL: "keep.example:9002",
		},
		{
			name:    "whitespace trimmed",
			seed:    "",
			lwb:     logWithURL("  p.example:9002  "),
			wantURL: "p.example:9002",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := &Node{logger: zap.NewNop()}
			if tc.seed != "" {
				n.platformURL.Store(tc.seed)
			}
			n.handlePlatformConfigLog(tc.lwb)
			require.Equal(t, tc.wantURL, n.PlatformRpcURL())
		})
	}
}

// TestIsSafePlatformURL directly exercises the scheme classifier, including both
// unix: forms (single-colon grpc-go target and unix:// URL) which must be rejected.
func TestIsSafePlatformURL(t *testing.T) {
	rejected := []string{
		"",
		"file:///etc/passwd",
		"unix:/x",
		"unix:///x",
		"unix://x",
		"unix-abstract://x",
		"http://example.com",
		"https://example.com",
		"passthrough:///x",
		"dns:///nohostport",
		"[::1]", // bracketed IPv6 without a port has no host:port form
	}
	for _, u := range rejected {
		require.False(t, isSafePlatformURL(u), "expected %q to be rejected", u)
	}

	accepted := []string{
		"p.example:9002",
		"dns:///p.example:9002",
		"dns:///x:9002",
		"dns://authority/x:9002",
		"[::1]:9002", // bracketed IPv6 host:port (net.SplitHostPort handles it)
	}
	for _, u := range accepted {
		require.True(t, isSafePlatformURL(u), "expected %q to be accepted", u)
	}
}
