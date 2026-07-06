package node

import (
	"context"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type fakeCallerWithAvsConfig struct {
	contractCaller.MockContractCallerStub // embeds all no-op methods (incl. the Task 3 GetAvsConfig)
	cfg                                   *caller.AvsConfig
}

func (f *fakeCallerWithAvsConfig) GetAvsConfig(ctx context.Context, avsAddress string) (*caller.AvsConfig, error) {
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
