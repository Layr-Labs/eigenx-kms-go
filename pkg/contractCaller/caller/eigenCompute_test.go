package caller

import (
	"context"
	"testing"

	iappctl "github.com/Layr-Labs/eigenx-kms-go/pkg/middleware-bindings/IAppController"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"go.uber.org/zap"
)

// fakeAppController is a minimal AppControllerInterface implementation for unit-testing
// the release-resolution helpers. It returns canned block numbers and event iterators.
type fakeAppController struct {
	latestBlock  uint32
	pendingBlock uint32
	// eventsByStartBlock returns the event slice keyed by the FilterOpts.Start value, so a
	// test can configure different events for the latest and pending block lookups.
	eventsByStartBlock map[uint64][]*AppUpgradedEvent
}

func (f *fakeAppController) GetAppCreator(opts *bind.CallOpts, app common.Address) (common.Address, error) {
	return common.Address{}, nil
}

func (f *fakeAppController) GetAppOperatorSetId(opts *bind.CallOpts, app common.Address) (uint32, error) {
	return 0, nil
}

func (f *fakeAppController) GetAppLatestReleaseBlockNumber(opts *bind.CallOpts, app common.Address) (uint32, error) {
	return f.latestBlock, nil
}

func (f *fakeAppController) GetAppPendingReleaseBlockNumber(opts *bind.CallOpts, app common.Address) (uint32, error) {
	return f.pendingBlock, nil
}

func (f *fakeAppController) GetAppStatus(opts *bind.CallOpts, app common.Address) (uint8, error) {
	return 0, nil
}

func (f *fakeAppController) FilterAppUpgraded(opts *bind.FilterOpts, apps []common.Address) (AppUpgradedIterator, error) {
	events := f.eventsByStartBlock[opts.Start]
	return &fakeAppUpgradedIterator{events: events, idx: -1}, nil
}

type fakeAppUpgradedIterator struct {
	events []*AppUpgradedEvent
	idx    int
}

func (it *fakeAppUpgradedIterator) Next() bool {
	it.idx++
	return it.idx < len(it.events)
}

func (it *fakeAppUpgradedIterator) Event() *AppUpgradedEvent {
	return it.events[it.idx]
}

func (it *fakeAppUpgradedIterator) Error() error { return nil }
func (it *fakeAppUpgradedIterator) Close() error { return nil }

// makeUpgradedEvent constructs an AppUpgradedEvent with a single artifact carrying the
// given digest, an empty (but valid JSON) public env, and the supplied encrypted env bytes.
func makeUpgradedEvent(blockNumber uint64, digest [32]byte, encryptedEnv []byte) *AppUpgradedEvent {
	return &AppUpgradedEvent{
		Release: AppRelease{
			RmsRelease: RmsRelease{
				Artifacts: []Artifact{{Digest: digest}},
			},
			PublicEnv:    []byte("{}"),
			EncryptedEnv: encryptedEnv,
			ContainerPolicy: iappctl.IAppControllerContainerPolicy{
				EnvKeys:           []string{},
				EnvValues:         []string{},
				EnvOverrideKeys:   []string{},
				EnvOverrideValues: []string{},
			},
		},
		Raw: ethTypes.Log{BlockNumber: blockNumber, Index: 0},
	}
}

// TestResolveReleaseAtBlock_LookupSelectsCorrectBlock verifies that resolveReleaseAtBlock
// passes the requested block number through to FilterAppUpgraded and parses the returned
// release event into the expected (digest, encryptedEnv, …) tuple.
func TestResolveReleaseAtBlock_LookupSelectsCorrectBlock(t *testing.T) {
	digestA := [32]byte{0xAA}
	digestB := [32]byte{0xBB}

	fake := &fakeAppController{
		eventsByStartBlock: map[uint64][]*AppUpgradedEvent{
			100: {makeUpgradedEvent(100, digestA, []byte("env-A"))},
			200: {makeUpgradedEvent(200, digestB, []byte("env-B"))},
		},
	}

	cc := &ContractCaller{
		appController: fake,
		logger:        zap.NewNop(),
	}

	app := common.HexToAddress("0x000000000000000000000000000000000000dEaD").Hex()

	gotDigestA, _, gotEncA, _, gotBlockA, err := cc.resolveReleaseAtBlock(context.Background(), app, 100)
	if err != nil {
		t.Fatalf("resolveReleaseAtBlock(100) error: %v", err)
	}
	if gotDigestA != digestA {
		t.Errorf("expected digestA, got %x", gotDigestA)
	}
	if string(gotEncA) != "env-A" {
		t.Errorf("expected env-A, got %s", string(gotEncA))
	}
	if gotBlockA != 100 {
		t.Errorf("expected block 100, got %d", gotBlockA)
	}

	gotDigestB, _, gotEncB, _, gotBlockB, err := cc.resolveReleaseAtBlock(context.Background(), app, 200)
	if err != nil {
		t.Fatalf("resolveReleaseAtBlock(200) error: %v", err)
	}
	if gotDigestB != digestB {
		t.Errorf("expected digestB, got %x", gotDigestB)
	}
	if string(gotEncB) != "env-B" {
		t.Errorf("expected env-B, got %s", string(gotEncB))
	}
	if gotBlockB != 200 {
		t.Errorf("expected block 200, got %d", gotBlockB)
	}
}

// TestResolveReleaseAtBlock_NoEvent surfaces an error when no AppUpgraded event exists
// at the requested block (e.g. lookup of a non-existent pending release).
func TestResolveReleaseAtBlock_NoEvent(t *testing.T) {
	fake := &fakeAppController{
		eventsByStartBlock: map[uint64][]*AppUpgradedEvent{
			// no entry for block 42 — iterator will return immediately
		},
	}
	cc := &ContractCaller{appController: fake, logger: zap.NewNop()}

	_, _, _, _, _, err := cc.resolveReleaseAtBlock(context.Background(), common.Address{}.Hex(), 42)
	if err == nil {
		t.Fatal("expected error for missing AppUpgraded event, got nil")
	}
}

// TestGetAppPendingReleaseBlockNumber_PassThrough verifies the wrapper forwards the call
// to the AppController binding.
func TestGetAppPendingReleaseBlockNumber_PassThrough(t *testing.T) {
	fake := &fakeAppController{pendingBlock: 777}
	cc := &ContractCaller{appController: fake, logger: zap.NewNop()}

	got, err := cc.GetAppPendingReleaseBlockNumber(common.Address{}, &bind.CallOpts{})
	if err != nil {
		t.Fatalf("GetAppPendingReleaseBlockNumber error: %v", err)
	}
	if got != 777 {
		t.Errorf("expected 777, got %d", got)
	}
}
