package node

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestResolveCutoffL2_MapsL1DeadlineToL2Height(t *testing.T) {
	l, _ := zap.NewDevelopment()

	// L1 interval=10, buffer=2 (Anvil) => deadline = triggerBlock + (10-2) = trigger+8.
	// Stub: L1 deadline block's timestamp is 1_700_000_096; the first L2 block at/after
	// that timestamp is 5000.
	const triggerBlock = int64(100)
	interval := config.GetReshareBlockIntervalForChain(config.ChainId_EthereumAnvil)
	buffer := config.GetReshareCutoffBufferForChain(config.ChainId_EthereumAnvil)
	wantDeadline := uint64(triggerBlock) + uint64(interval-buffer)

	var gotDeadlineArg uint64
	stub := &contractCaller.MockContractCallerStub{
		HeaderTimestampAtFunc: func(ctx context.Context, blockNumber uint64) (uint64, error) {
			gotDeadlineArg = blockNumber
			return 1_700_000_096, nil
		},
		FirstBlockAtOrAfterTimestampFunc: func(ctx context.Context, ts uint64) (uint64, error) {
			if ts != 1_700_000_096 {
				t.Fatalf("expected target ts 1700000096, got %d", ts)
			}
			return 5000, nil
		},
	}

	n := &Node{
		logger:               l,
		ChainID:              config.ChainId_EthereumAnvil,
		platformConfigCaller: stub, // L1-bound caller (see Step 3 for selection)
		baseContractCaller:   stub,
	}

	got, err := n.resolveCutoffL2(context.Background(), triggerBlock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotDeadlineArg != wantDeadline {
		t.Fatalf("expected L1 timestamp lookup at deadline block %d, got %d", wantDeadline, gotDeadlineArg)
	}
	if got != 5000 {
		t.Fatalf("expected cutoffL2 = 5000, got %d", got)
	}
}

// makeAddrs returns n distinct, deterministic common.Address values for tests.
func makeAddrs(n int) []common.Address {
	addrs := make([]common.Address, n)
	for i := range addrs {
		addrs[i] = common.HexToAddress(fmt.Sprintf("0x%040x", i+1))
	}
	return addrs
}

// nodeWithCutoffCallers builds a minimal *Node wired with DISTINCT L1 (platformConfigCaller)
// and L2 (baseContractCaller) stubs, so a caller swap in deriveAgreedDealerSet/resolveCutoffL2
// (reading the L1 deadline header on the L2 caller, or vice-versa) is caught by the test.
// resolveCutoffL2 reads the L1 deadline block's header from platformConfigCaller and the L2
// cutoff height + per-dealer commitments from baseContractCaller.
func nodeWithCutoffCallers(t *testing.T, l *zap.Logger, l1, l2 *contractCaller.MockContractCallerStub) *Node {
	t.Helper()
	return &Node{
		logger:                    l,
		ChainID:                   config.ChainId_EthereumAnvil,
		OperatorAddress:           common.HexToAddress("0xabc"),
		commitmentRegistryAddress: common.HexToAddress("0x1111111111111111111111111111111111111111"),
		platformConfigCaller:      l1,
		baseContractCaller:        l2,
	}
}

func TestDeriveAgreedDealerSet_RetriesThenReadsAtPinnedHeight(t *testing.T) {
	l, _ := zap.NewDevelopment()
	dealers := makeAddrs(3)

	// L1 stub resolves the deadline block header timestamp; L2 stub maps it to cutoff 5000
	// and serves per-dealer commitments. Distinct instances so a caller swap is caught.
	l1 := &contractCaller.MockContractCallerStub{
		HeaderTimestampAtFunc: func(ctx context.Context, b uint64) (uint64, error) { return 1000, nil },
	}
	var readsAtCutoff int
	callsPerDealer := map[common.Address]int{}
	l2 := &contractCaller.MockContractCallerStub{
		FirstBlockAtOrAfterTimestampFunc: func(ctx context.Context, ts uint64) (uint64, error) {
			// The deadline-block timestamp MUST come from the L1 caller (l1 above). If the
			// code read the header on the L2 caller instead, l2's nil HeaderTimestampAtFunc
			// would return 0 and this assertion catches the caller swap.
			if ts != 1000 {
				t.Fatalf("expected L1 deadline timestamp 1000 from platformConfigCaller, got %d (caller swap?)", ts)
			}
			return 5000, nil
		},
		GetCommitmentAtFunc: func(ctx context.Context, reg common.Address, epoch int64, op common.Address, blk uint64) ([32]byte, [32]byte, uint64, error) {
			if blk != 5000 {
				t.Fatalf("expected read pinned at cutoffL2=5000, got %d", blk)
			}
			readsAtCutoff++
			callsPerDealer[op]++
			// First dealer's first read simulates this node's L2 view not-yet-synced,
			// then succeeds on retry.
			if op == dealers[0] && callsPerDealer[op] == 1 {
				return [32]byte{}, [32]byte{}, 0, fmt.Errorf("missing trie node")
			}
			var h [32]byte
			h[0] = 1 // non-zero => submitted
			return h, [32]byte{}, 0, nil
		},
	}
	n := nodeWithCutoffCallers(t, l, l1, l2)

	// Pass dealers explicitly as expectedDealers so the test doesn't depend on an active
	// version; the operators arg is only consulted for the nil-fallback.
	got, hashes, err := n.deriveAgreedDealerSet(context.Background(), nil, 12345, 100, dealers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected all 3 dealers, got %d", len(got))
	}
	if len(hashes) != 3 {
		t.Fatalf("expected 3 on-chain hashes, got %d", len(hashes))
	}
	if callsPerDealer[dealers[0]] != 2 {
		t.Fatalf("expected dealer[0] to be retried once (2 reads), got %d", callsPerDealer[dealers[0]])
	}
	if readsAtCutoff < 4 {
		t.Fatalf("expected all reads pinned at cutoff (>=4 incl. retry), got %d", readsAtCutoff)
	}
}

func TestDeriveAgreedDealerSet_AbortsWholeRoundOnPersistentReadFailure(t *testing.T) {
	l, _ := zap.NewDevelopment()
	dealers := makeAddrs(3)
	l1 := &contractCaller.MockContractCallerStub{
		HeaderTimestampAtFunc: func(ctx context.Context, b uint64) (uint64, error) { return 1000, nil },
	}
	l2 := &contractCaller.MockContractCallerStub{
		FirstBlockAtOrAfterTimestampFunc: func(ctx context.Context, ts uint64) (uint64, error) { return 5000, nil },
		GetCommitmentAtFunc: func(ctx context.Context, reg common.Address, epoch int64, op common.Address, blk uint64) ([32]byte, [32]byte, uint64, error) {
			if op == dealers[2] {
				return [32]byte{}, [32]byte{}, 0, fmt.Errorf("missing trie node") // never recovers
			}
			var h [32]byte
			h[0] = 1
			return h, [32]byte{}, 0, nil
		},
	}
	n := nodeWithCutoffCallers(t, l, l1, l2)
	// Cancel via ctx to bound the test quickly (the internal deadline is ~one interval,
	// which is far longer than a unit test should run).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, _, err := n.deriveAgreedDealerSet(ctx, nil, 12345, 100, dealers)
	if err == nil {
		t.Fatal("expected whole-round abort when a dealer read never succeeds, got nil error")
	}
	if got != nil {
		t.Fatalf("expected no partial dealer set on abort, got %d dealers", len(got))
	}
}

// TestNewOperatorPath_UsesTriggerBlockForCutoff asserts a joining node computes the same
// deterministic L2 cutoff as an existing node given the same trigger block. The join path
// (RunReshareAsNewOperator) threads the real trigger block into deriveAgreedDealerSet, which
// calls the identical resolveCutoffL2 helper exercised here — so cutoff parity between the
// join and existing paths is structural, not incidental.
func TestNewOperatorPath_UsesTriggerBlockForCutoff(t *testing.T) {
	l, _ := zap.NewDevelopment()
	var seenDeadlineBlock uint64
	stub := &contractCaller.MockContractCallerStub{
		HeaderTimestampAtFunc: func(ctx context.Context, b uint64) (uint64, error) {
			seenDeadlineBlock = b
			return 1000, nil
		},
		FirstBlockAtOrAfterTimestampFunc: func(ctx context.Context, ts uint64) (uint64, error) { return 5000, nil },
	}
	n := &Node{logger: l, ChainID: config.ChainId_EthereumAnvil, baseContractCaller: stub, platformConfigCaller: stub}

	got, err := n.resolveCutoffL2(context.Background(), 200)
	require.NoError(t, err)
	require.Equal(t, uint64(5000), got)
	interval := config.GetReshareBlockIntervalForChain(config.ChainId_EthereumAnvil)
	buffer := config.GetReshareCutoffBufferForChain(config.ChainId_EthereumAnvil)
	require.Equal(t, uint64(200+interval-buffer), seenDeadlineBlock)
}
