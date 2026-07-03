package node

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// GetCommitmentsFor feeds each dealer's C_d[0] into ValidateReshareMasterPublicKey
// (Layer 1). A regression here (wrong dealer's commitments, a nil slice for a present
// dealer, or aliasing back into session state) would silently weaken the MPK check, so
// lock its contract directly. (bot review round 2.)
func TestSession_GetCommitmentsFor(t *testing.T) {
	dealerA := common.HexToAddress("0x0A")
	dealerB := common.HexToAddress("0x0B")

	commA := []types.G2Point{{CompressedBytes: []byte{1, 2, 3}}, {CompressedBytes: []byte{4}}}
	commB := []types.G2Point{{CompressedBytes: []byte{9, 9}}}

	s := &ProtocolSession{
		commitments: map[common.Address][]types.G2Point{
			dealerA: commA,
			dealerB: commB,
		},
	}

	gotA := s.GetCommitmentsFor(dealerA)
	require.Len(t, gotA, 2, "must return dealer A's own commitments")
	require.Equal(t, []byte{1, 2, 3}, gotA[0].CompressedBytes)

	gotB := s.GetCommitmentsFor(dealerB)
	require.Len(t, gotB, 1, "distinct dealers must get distinct commitments")

	require.Nil(t, s.GetCommitmentsFor(common.HexToAddress("0xFF")),
		"must return nil for a dealer with no commitments (not another dealer's)")

	// The returned slice is a copy: reassigning an element must not mutate session state.
	gotA[0] = types.G2Point{CompressedBytes: []byte{0xFF}}
	again := s.GetCommitmentsFor(dealerA)
	require.Equal(t, []byte{1, 2, 3}, again[0].CompressedBytes,
		"returned slice must be a copy; caller element reassignment must not alias into session state")

	// Deep copy: an IN-PLACE byte mutation of the returned commitment must also not corrupt
	// session state (a shallow copy would share the CompressedBytes backing array).
	again[0].CompressedBytes[0] = 0xFF
	afterInPlace := s.GetCommitmentsFor(dealerA)
	require.Equal(t, []byte{1, 2, 3}, afterInPlace[0].CompressedBytes,
		"returned commitments must be deep-copied; in-place byte mutation must not alias into session state")
}

// Layer 3a (docs/012): a dealer must be able to serve the share it generated for a peer
// even AFTER its own session has been torn down on round completion. In the live incident
// the dealer finished the round and deleted its session, so a lagging peer's on-demand
// fetch got a 503, the peer aborted and fell a version behind, and the next round
// corrupted the master secret. Retaining generated shares at the node level (bounded)
// past session teardown closes that trigger.
func TestNode_RetainedGeneratedShares_SurviveSessionTeardown(t *testing.T) {
	n := makeNodeForValidation(t, 3)

	recipient := common.HexToAddress("0x02")
	share := new(fr.Element).SetUint64(4242)

	n.retainGeneratedShares(1_700_000_100, map[common.Address]*fr.Element{recipient: share})

	got := n.getRetainedGeneratedShare(1_700_000_100, recipient)
	require.NotNil(t, got, "retained share must survive independently of any live session")
	require.True(t, got.Equal(share))

	require.Nil(t, n.getRetainedGeneratedShare(1_700_000_100, common.HexToAddress("0xAA")),
		"must not fabricate a share for a recipient we never dealt to")
	require.Nil(t, n.getRetainedGeneratedShare(999, recipient),
		"must not return a share for an unknown session")
}

// Retention is bounded: only the most recent K rounds are kept, so the store cannot grow
// without bound across the ~2-minute reshare cadence. The oldest round is evicted first.
func TestNode_RetainedGeneratedShares_BoundedEviction(t *testing.T) {
	n := makeNodeForValidation(t, 3)
	recipient := common.HexToAddress("0x02")

	// Insert more than the retention bound; oldest sessions must be evicted.
	base := int64(1_700_000_000)
	total := retainedShareRounds + 2
	for i := 0; i < total; i++ {
		ts := base + int64(i)
		n.retainGeneratedShares(ts, map[common.Address]*fr.Element{
			recipient: new(fr.Element).SetUint64(uint64(ts)),
		})
	}

	// The two oldest are gone.
	require.Nil(t, n.getRetainedGeneratedShare(base+0, recipient), "oldest round must be evicted")
	require.Nil(t, n.getRetainedGeneratedShare(base+1, recipient), "second-oldest round must be evicted")

	// The most recent retainedShareRounds are still present.
	for i := 2; i < total; i++ {
		ts := base + int64(i)
		got := n.getRetainedGeneratedShare(ts, recipient)
		require.NotNilf(t, got, "recent round %d must be retained", ts)
		require.True(t, got.Equal(new(fr.Element).SetUint64(uint64(ts))))
	}
}

// The retained store must return a copy so a caller cannot mutate stored key material.
func TestNode_RetainedGeneratedShares_ReturnsCopy(t *testing.T) {
	n := makeNodeForValidation(t, 3)
	recipient := common.HexToAddress("0x02")
	n.retainGeneratedShares(1_700_000_100, map[common.Address]*fr.Element{
		recipient: new(fr.Element).SetUint64(4242),
	})

	got := n.getRetainedGeneratedShare(1_700_000_100, recipient)
	require.NotNil(t, got)
	got.SetUint64(1)

	again := n.getRetainedGeneratedShare(1_700_000_100, recipient)
	require.NotNil(t, again)
	require.True(t, again.Equal(new(fr.Element).SetUint64(4242)),
		"stored share must not be mutable through the returned element")
}
