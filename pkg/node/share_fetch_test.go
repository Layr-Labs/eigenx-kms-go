package node

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// The on-demand share-fetch responder serves a share PER RECIPIENT from the dealer's
// retained generated shares. These tests lock the session-level accessor behavior that
// the /reshare/share/request handler relies on: it must return the share generated for
// a given recipient, and nothing for an unknown one.
func TestSession_GeneratedShareRetention(t *testing.T) {
	recipA := common.HexToAddress("0x01")
	recipB := common.HexToAddress("0x02")
	unknown := common.HexToAddress("0x03")

	shareA := new(fr.Element).SetUint64(111)
	shareB := new(fr.Element).SetUint64(222)

	s := &ProtocolSession{}
	s.SetMyGeneratedShares(map[common.Address]*fr.Element{
		recipA: shareA,
		recipB: shareB,
	})

	gotA := s.GetMyGeneratedShareFor(recipA)
	require.NotNil(t, gotA)
	require.True(t, gotA.Equal(shareA), "must return the share generated for recipient A")

	gotB := s.GetMyGeneratedShareFor(recipB)
	require.NotNil(t, gotB)
	require.True(t, gotB.Equal(shareB), "must return the share generated for recipient B")
	require.False(t, gotB.Equal(shareA), "recipients must get distinct shares")

	require.Nil(t, s.GetMyGeneratedShareFor(unknown),
		"must not fabricate a share for a recipient we never dealt to")
}

// A session with no generated shares (e.g. a node that did not act as dealer) must
// return nil rather than panic.
func TestSession_GeneratedShareNilBeforeSet(t *testing.T) {
	s := &ProtocolSession{}
	require.Nil(t, s.GetMyGeneratedShareFor(common.HexToAddress("0x01")))
}
