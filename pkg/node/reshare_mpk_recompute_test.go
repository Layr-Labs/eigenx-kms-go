package node

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"

	eigenxcrypto "github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// recomputeReshareMPK must equal Σ_{i∈dealers} λ_i(dealers)·C_i[0], and a
// different dealer set must yield a different MPK (the condition that triggers
// the self-heal log in reshare finalization).
func TestRecomputeReshareMPK(t *testing.T) {
	addr := func(b byte) common.Address { var a common.Address; a[19] = b; return a }
	d1, d2, d3 := addr(1), addr(2), addr(3)
	dealers := []common.Address{d1, d2, d3}

	// raw dealer commitments C_i[0] = c_i·G2 for random c_i
	coef := map[common.Address]*fr.Element{}
	session := &ProtocolSession{commitments: map[common.Address][]types.G2Point{}}
	for _, d := range dealers {
		c := new(fr.Element)
		if _, err := c.SetRandom(); err != nil {
			t.Fatal(err)
		}
		coef[d] = c
		pt, err := eigenxcrypto.ScalarMulG2(eigenxcrypto.G2Generator, c)
		if err != nil {
			t.Fatal(err)
		}
		session.commitments[d] = []types.G2Point{*pt}
	}

	n := &Node{}
	got, err := n.recomputeReshareMPK(session, dealers)
	if err != nil {
		t.Fatalf("recomputeReshareMPK: %v", err)
	}

	// expected = (Σ λ_i(D)·c_i)·G2
	expScalar := new(fr.Element).SetZero()
	for _, d := range dealers {
		lam := eigenxcrypto.ComputeLagrangeCoefficient(d, dealers)
		expScalar.Add(expScalar, new(fr.Element).Mul(lam, coef[d]))
	}
	exp, err := eigenxcrypto.ScalarMulG2(eigenxcrypto.G2Generator, expScalar)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsEqual(exp) {
		t.Fatalf("recomputeReshareMPK != Σλ_i(D)·C_i[0]")
	}

	// A different dealer set yields a different MPK (this divergence from a stale
	// stored MPK is what the reshare-finalize self-heal logs).
	got2, err := n.recomputeReshareMPK(session, []common.Address{d1, d2})
	if err != nil {
		t.Fatalf("recomputeReshareMPK(subset): %v", err)
	}
	if got2.IsEqual(got) {
		t.Fatalf("expected a different MPK for a different dealer set")
	}
}

// A missing commitment for a trusted dealer is a hard error (not a silent
// wrong MPK), so finalization fails loudly rather than persisting garbage.
func TestRecomputeReshareMPK_MissingCommitment(t *testing.T) {
	addr := func(b byte) common.Address { var a common.Address; a[19] = b; return a }
	d1, d2 := addr(1), addr(2)
	session := &ProtocolSession{commitments: map[common.Address][]types.G2Point{}}
	pt, _ := eigenxcrypto.ScalarMulG2(eigenxcrypto.G2Generator, new(fr.Element).SetOne())
	session.commitments[d1] = []types.G2Point{*pt} // d2 missing

	n := &Node{}
	if _, err := n.recomputeReshareMPK(session, []common.Address{d1, d2}); err == nil {
		t.Fatal("expected error for missing dealer commitment")
	}
}
