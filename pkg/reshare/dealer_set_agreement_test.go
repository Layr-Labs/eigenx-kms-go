package reshare

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
	"github.com/ethereum/go-ethereum/common"
)

// This test documents and guards the core correctness invariant behind the
// reshare-finalize fix: operators MUST finalize on the same dealer set, otherwise
// their refreshed shares become mutually inconsistent and decryption breaks for every
// app ("all combinations exhausted"). It reproduces the bug at the crypto layer using
// the real ComputeNewKeyShare, then shows the uniform-dealer-set path stays consistent.
//
// Models the live 3-operator preprod cluster: n=3, threshold=2.

func runRoundWithDealerSets(
	t *testing.T,
	ops []*peering.OperatorSetPeer,
	currentShares map[common.Address]*fr.Element,
	threshold int,
	dealerSetOf map[common.Address][]common.Address,
) map[common.Address]*fr.Element {
	t.Helper()

	// Every operator deals its current share to all recipients.
	sharesByDealer := map[common.Address]map[common.Address]*fr.Element{}
	for _, d := range ops {
		r := NewReshare(d.OperatorAddress, ops)
		per, _, err := r.GenerateNewShares(currentShares[d.OperatorAddress], threshold)
		if err != nil {
			t.Fatalf("GenerateNewShares(%s): %v", d.OperatorAddress.Hex(), err)
		}
		sharesByDealer[d.OperatorAddress] = per
	}

	// Each recipient finalizes using the dealer set it was given.
	newShares := map[common.Address]*fr.Element{}
	for _, recip := range ops {
		dealers := dealerSetOf[recip.OperatorAddress]
		received := map[common.Address]*fr.Element{}
		for _, d := range dealers {
			received[d] = sharesByDealer[d][recip.OperatorAddress]
		}
		r := NewReshare(recip.OperatorAddress, ops)
		kv, err := r.ComputeNewKeyShare(dealers, received, nil)
		if err != nil {
			t.Fatalf("ComputeNewKeyShare(%s): %v", recip.OperatorAddress.Hex(), err)
		}
		newShares[recip.OperatorAddress] = kv.PrivateShare
	}
	return newShares
}

// recoversConsistentKey reports whether all threshold-sized subsets of newShares
// recover the SAME secret (i.e. the shares lie on one polynomial). If they don't,
// threshold recovery is broken and decryption would fail for every app.
func recoversConsistentKey(t *testing.T, newShares map[common.Address]*fr.Element, members []common.Address) (bool, *fr.Element) {
	t.Helper()
	subsets := [][]common.Address{
		{members[0], members[1]},
		{members[0], members[2]},
		{members[1], members[2]},
	}
	var first *fr.Element
	for _, sub := range subsets {
		rec := map[common.Address]*fr.Element{sub[0]: newShares[sub[0]], sub[1]: newShares[sub[1]]}
		got, err := crypto.RecoverSecret(rec)
		if err != nil {
			t.Fatalf("RecoverSecret: %v", err)
		}
		if first == nil {
			first = got
		} else if !got.Equal(first) {
			return false, nil
		}
	}
	return true, first
}

func setupThreeOpSharing(t *testing.T) ([]*peering.OperatorSetPeer, map[common.Address]*fr.Element, *fr.Element, int) {
	t.Helper()
	ops := createTestOperators(t, 3)
	threshold := 2
	S := new(fr.Element).SetUint64(987654321)
	poly := make(polynomial.Polynomial, threshold)
	poly[0].Set(S)
	if _, err := poly[1].SetRandom(); err != nil {
		t.Fatal(err)
	}
	cur := map[common.Address]*fr.Element{}
	for _, op := range ops {
		cur[op.OperatorAddress] = crypto.EvaluatePolynomial(poly, op.OperatorAddress)
	}
	return ops, cur, S, threshold
}

// TestMixedDealerSetsBreakConsistency reproduces the production bug: when operators
// finalize on DIFFERENT dealer sets in the same round, their refreshed shares become
// mutually inconsistent.
func TestMixedDealerSetsBreakConsistency(t *testing.T) {
	ops, cur, _, threshold := setupThreeOpSharing(t)
	A, B, C := ops[0].OperatorAddress, ops[1].OperatorAddress, ops[2].OperatorAddress
	members := []common.Address{A, B, C}

	// The realistic "one straggler" partition: B and C see all 3 dealers, but A was
	// briefly partitioned and finalizes missing dealer C.
	mixed := map[common.Address][]common.Address{
		A: {A, B},    // partitioned: missed C
		B: {A, B, C}, // full
		C: {A, B, C}, // full
	}
	newShares := runRoundWithDealerSets(t, ops, cur, threshold, mixed)

	consistent, _ := recoversConsistentKey(t, newShares, members)
	if consistent {
		t.Fatal("expected mixed dealer sets to BREAK share consistency, but shares were consistent " +
			"— the bug this fix targets did not reproduce; revisit the model")
	}
	t.Log("confirmed: mixed dealer sets produce mutually inconsistent shares (decrypt would fail)")
}

// TestUniformDealerSetPreservesConsistency proves the fix's guarantee: when all
// operators finalize on the SAME dealer set, refreshed shares stay consistent.
func TestUniformDealerSetPreservesConsistency(t *testing.T) {
	ops, cur, S, threshold := setupThreeOpSharing(t)
	A, B, C := ops[0].OperatorAddress, ops[1].OperatorAddress, ops[2].OperatorAddress
	members := []common.Address{A, B, C}
	full := []common.Address{A, B, C}

	// Full-set agreement (what the fix enforces): every operator uses {A,B,C}.
	uniform := map[common.Address][]common.Address{A: full, B: full, C: full}
	newShares := runRoundWithDealerSets(t, ops, cur, threshold, uniform)

	consistent, recovered := recoversConsistentKey(t, newShares, members)
	if !consistent {
		t.Fatal("uniform full dealer set must keep shares consistent, but it did not")
	}
	if !recovered.Equal(S) {
		t.Fatalf("uniform full dealer set must preserve the master secret S; got a different key")
	}
	t.Log("confirmed: uniform full dealer set preserves S and keeps shares consistent")
}

// sanity: types import used (keeps goimports honest if this file is trimmed later)
var _ = types.G2Point{}
