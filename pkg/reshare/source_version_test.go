package reshare

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
)

// Layer 2 (docs/012): at finalize, keep only dealers that dealt from the MAJORITY source
// version. A dealer on a stale/foreign source version (it lagged a round) is excluded so
// it cannot inject a mismatched-source polynomial; it still recomputes its own share as a
// recipient from the majority dealers, resyncing implicitly. If fewer than `threshold`
// dealers share the majority version, there is no safe set to finalize on → error.

func TestSelectMajoritySourceVersion_AllAgree(t *testing.T) {
	A := common.HexToAddress("0x0A")
	B := common.HexToAddress("0x0B")
	C := common.HexToAddress("0x0C")
	src := map[common.Address]int64{A: 100, B: 100, C: 100}

	kept, version, err := SelectMajoritySourceVersion([]common.Address{A, B, C}, src, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != 100 {
		t.Fatalf("expected majority version 100, got %d", version)
	}
	if len(kept) != 3 {
		t.Fatalf("expected all 3 dealers kept, got %d", len(kept))
	}
}

func TestSelectMajoritySourceVersion_ExcludesLaggard(t *testing.T) {
	A := common.HexToAddress("0x0A")
	B := common.HexToAddress("0x0B")
	C := common.HexToAddress("0x0C")
	// A lagged: it is dealing from an older source version than the B/C quorum.
	src := map[common.Address]int64{A: 90, B: 100, C: 100}

	kept, version, err := SelectMajoritySourceVersion([]common.Address{A, B, C}, src, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != 100 {
		t.Fatalf("expected majority version 100, got %d", version)
	}
	if len(kept) != 2 {
		t.Fatalf("expected laggard A excluded (2 kept), got %d: %v", len(kept), kept)
	}
	for _, d := range kept {
		if d == A {
			t.Fatal("laggard A must be excluded from the finalize set")
		}
	}
}

func TestSelectMajoritySourceVersion_AbortsWhenMajorityBelowThreshold(t *testing.T) {
	A := common.HexToAddress("0x0A")
	B := common.HexToAddress("0x0B")
	C := common.HexToAddress("0x0C")
	// Three-way split: no version has >= threshold(2) dealers.
	src := map[common.Address]int64{A: 90, B: 100, C: 110}

	if _, _, err := SelectMajoritySourceVersion([]common.Address{A, B, C}, src, 2); err == nil {
		t.Fatal("expected error when no source version reaches threshold, got nil")
	}
}

func TestSelectMajoritySourceVersion_AbortsOnTie(t *testing.T) {
	A := common.HexToAddress("0x0A")
	B := common.HexToAddress("0x0B")
	C := common.HexToAddress("0x0C")
	D := common.HexToAddress("0x0D")
	// Tie: two on 100, two on 90, threshold 2. A tie is ambiguous — different nodes could
	// pick different majorities and finalize on divergent sets, so abort rather than risk it.
	src := map[common.Address]int64{A: 100, B: 100, C: 90, D: 90}

	if _, _, err := SelectMajoritySourceVersion([]common.Address{A, B, C, D}, src, 2); err == nil {
		t.Fatal("expected error on an ambiguous tie, got nil")
	}
}

func TestSelectMajoritySourceVersion_UnknownDealerDropped(t *testing.T) {
	A := common.HexToAddress("0x0A")
	B := common.HexToAddress("0x0B")
	C := common.HexToAddress("0x0C")
	// C never reported a source version (absent from the map) — it is unknown and dropped
	// from the tally, exactly like a zero. A and B share version 100 and meet the threshold,
	// so we finalize on {A, B} and exclude C. (Dropping an unclassifiable laggard and
	// finalizing on the known-version quorum is the intended Layer 2 behavior; Layer 1
	// backstops any residual divergence.)
	src := map[common.Address]int64{A: 100, B: 100}

	kept, version, err := SelectMajoritySourceVersion([]common.Address{A, B, C}, src, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != 100 || len(kept) != 2 {
		t.Fatalf("expected {A,B} on version 100 (C dropped as unknown), got version %d, kept %v", version, kept)
	}
	for _, d := range kept {
		if d == C {
			t.Fatal("dealer with an unknown source version must be excluded")
		}
	}

	// But if dropping the unknown leaves fewer than threshold on the majority, abort.
	if _, _, err := SelectMajoritySourceVersion([]common.Address{A, B, C}, map[common.Address]int64{A: 100}, 2); err == nil {
		t.Fatal("expected error when known-version dealers fall below threshold, got nil")
	}
}

// A dealer reporting SourceVersion == 0 is a pre-Layer-2 peer (the field is omitempty, so
// old nodes send nothing and it deserializes to 0) or a node with no active version. The
// zero is "unknown", NOT a real version 0 — it must be excluded from the source-version
// tally exactly like a missing entry, so a rolling upgrade cannot count old nodes into a
// bogus "version 0" majority. (docs/012 Layer 2; bot review round 1.)
func TestSelectMajoritySourceVersion_ZeroIsUnknownNotCounted(t *testing.T) {
	A := common.HexToAddress("0x0A")
	B := common.HexToAddress("0x0B")
	C := common.HexToAddress("0x0C")

	// A is pre-Layer-2 (reports 0); B and C are on version 100. A must be excluded, and the
	// kept set must be {B, C} on version 100 — never a "version 0" that includes A.
	src := map[common.Address]int64{A: 0, B: 100, C: 100}
	kept, version, err := SelectMajoritySourceVersion([]common.Address{A, B, C}, src, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != 100 {
		t.Fatalf("expected majority version 100, got %d", version)
	}
	if len(kept) != 2 {
		t.Fatalf("expected {B,C} kept (A excluded as unknown), got %d: %v", len(kept), kept)
	}
	for _, d := range kept {
		if d == A {
			t.Fatal("dealer reporting SourceVersion 0 must be excluded, not counted as version 0")
		}
	}

	// If the ONLY dealers reachable report 0, there is no known majority ≥ threshold → abort.
	allZero := map[common.Address]int64{A: 0, B: 0, C: 0}
	if _, _, err := SelectMajoritySourceVersion([]common.Address{A, B, C}, allZero, 2); err == nil {
		t.Fatal("expected error when all dealers report unknown (0) source versions, got nil")
	}
}

// TestLayer2_MixedSourceRoundReproducedAndFixed is the end-to-end regression for the live
// incident (docs/012): round R+1 after a version split, where one dealer (A) deals from a
// stale source version while B and C deal from the current one. It proves BOTH halves:
//
//   - WITHOUT source-version filtering (finalize on all 3 dealers): the refreshed shares
//     reconstruct a DIFFERENT secret S” != S — consistent among themselves but no longer
//     matching the served master public key MPK(S), so every decrypt fails ("all
//     combinations exhausted"). This is the precise corruption signature (see docs/012).
//   - WITH SelectMajoritySourceVersion (drop the laggard, finalize on {B,C}): the refreshed
//     shares reconstruct S and preserve the master secret.
func TestLayer2_MixedSourceRoundReproducedAndFixed(t *testing.T) {
	ops, cur, S, threshold := setupThreeOpSharing(t)
	A, B, C := ops[0].OperatorAddress, ops[1].OperatorAddress, ops[2].OperatorAddress
	members := []common.Address{A, B, C}

	// Version split: A lagged and is dealing from a stale/foreign source point; B and C are
	// on the current source version. (Distinct source versions, modeling the incident.)
	staleShares := map[common.Address]*fr.Element{
		A: new(fr.Element).SetUint64(111111111), // foreign source point
		B: cur[B],
		C: cur[C],
	}
	sourceVersions := map[common.Address]int64{A: 90, B: 100, C: 100}

	// (1) Unfiltered: all three deal, everyone finalizes on {A,B,C}. Shares stay mutually
	// consistent (uniform dealer set) but reconstruct S'' != S — the served MPK(S) no longer
	// matches, so decrypt fails cluster-wide. This is the corruption.
	allDealers := map[common.Address][]common.Address{A: members, B: members, C: members}
	corrupt := runRoundWithDealerSets(t, ops, staleShares, threshold, allDealers)
	consistent, corruptSecret := recoversConsistentKey(t, corrupt, members)
	if !consistent {
		t.Fatal("expected mixed-source round with a uniform dealer set to stay self-consistent; it did not — model drift")
	}
	if corruptSecret.Equal(S) {
		t.Fatal("expected mixed-source round WITHOUT filtering to reconstruct S'' != S (corruption); it preserved S — model drift")
	}

	// (2) Layer 2 filtering: majority source version is 100 → keep {B,C}, drop A.
	kept, version, err := SelectMajoritySourceVersion(members, sourceVersions, threshold)
	if err != nil {
		t.Fatalf("SelectMajoritySourceVersion: %v", err)
	}
	if version != 100 || len(kept) != 2 {
		t.Fatalf("expected majority version 100 with 2 dealers, got version %d, kept %v", version, kept)
	}

	// Every node finalizes on the SAME kept set {B,C}. A too (as a recipient of B,C) — it
	// recomputes its own refreshed share from the kept dealers, resyncing.
	keptSets := map[common.Address][]common.Address{A: kept, B: kept, C: kept}
	fixed := runRoundWithDealerSets(t, ops, staleShares, threshold, keptSets)

	consistent, recovered := recoversConsistentKey(t, fixed, members)
	if !consistent {
		t.Fatal("Layer 2 kept-set round must keep shares consistent, but it did not")
	}
	if !recovered.Equal(S) {
		t.Fatal("Layer 2 kept-set round must preserve the master secret S (B and C are on the S-version), got a different key")
	}
	t.Log("confirmed: mixed-source round corrupts unfiltered; source-version filtering preserves S")
}
