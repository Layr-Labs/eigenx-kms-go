package reshare

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
)

// VerifyDealerSourceVersions is the docs/013 Change 2 gate: it keeps only agreed dealers
// whose P2P (commitments, sourceVersion) hash to the dealer's on-chain commitment hash,
// returning the verified dealers and their verified source-version map. This is the
// mechanism that closes Bug 2 — an unauthenticated P2P source version can no longer enter
// the tally, so honest nodes cannot finalize on divergent same-source subsets.

func fixedComms(tag byte) []types.G2Point {
	return []types.G2Point{{CompressedBytes: []byte{tag, tag, tag}}}
}

func TestVerifyDealerSourceVersions_AcceptsMatching(t *testing.T) {
	A := common.HexToAddress("0x0A")
	B := common.HexToAddress("0x0B")

	commsA, commsB := fixedComms(0xAA), fixedComms(0xBB)
	svA, svB := int64(100), int64(100)

	onChain := map[common.Address][32]byte{
		A: crypto.HashReshareCommitment(commsA, svA),
		B: crypto.HashReshareCommitment(commsB, svB),
	}
	commitmentsByDealer := map[common.Address][]types.G2Point{A: commsA, B: commsB}
	sourceVersions := map[common.Address]int64{A: svA, B: svB}

	verified, versions := VerifyDealerSourceVersions(
		[]common.Address{A, B}, onChain, commitmentsByDealer, sourceVersions)

	if len(verified) != 2 {
		t.Fatalf("expected both dealers verified, got %d", len(verified))
	}
	if versions[A] != 100 || versions[B] != 100 {
		t.Fatalf("verified versions wrong: %v", versions)
	}
}

// Equivocation: a dealer advertises a source version over P2P that differs from the one it
// committed on-chain. The on-chain hash was computed with the committed version, so the
// recomputed hash won't match → the dealer is REJECTED. This is the corruption vector.
func TestVerifyDealerSourceVersions_RejectsEquivocatedVersion(t *testing.T) {
	A := common.HexToAddress("0x0A")
	B := common.HexToAddress("0x0B")

	commsA, commsB := fixedComms(0xAA), fixedComms(0xBB)

	// A committed version 100 on-chain but advertises 999 over P2P.
	onChain := map[common.Address][32]byte{
		A: crypto.HashReshareCommitment(commsA, 100),
		B: crypto.HashReshareCommitment(commsB, 100),
	}
	commitmentsByDealer := map[common.Address][]types.G2Point{A: commsA, B: commsB}
	sourceVersions := map[common.Address]int64{A: 999, B: 100} // A equivocates

	verified, versions := VerifyDealerSourceVersions(
		[]common.Address{A, B}, onChain, commitmentsByDealer, sourceVersions)

	if len(verified) != 1 || verified[0] != B {
		t.Fatalf("equivocating A must be rejected, only B kept; got %v", verified)
	}
	if _, ok := versions[A]; ok {
		t.Fatal("equivocating dealer must not appear in the verified version map")
	}
}

// A dealer whose P2P commitment/version we haven't received (e.g. dropped broadcast) can't
// be verified against its on-chain hash, so it is dropped — never silently trusted.
func TestVerifyDealerSourceVersions_DropsUnreceived(t *testing.T) {
	A := common.HexToAddress("0x0A")
	B := common.HexToAddress("0x0B")

	commsA := fixedComms(0xAA)
	onChain := map[common.Address][32]byte{
		A: crypto.HashReshareCommitment(commsA, 100),
		B: crypto.HashReshareCommitment(fixedComms(0xBB), 100),
	}
	// B's commitments/version never arrived over P2P.
	commitmentsByDealer := map[common.Address][]types.G2Point{A: commsA}
	sourceVersions := map[common.Address]int64{A: 100}

	verified, _ := VerifyDealerSourceVersions(
		[]common.Address{A, B}, onChain, commitmentsByDealer, sourceVersions)

	if len(verified) != 1 || verified[0] != A {
		t.Fatalf("unreceived B must be dropped, only A kept; got %v", verified)
	}
}

// Determinism: two nodes given identical on-chain hashes but DIFFERENT partial P2P views
// (one missing a dealer) still produce verified sets that are subsets of the same set and
// never contain a dealer bound to a different version — so the downstream tally over the
// verified set cannot diverge into inconsistent same-source subsets.
func TestVerifyDealerSourceVersions_NeverAdmitsWrongVersion(t *testing.T) {
	A := common.HexToAddress("0x0A")
	commsA := fixedComms(0xAA)
	// On-chain commits version 100.
	onChain := map[common.Address][32]byte{A: crypto.HashReshareCommitment(commsA, 100)}

	// Node X received A's real commitments+version → verifies.
	vx, mx := VerifyDealerSourceVersions([]common.Address{A}, onChain,
		map[common.Address][]types.G2Point{A: commsA}, map[common.Address]int64{A: 100})
	if len(vx) != 1 || mx[A] != 100 {
		t.Fatalf("node X should verify A@100, got %v / %v", vx, mx)
	}

	// Node Y received A's commitments but a WRONG version (skewed/tampered P2P) → rejects,
	// rather than admitting A at a version that would diverge from node X.
	vy, my := VerifyDealerSourceVersions([]common.Address{A}, onChain,
		map[common.Address][]types.G2Point{A: commsA}, map[common.Address]int64{A: 200})
	if len(vy) != 0 {
		t.Fatalf("node Y must reject A (wrong version), got %v / %v", vy, my)
	}
}
