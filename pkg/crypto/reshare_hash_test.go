package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// fixedCommitments returns a deterministic (non-random) commitment slice so hash outputs
// are stable across runs — required for the golden-vector guard below.
func fixedCommitments() []types.G2Point {
	return []types.G2Point{
		{CompressedBytes: []byte{0x01, 0x02, 0x03, 0x04}},
		{CompressedBytes: []byte{0xaa, 0xbb, 0xcc}},
	}
}

// knownHashCommitmentGolden is sha256(0x01020304 ‖ 0xaabbcc) — the current HashCommitment
// output for fixedCommitments(). Pinned so any change to HashCommitment's algorithm fails
// loudly (see below).
const knownHashCommitmentGolden = "31d0c4c8b11197baaf69b4539a83288914f5f238b9dc8d5b3113f0dfd87f5672"

// GOLDEN VECTOR: HashCommitment must remain byte-for-byte unchanged. It is shared by DKG
// on-chain submission and ack merkle signing/verification; binding a reshare source
// version into it (docs/013 Change 2) would silently break DKG hashes and ack signatures
// across the DKG/reshare boundary. This pins its output for a fixed input so any change to
// HashCommitment's algorithm fails loudly. If this test ever needs updating, that is a red
// flag — HashCommitment's wire/consensus meaning changed.
func TestHashCommitment_GoldenVectorUnchanged(t *testing.T) {
	got := hex.EncodeToString(hashSlice(HashCommitment(fixedCommitments())))
	if got != knownHashCommitmentGolden {
		t.Fatalf("HashCommitment output changed!\n got: %s\nwant: %s\nHashCommitment is shared with DKG+acks and MUST NOT change.", got, knownHashCommitmentGolden)
	}
}

func hashSlice(h [32]byte) []byte { return h[:] }

// HashReshareCommitment must (a) differ from HashCommitment for the same commitments, and
// (b) differ for different source versions — so the on-chain-submitted hash commits to the
// dealer's source version and equivocation (advertising a different version over P2P) is
// detectable.
func TestHashReshareCommitment_BindsSourceVersion(t *testing.T) {
	c := fixedCommitments()

	plain := HashCommitment(c)
	v1 := HashReshareCommitment(c, 1783120000)
	v1again := HashReshareCommitment(c, 1783120000)
	v2 := HashReshareCommitment(c, 1783120120)

	if v1 != v1again {
		t.Fatal("HashReshareCommitment must be deterministic")
	}
	if v1 == plain {
		t.Fatal("HashReshareCommitment must differ from HashCommitment (source version must change the hash)")
	}
	if v1 == v2 {
		t.Fatal("HashReshareCommitment must differ for different source versions")
	}
}
