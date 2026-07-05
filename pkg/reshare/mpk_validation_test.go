package reshare

import (
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
)

// mpkOf returns S·G2, the master public key for secret S.
func mpkOf(t *testing.T, S *fr.Element) *types.G2Point {
	t.Helper()
	pk, err := crypto.ScalarMulG2(crypto.G2Generator, S)
	if err != nil {
		t.Fatalf("ScalarMulG2: %v", err)
	}
	return pk
}

// dealRound has every operator deal its current share and returns each dealer's
// polynomial commitments (commitments[dealer][0] == currentShare·G2).
func dealRound(
	t *testing.T,
	ops []*peering.OperatorSetPeer,
	currentShares map[common.Address]*fr.Element,
	threshold int,
) map[common.Address][]types.G2Point {
	t.Helper()
	commitmentsByDealer := map[common.Address][]types.G2Point{}
	for _, d := range ops {
		r := NewReshare(d.OperatorAddress, ops)
		_, commitments, err := r.GenerateNewShares(currentShares[d.OperatorAddress], threshold)
		if err != nil {
			t.Fatalf("GenerateNewShares(%s): %v", d.OperatorAddress.Hex(), err)
		}
		commitmentsByDealer[d.OperatorAddress] = commitments
	}
	return commitmentsByDealer
}

// TestValidateReshareMasterPublicKey_UniformSourcePasses proves the check accepts a
// healthy round: when every dealer deals from a share of the SAME source polynomial,
// the recomputed group public key Σ λ_d(D)·C_d[0] equals the carried-forward MPK(S).
func TestValidateReshareMasterPublicKey_UniformSourcePasses(t *testing.T) {
	ops, cur, S, threshold := setupThreeOpSharing(t)
	A, B, C := ops[0].OperatorAddress, ops[1].OperatorAddress, ops[2].OperatorAddress
	dealers := []common.Address{A, B, C}

	commitmentsByDealer := dealRound(t, ops, cur, threshold)

	if err := ValidateReshareMasterPublicKey(dealers, commitmentsByDealer, mpkOf(t, S)); err != nil {
		t.Fatalf("uniform-source round must validate against MPK(S), got error: %v", err)
	}
}

// TestValidateReshareMasterPublicKey_MixedSourceFails is the cross-round regression the
// design (docs/012) calls for: a version split leaves one dealer dealing from a stale
// source share. The recomputed group public key is then S”·G2 for some S” != S, so the
// check MUST reject it — this is the loud abort that replaces silent corruption.
func TestValidateReshareMasterPublicKey_MixedSourceFails(t *testing.T) {
	ops, cur, S, threshold := setupThreeOpSharing(t)
	A, B, C := ops[0].OperatorAddress, ops[1].OperatorAddress, ops[2].OperatorAddress
	dealers := []common.Address{A, B, C}

	// A is on a DIFFERENT source polynomial than B and C (it lagged a round). Mixing
	// its foreign source point into the reconstruction yields a different secret S''.
	staleShares := map[common.Address]*fr.Element{
		A: new(fr.Element).SetUint64(111111111), // stale/foreign source point
		B: cur[B],
		C: cur[C],
	}
	commitmentsByDealer := dealRound(t, ops, staleShares, threshold)

	if err := ValidateReshareMasterPublicKey(dealers, commitmentsByDealer, mpkOf(t, S)); err == nil {
		t.Fatal("mixed-source round must FAIL MPK validation (would otherwise silently corrupt), got nil")
	}
}

// TestValidateReshareMasterPublicKey_MissingCommitmentErrors guards the input contract:
// a dealer in the agreed set with no commitments cannot be validated, so the check must
// error rather than silently skipping it (skipping would drop it from the sum and pass a
// wrong key).
func TestValidateReshareMasterPublicKey_MissingCommitmentErrors(t *testing.T) {
	ops, cur, S, threshold := setupThreeOpSharing(t)
	A, B, C := ops[0].OperatorAddress, ops[1].OperatorAddress, ops[2].OperatorAddress
	dealers := []common.Address{A, B, C}

	commitmentsByDealer := dealRound(t, ops, cur, threshold)
	delete(commitmentsByDealer, C) // C's commitments missing

	if err := ValidateReshareMasterPublicKey(dealers, commitmentsByDealer, mpkOf(t, S)); err == nil {
		t.Fatal("missing dealer commitment must error, got nil")
	}
}
