package reshare

import (
	"fmt"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/bls"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/dkg"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/merkle"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
	"github.com/ethereum/go-ethereum/common"
)

// Protocol represents the reshare protocol interface
type Protocol interface {
	GenerateNewShares(currentShare *fr.Element, newThreshold int) (map[common.Address]*fr.Element, []types.G2Point, error)
	VerifyNewShare(share *fr.Element, commitments []types.G2Point) bool
	ComputeNewKeyShare(dealers []common.Address, shares map[common.Address]*fr.Element, allCommitments [][]types.G2Point) (*types.KeyShareVersion, error)
}

// Reshare implements the reshare protocol
type Reshare struct {
	nodeAddress common.Address
	operators   []*peering.OperatorSetPeer
	poly        polynomial.Polynomial
}

// NewReshare creates a new reshare instance
func NewReshare(nodeAddress common.Address, operators []*peering.OperatorSetPeer) *Reshare {
	return &Reshare{
		nodeAddress: nodeAddress,
		operators:   operators,
	}
}

// GenerateNewShares generates new shares with the current share as the constant term
func (r *Reshare) GenerateNewShares(currentShare *fr.Element, newThreshold int) (map[common.Address]*fr.Element, []types.G2Point, error) {
	if currentShare == nil {
		return nil, nil, fmt.Errorf("no current share to reshare")
	}

	// Generate new polynomial where f'_i(0) = s_i (current share)
	coeffs := make([]fr.Element, newThreshold)
	coeffs[0].Set(currentShare) // CRITICAL: constant term is current share

	for i := 1; i < newThreshold; i++ {
		if _, err := coeffs[i].SetRandom(); err != nil {
			return nil, nil, err
		}
	}
	r.poly = coeffs

	// Compute shares for all operators
	newShares := make(map[common.Address]*fr.Element)
	for _, op := range r.operators {
		share := crypto.EvaluatePolynomial(r.poly, op.OperatorAddress)
		newShares[op.OperatorAddress] = share
	}

	// Create commitments in G2
	commitments := make([]types.G2Point, newThreshold)
	for k := 0; k < newThreshold; k++ {
		commitment, err := crypto.ScalarMulG2(crypto.G2Generator, &coeffs[k])
		if err != nil {
			return nil, nil, err
		}
		commitments[k] = *commitment
	}

	return newShares, commitments, nil
}

// VerifyNewShare verifies a reshared share against commitments.
//
// NOTE: This reimplements the polynomial commitment verification logic found in
// bls.VerifyShare. The duplication exists because bls.VerifyShare operates on
// []*bls.G2Point (which wraps bls12381.G2Affine internally) while this method
// receives []types.G2Point (a serialization-friendly type using CompressedBytes).
// Bridging the two types would require either a circular import (types -> bls)
// or an awkward deserialization/conversion layer that isn't justified for a
// single call site. If the types are unified in the future, this should delegate
// to bls.VerifyShare.
func (r *Reshare) VerifyNewShare(share *fr.Element, commitments []types.G2Point) bool {
	if len(commitments) == 0 || share == nil {
		return false
	}

	// Same verification as DKG
	leftSide, err := crypto.ScalarMulG2(crypto.G2Generator, share)
	if err != nil {
		return false
	}

	jFr := bls.AddressToFr(r.nodeAddress)
	jPower := new(fr.Element).SetOne()
	rightSide := commitments[0]

	for k := 1; k < len(commitments); k++ {
		jPower.Mul(jPower, jFr)
		term, err := crypto.ScalarMulG2(commitments[k], jPower)
		if err != nil {
			return false
		}
		tmpRightSide, err := crypto.AddG2(rightSide, *term)
		if err != nil {
			return false
		}
		rightSide = *tmpRightSide
	}

	return leftSide.IsEqual(&rightSide)
}

// ComputeNewKeyShare computes the new key share using Lagrange interpolation
func (r *Reshare) ComputeNewKeyShare(dealers []common.Address, shares map[common.Address]*fr.Element, _ [][]types.G2Point) (*types.KeyShareVersion, error) {
	if len(dealers) == 0 {
		return nil, fmt.Errorf("no dealer IDs provided")
	}

	// Compute x'_j = Σ_{i∈dealers} λ_i * s'_{ij}
	newShare := new(fr.Element).SetZero()

	for _, dealerAddr := range dealers {
		share := shares[dealerAddr]
		if share == nil {
			continue
		}

		lambda := crypto.ComputeLagrangeCoefficient(dealerAddr, dealers)
		term := new(fr.Element).Mul(lambda, share)
		newShare.Add(newShare, term)
	}

	// Publish commitments in the same form as existing operators so that /pubkey
	// reconstruction semantics are consistent across operator join paths.
	commitments := make([]types.G2Point, 0, 1)
	shareCommitment, err := crypto.ScalarMulG2(crypto.G2Generator, newShare)
	if err != nil {
		return nil, fmt.Errorf("failed to compute share commitment: %w", err)
	}
	lambdaJ := crypto.ComputeLagrangeCoefficient(r.nodeAddress, dealers)
	scaledCommitment, scaleErr := crypto.ScalarMulG2(*shareCommitment, lambdaJ)
	if scaleErr != nil {
		return nil, fmt.Errorf("failed to scale commitment: %w", scaleErr)
	}
	commitments = append(commitments, *scaledCommitment)

	return &types.KeyShareVersion{
		Version:        0, // TODO: Use proper epoch calculation
		PrivateShare:   newShare,
		Commitments:    commitments,
		IsActive:       false,
		ParticipantIDs: dealers,
	}, nil
}

// ValidateReshareMasterPublicKey recomputes the group public key implied by the refreshed
// sharing and requires it to equal the expected (carried-forward) master public key.
//
// Each dealer d's polynomial has constant term equal to its source share x_d, so its first
// commitment is C_d[0] = x_d·G2. The refreshed secret is S” = Σ_{d∈D} λ_d(D)·x_d, hence the
// refreshed group public key is Σ_{d∈D} λ_d(D)·C_d[0] = S”·G2. If every dealer dealt from a
// share of the SAME source polynomial, S” = S and this equals MPK(S). If a dealer dealt from
// a stale/foreign source (a cross-round version split, docs/012), S” != S and this check
// FAILS — converting silent master-secret corruption into a loud, retryable abort.
//
// This is the "validate before commit" step specified in docs/011 (§ step 5) and never
// implemented; docs/012 Layer 1. commitmentsByDealer must contain every dealer in D;
// a missing entry is an error (silently skipping it would sum a wrong key).
func ValidateReshareMasterPublicKey(
	dealers []common.Address,
	commitmentsByDealer map[common.Address][]types.G2Point,
	expectedMPK *types.G2Point,
) error {
	if len(dealers) == 0 {
		return fmt.Errorf("no dealers provided for MPK validation")
	}
	if expectedMPK == nil {
		return fmt.Errorf("no expected master public key provided for MPK validation")
	}

	var sum *types.G2Point
	for _, dealer := range dealers {
		commitments, ok := commitmentsByDealer[dealer]
		if !ok || len(commitments) == 0 {
			return fmt.Errorf("missing commitments for agreed dealer %s; cannot validate MPK", dealer.Hex())
		}

		lambda := crypto.ComputeLagrangeCoefficient(dealer, dealers)
		term, err := crypto.ScalarMulG2(commitments[0], lambda)
		if err != nil {
			return fmt.Errorf("failed to scale commitment for dealer %s: %w", dealer.Hex(), err)
		}

		if sum == nil {
			sum = term
			continue
		}
		sum, err = crypto.AddG2(*sum, *term)
		if err != nil {
			return fmt.Errorf("failed to accumulate commitment for dealer %s: %w", dealer.Hex(), err)
		}
	}

	// Defensive: with len(dealers) > 0 and each ScalarMulG2 returning a non-nil point, sum is
	// non-nil here — but guard rather than risk a nil-deref panic on a consensus-critical path
	// if ScalarMulG2's contract ever changes.
	if sum == nil {
		return fmt.Errorf("internal: MPK sum is nil after processing %d dealers", len(dealers))
	}
	if !sum.IsEqual(expectedMPK) {
		return fmt.Errorf("post-reshare master public key mismatch: refreshed shares do not reconstruct the served master public key " +
			"(source-version split or divergent dealer set); aborting to avoid corrupting the master secret")
	}
	return nil
}

// SelectMajoritySourceVersion picks the source key version that a threshold of the agreed
// dealers dealt from, and returns the subset of dealers on that version (docs/012 Layer 2).
//
// Reshare only preserves the master secret if every finalized dealer dealt from a share of
// the SAME source polynomial (version). A dealer that lagged a round deals from a stale
// version; including it would shift the reconstructed secret. We therefore keep only the
// dealers on the majority version and drop the laggards — an excluded dealer still
// recomputes its own share as a recipient of the majority dealers, resyncing implicitly.
//
// Safety rules (conservative — Layer 1's MPK check is the ultimate backstop, so when in
// doubt we abort rather than risk divergent finalize sets across nodes):
//   - a dealer with an UNKNOWN source version is dropped from the tally, not counted. A
//     source version is unknown if it is absent from the map OR reported as 0 — 0 is the
//     zero value a pre-Layer-2 peer (omitempty field) or a node with no active version
//     sends, so it must never be counted as a real "version 0" (that would let a rolling
//     upgrade form a bogus version-0 majority);
//   - the winning version must have >= threshold dealers (else no safe set → error);
//   - a tie for the top count is ambiguous (different nodes could break it differently)
//     → error.
//
// All honest nodes observe the same dealer commitments, so this selection is deterministic
// across the cluster.
func SelectMajoritySourceVersion(
	dealers []common.Address,
	sourceVersions map[common.Address]int64,
	threshold int,
) ([]common.Address, int64, error) {
	if len(dealers) == 0 {
		return nil, 0, fmt.Errorf("no dealers provided for source-version selection")
	}

	counts := make(map[int64]int)
	for _, d := range dealers {
		// A version of 0 (or absent) is "unknown" — skip it. It never counts toward a
		// majority; if too few dealers have a known version, the threshold check below aborts.
		if v := sourceVersions[d]; v != 0 {
			counts[v]++
		}
	}

	// Find the top count and detect ties. `tie` is cleared whenever a strictly higher count
	// is found, so a later equal-count entry only re-flags a tie against the current best.
	// Invariant: `counts` contains only non-zero versions (the v != 0 guard above), so every
	// entry has c >= 1 and the first iteration always satisfies c > 0 == bestCount — there is
	// no spurious tie at initialization. This relies on that guard; do not relax it.
	var bestVersion int64
	bestCount := 0
	tie := false
	for v, c := range counts {
		switch {
		case c > bestCount:
			bestVersion, bestCount, tie = v, c, false
		case c == bestCount:
			tie = true
		}
	}
	if tie {
		return nil, 0, fmt.Errorf("ambiguous source-version majority (tie at %d dealers); aborting to avoid divergent finalize sets", bestCount)
	}
	if bestCount < threshold {
		return nil, 0, fmt.Errorf("majority source version has only %d dealers, need %d; aborting", bestCount, threshold)
	}

	// Keep dealers on the winning version, preserving input order for determinism.
	kept := make([]common.Address, 0, bestCount)
	for _, d := range dealers {
		if sourceVersions[d] == bestVersion {
			kept = append(kept, d)
		}
	}
	return kept, bestVersion, nil
}

// CreateCompletionSignature creates a completion signature for reshare
func CreateCompletionSignature(nodeAddress common.Address, epoch int64, commitmentHash [32]byte, signer func(int64, [32]byte) []byte) *types.CompletionSignature {
	signature := signer(epoch, commitmentHash)

	return &types.CompletionSignature{
		NodeAddress:      nodeAddress,
		SessionTimestamp: epoch,
		CommitmentHash:   commitmentHash,
		Signature:        signature,
	}
}

// BuildAcknowledgementMerkleTree creates a merkle tree from collected acknowledgements.
// Delegates to dkg.BuildAcknowledgementMerkleTree as the canonical implementation.
func BuildAcknowledgementMerkleTree(acks []*types.Acknowledgement) (*merkle.MerkleTree, error) {
	return dkg.BuildAcknowledgementMerkleTree(acks)
}
