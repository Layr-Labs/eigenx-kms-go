package reshare

import (
	"fmt"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/merkle"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/util"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

// Protocol represents the reshare protocol interface
type Protocol interface {
	GenerateNewShares(currentShare *fr.Element, newThreshold int) (map[int]*fr.Element, []types.G2Point, error)
	VerifyNewShare(fromID int, share *fr.Element, commitments []types.G2Point) bool
	ComputeNewKeyShare(dealerIDs []int, shares map[int]*fr.Element, allCommitments [][]types.G2Point) *types.KeyShareVersion
}

// Reshare implements the reshare protocol
type Reshare struct {
	nodeID    int
	operators []*peering.OperatorSetPeer
	poly      polynomial.Polynomial
}

// NewReshare creates a new reshare instance
func NewReshare(nodeID int, operators []*peering.OperatorSetPeer) *Reshare {
	return &Reshare{
		nodeID:    nodeID,
		operators: operators,
	}
}

// GenerateNewShares generates new shares with the current share as the constant term
func (r *Reshare) GenerateNewShares(currentShare *fr.Element, newThreshold int) (map[int]*fr.Element, []types.G2Point, error) {
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
	newShares := make(map[int]*fr.Element)
	for _, op := range r.operators {
		opNodeID := util.AddressToNodeID(op.OperatorAddress)
		share := crypto.EvaluatePolynomial(r.poly, int64(opNodeID))
		newShares[opNodeID] = share
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

// VerifyNewShare verifies a reshared share against commitments
func (r *Reshare) VerifyNewShare(fromID int, share *fr.Element, commitments []types.G2Point) bool {
	// Same verification as DKG
	leftSide, err := crypto.ScalarMulG2(crypto.G2Generator, share)
	if err != nil {
		return false
	}

	jFr := new(fr.Element).SetInt64(int64(r.nodeID))
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
func (r *Reshare) ComputeNewKeyShare(dealerIDs []int, shares map[int]*fr.Element, allCommitments [][]types.G2Point) *types.KeyShareVersion {
	// Compute x'_j = Σ_{i∈dealers} λ_i * s'_{ij}
	newShare := new(fr.Element).SetZero()

	for _, dealerID := range dealerIDs {
		share := shares[dealerID]
		if share == nil {
			continue
		}

		lambda := crypto.ComputeLagrangeCoefficient(dealerID, dealerIDs)
		term := new(fr.Element).Mul(lambda, share)
		newShare.Add(newShare, term)
	}

	return &types.KeyShareVersion{
		Version:        0, // TODO: Use proper epoch calculation
		PrivateShare:   newShare,
		Commitments:    allCommitments[0],
		IsActive:       false,
		ParticipantIDs: dealerIDs,
	}
}

// CreateCompletionSignature creates a completion signature for reshare
func CreateCompletionSignature(nodeID int, epoch int64, commitmentHash [32]byte, signer func(int64, [32]byte) []byte) *types.CompletionSignature {
	signature := signer(epoch, commitmentHash)

	return &types.CompletionSignature{
		NodeID:         nodeID,
		Epoch:          epoch,
		CommitmentHash: commitmentHash,
		Signature:      signature,
	}
}

// CreateAcknowledgement creates an acknowledgement for received reshare (Phase 4)
// Same signature as DKG for consistency
func CreateAcknowledgement(nodeID, dealerID int, epoch int64, share *fr.Element, commitments []types.G2Point, signer func(int, [32]byte) []byte) *types.Acknowledgement {
	commitmentHash := crypto.HashCommitment(commitments)
	shareHash := crypto.HashShareForAck(share)
	signature := signer(dealerID, commitmentHash)

	return &types.Acknowledgement{
		DealerID:       dealerID,
		PlayerID:       nodeID,
		Epoch:          epoch,
		ShareHash:      shareHash,
		CommitmentHash: commitmentHash,
		Signature:      signature,
	}
}

// BuildAcknowledgementMerkleTree creates a merkle tree from collected acknowledgements (Phase 4)
// This is called after collecting all n-1 acknowledgements from other operators
// Returns the merkle tree for proof generation and the root hash for contract submission
func BuildAcknowledgementMerkleTree(acks []*types.Acknowledgement) (*merkle.MerkleTree, error) {
	if len(acks) == 0 {
		return nil, nil // No tree for empty acks
	}

	// Build merkle tree using the merkle package
	tree, err := merkle.BuildMerkleTree(acks)
	if err != nil {
		return nil, err
	}

	return tree, nil
}
