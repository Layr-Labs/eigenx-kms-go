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
		share := crypto.EvaluatePolynomialAddr(r.poly, op.OperatorAddress)
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

// VerifyNewShare verifies a reshared share against commitments
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

		lambda := crypto.ComputeLagrangeCoefficientAddr(dealerAddr, dealers)
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
	lambdaJ := crypto.ComputeLagrangeCoefficientAddr(r.nodeAddress, dealers)
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
