package dkg

import (
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/merkle"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// addressToNodeID converts an Ethereum address to a node ID using keccak256 hash
func addressToNodeID(address common.Address) int {
	hash := ethcrypto.Keccak256(address.Bytes())
	nodeID := int(common.BytesToHash(hash).Big().Uint64())
	return nodeID
}

// Protocol represents the DKG protocol interface
type Protocol interface {
	GenerateShares() (map[int]*fr.Element, []types.G2Point, error)
	VerifyShare(fromID int, share *fr.Element, commitments []types.G2Point) bool
	FinalizeKeyShare(shares map[int]*fr.Element, allCommitments [][]types.G2Point, participantIDs []int) *types.KeyShareVersion
}

// DKG implements the distributed key generation protocol
type DKG struct {
	nodeID    int
	threshold int
	operators []*peering.OperatorSetPeer
	poly      polynomial.Polynomial
}

// NewDKG creates a new DKG instance
func NewDKG(nodeID int, threshold int, operators []*peering.OperatorSetPeer) *DKG {
	return &DKG{
		nodeID:    nodeID,
		threshold: threshold,
		operators: operators,
	}
}

// GenerateShares generates polynomial coefficients, shares, and commitments
func (d *DKG) GenerateShares() (map[int]*fr.Element, []types.G2Point, error) {
	// Generate random polynomial of degree t-1.
	// fr.Element.SetRandom() pulls entropy from crypto/rand via gnark-crypto; the call may
	// fail if the system RNG is unavailable, in which case we bubble the error up.
	coeffs := make([]fr.Element, d.threshold)
	for i := 0; i < d.threshold; i++ {
		if _, err := coeffs[i].SetRandom(); err != nil {
			return nil, nil, err
		}
	}
	d.poly = coeffs

	// Compute shares for all operators
	shares := make(map[int]*fr.Element)
	for _, op := range d.operators {
		opNodeID := addressToNodeID(op.OperatorAddress)
		share := crypto.EvaluatePolynomial(d.poly, int64(opNodeID))
		shares[opNodeID] = share
	}

	// Create commitments in G2
	commitments := make([]types.G2Point, d.threshold)
	for k := 0; k < d.threshold; k++ {
		commitment, err := crypto.ScalarMulG2(crypto.G2Generator, &coeffs[k])
		if err != nil {
			return nil, nil, err
		}
		commitments[k] = *commitment
	}

	return shares, commitments, nil
}

// VerifyShare verifies a share against commitments using polynomial commitment verification
func (d *DKG) VerifyShare(fromID int, share *fr.Element, commitments []types.G2Point) bool {
	// Verify: share * G2 == Σ(commitment_k * nodeID^k)
	leftSide, err := crypto.ScalarMulG2(crypto.G2Generator, share)
	if err != nil {
		return false
	}

	jFr := new(fr.Element).SetInt64(int64(d.nodeID))
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

// FinalizeKeyShare computes the final key share from all received shares
func (d *DKG) FinalizeKeyShare(shares map[int]*fr.Element, allCommitments [][]types.G2Point, participantIDs []int) *types.KeyShareVersion {
	// Sum all received shares
	privateShare := new(fr.Element).SetZero()
	for _, share := range shares {
		privateShare.Add(privateShare, share)
	}

	// Combine commitments from all dealers element-wise
	combinedCommitments := make([]types.G2Point, 0)
	if len(allCommitments) > 0 {
		combinedCommitments = make([]types.G2Point, len(allCommitments[0]))
		for i := range combinedCommitments {
			combinedCommitments[i] = *types.ZeroG2Point()
		}
		for _, commitments := range allCommitments {
			for idx, commitment := range commitments {
				sum, err := crypto.AddG2(combinedCommitments[idx], commitment)
				if err != nil {
					continue
				}
				combinedCommitments[idx] = *sum
			}
		}
	}

	return &types.KeyShareVersion{
		Version:        GetReshareEpoch(),
		PrivateShare:   privateShare,
		Commitments:    combinedCommitments,
		IsActive:       true,
		ParticipantIDs: participantIDs,
	}
}

// GetReshareEpoch calculates the current reshare epoch
func GetReshareEpoch() int64 {
	return 0 // Placeholder - should use time.Now().Unix() / RESHARE_FREQUENCY
}

// CreateAcknowledgement creates an acknowledgement for received shares
// Phase 4: Updated to include shareHash and epoch
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

// CalculateThreshold calculates the threshold for a given number of nodes
func CalculateThreshold(n int) int {
	// ⌈2n/3⌉
	return (2*n + 2) / 3
}
