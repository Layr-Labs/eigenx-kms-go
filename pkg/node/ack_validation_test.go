package node

import (
	"testing"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	eigenxcrypto "github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transportSigner/inMemoryTransportSigner"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"go.uber.org/zap"
)

func TestVerifyAcknowledgement_BindsFieldsAndSignature(t *testing.T) {
	logger := zap.NewNop()
	skBytes := make([]byte, 32)
	skBytes[31] = 1

	ts, err := inMemoryTransportSigner.NewBn254InMemoryTransportSigner(skBytes, logger)
	if err != nil {
		t.Fatalf("failed to create transport signer: %v", err)
	}
	sk, err := bn254.NewPrivateKeyFromBytes(skBytes)
	if err != nil {
		t.Fatalf("failed to create BN254 private key: %v", err)
	}

	dealerAddr := common.HexToAddress("0x000000000000000000000000000000000000000B")
	playerAddr := common.HexToAddress("0x0000000000000000000000000000000000000016")

	n := &Node{
		logger:          logger,
		transportSigner: ts,
		OperatorAddress: dealerAddr,
	}

	dealerID := int64(11)
	epoch := int64(123456)
	commitments := []types.G2Point{{CompressedBytes: []byte{1, 2, 3}}}
	shareHash := [32]byte{1, 1, 1}

	// Ensure commitment hash used in ack matches what verifier recomputes from session state.
	commitmentHash := eigenxcrypto.HashCommitment(commitments)

	ack := &types.Acknowledgement{
		DealerAddress:    dealerAddr,
		PlayerAddress:    playerAddr,
		SessionTimestamp: epoch,
		ShareHash:        shareHash,
		CommitmentHash:   commitmentHash,
	}
	ack.Signature = n.signAcknowledgement(ack.DealerAddress, ack.PlayerAddress, ack.SessionTimestamp, ack.ShareHash, ack.CommitmentHash)

	session := &ProtocolSession{
		commitments: map[int64][]types.G2Point{
			dealerID: commitments,
		},
	}
	senderPeer := &peering.OperatorSetPeer{
		OperatorAddress: playerAddr,
		CurveType:       config.CurveTypeBN254,
		WrappedPublicKey: peering.WrappedPublicKey{
			PublicKey: sk.Public(),
		},
	}

	if err := n.verifyAcknowledgement(session, senderPeer, dealerID, epoch, ack); err != nil {
		t.Fatalf("expected valid acknowledgement, got error: %v", err)
	}

	// Tamper epoch: signature/semantic binding must fail.
	tampered := *ack
	tampered.SessionTimestamp = epoch + 1
	if err := n.verifyAcknowledgement(session, senderPeer, dealerID, epoch, &tampered); err == nil {
		t.Fatal("expected tampered acknowledgement to be rejected")
	}
}
