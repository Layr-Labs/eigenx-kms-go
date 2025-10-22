package peering

import (
	"context"

	"github.com/Layr-Labs/crypto-libs/pkg/signing"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/ethereum/go-ethereum/common"
)

type WrappedPublicKey struct {
	PublicKey    signing.PublicKey `json:"publicKey"`
	ECDSAAddress common.Address    `json:"ecdsaAddress"`
}

type OperatorSetPeer struct {
	OperatorAddress  common.Address
	SocketAddress    string
	WrappedPublicKey WrappedPublicKey
	CurveType        config.CurveType
}

type OperatorSetPeers struct {
	OperatorSetId uint32
	AVSAddress    common.Address
	Peers         []*OperatorSetPeer
}

type IPeeringDataFetcher interface {
	ListKMSOperators(ctx context.Context, avsAddress string, operatorSetId uint32) (*OperatorSetPeers, error)
}
