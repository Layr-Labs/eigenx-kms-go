package localPeeringDataFetcher

import (
	"context"
	"errors"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"go.uber.org/zap"
)

type LocalPeeringDataFetcher struct {
	operatorPeers []*peering.OperatorSetPeers
	logger        *zap.Logger
}

func NewLocalPeeringDataFetcher(
	peers []*peering.OperatorSetPeers,
	logger *zap.Logger,
) *LocalPeeringDataFetcher {
	return &LocalPeeringDataFetcher{
		operatorPeers: peers,
		logger:        logger,
	}
}

func (lpdf *LocalPeeringDataFetcher) ListKMSOperators(ctx context.Context, avsAddress string, operatorSetId uint32) (*peering.OperatorSetPeers, error) {
	for _, ops := range lpdf.operatorPeers {
		if ops.AVSAddress.Hex() == avsAddress && ops.OperatorSetId == operatorSetId {
			return ops, nil
		}
	}
	return nil, errors.New("operator set not found")
}
