package peeringDataFetcher

import (
	"context"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"go.uber.org/zap"
)

type PeeringDataFetcher struct {
	contractCaller contractCaller.IContractCaller
	logger         *zap.Logger
}

func NewPeeringDataFetcher(
	contractCaller contractCaller.IContractCaller,
	logger *zap.Logger,
) *PeeringDataFetcher {
	return &PeeringDataFetcher{
		contractCaller: contractCaller,
		logger:         logger,
	}
}

func (pdf *PeeringDataFetcher) ListKMSOperators(ctx context.Context, avsAddress string, operatorSetId uint32) (*peering.OperatorSetPeers, error) {
	return pdf.contractCaller.GetOperatorSetMembersWithPeering(avsAddress, operatorSetId)
}
