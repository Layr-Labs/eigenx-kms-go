package contractCaller

import (
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/ethereum/go-ethereum/common"
)

type IContractCaller interface {
	GetOperatorSetMembersWithPeering(
		avsAddress string,
		operatorSetId uint32,
	) (*peering.OperatorSetPeers, error)

	GetOperatorSetDetailsForOperator(
		operatorAddress common.Address,
		avsAddress string,
		operatorSetId uint32,
	) (*peering.OperatorSetPeer, error)

	GetOperatorSetMembers(avsAddress string, operatorSetId uint32) ([]string, error)
}
