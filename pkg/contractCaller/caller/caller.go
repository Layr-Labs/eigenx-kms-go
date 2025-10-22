package caller

import (
	"context"
	"fmt"
	"math/big"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenlayer-contracts/pkg/bindings/IAllocationManager"
	"github.com/Layr-Labs/eigenlayer-contracts/pkg/bindings/IKeyRegistrar"
	"github.com/Layr-Labs/eigenlayer-contracts/pkg/bindings/IReleaseManager"
	ethereum "github.com/Layr-Labs/eigenx-kms-go/pkg/clients"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/middleware-bindings/ISocketRegistryV2"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/util"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"
)

type ContractCaller struct {
	ethclient     *ethclient.Client
	logger        *zap.Logger
	coreContracts *config.CoreContractAddresses

	allocationManager *IAllocationManager.IAllocationManager
	keyRegistrar      *IKeyRegistrar.IKeyRegistrar
	releaseManager    *IReleaseManager.IReleaseManager
}

func NewContractCallerFromEthereumClient(
	ethClient *ethereum.Client,
	logger *zap.Logger,
) (*ContractCaller, error) {
	client, err := ethClient.GetEthereumContractCaller()
	if err != nil {
		return nil, err
	}

	return NewContractCaller(client, logger)
}

func NewContractCaller(
	ethclient *ethclient.Client,
	logger *zap.Logger,
) (*ContractCaller, error) {
	chainId, err := ethclient.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %w", err)
	}

	coreContracts, err := config.GetCoreContractsForChainId(config.ChainId(chainId.Uint64()))
	if err != nil {
		return nil, fmt.Errorf("failed to get core contracts: %w", err)
	}
	logger.Sugar().Infow("Using core contracts",
		zap.Any("coreContracts", coreContracts),
	)

	allocationManager, err := IAllocationManager.NewIAllocationManager(common.HexToAddress(coreContracts.AllocationManager), ethclient)
	if err != nil {
		return nil, fmt.Errorf("failed to create allocation manager contract instance: %w", err)
	}

	keyRegistrar, err := IKeyRegistrar.NewIKeyRegistrar(common.HexToAddress(coreContracts.KeyRegistrar), ethclient)
	if err != nil {
		return nil, fmt.Errorf("failed to create key registrar contract instance: %w", err)
	}

	releaseManager, err := IReleaseManager.NewIReleaseManager(common.HexToAddress(coreContracts.ReleaseManager), ethclient)
	if err != nil {
		return nil, fmt.Errorf("failed to create release manager contract instance: %w", err)
	}

	return &ContractCaller{
		ethclient:     ethclient,
		coreContracts: coreContracts,
		logger:        logger,

		allocationManager: allocationManager,
		keyRegistrar:      keyRegistrar,
		releaseManager:    releaseManager,
	}, nil
}

func (cc *ContractCaller) GetOperatorSetMembersWithPeering(
	avsAddress string,
	operatorSetId uint32,
) (*peering.OperatorSetPeers, error) {
	operatorSetStringAddrs, err := cc.GetOperatorSetMembers(avsAddress, operatorSetId)
	if err != nil {
		return nil, err
	}

	operatorSetMemberAddrs := util.Map(operatorSetStringAddrs, func(address string, i uint64) common.Address {
		return common.HexToAddress(address)
	})

	allMembers := make([]*peering.OperatorSetPeer, 0)
	for _, member := range operatorSetMemberAddrs {
		operatorSetInfo, err := cc.GetOperatorSetDetailsForOperator(member, avsAddress, operatorSetId)
		if err != nil {
			cc.logger.Sugar().Errorf("failed to get operator set details for operator %s: %v", member.Hex(), err)
			return nil, err
		}
		allMembers = append(allMembers, operatorSetInfo)
	}
	return &peering.OperatorSetPeers{
		OperatorSetId: operatorSetId,
		Peers:         allMembers,
		AVSAddress:    common.HexToAddress(avsAddress),
	}, nil
}

func (cc *ContractCaller) GetOperatorSetDetailsForOperator(
	operatorAddress common.Address,
	avsAddress string,
	operatorSetId uint32,
) (*peering.OperatorSetPeer, error) {
	opset := IKeyRegistrar.OperatorSet{
		Avs: common.HexToAddress(avsAddress),
		Id:  operatorSetId,
	}

	// Get the AVS registrar address from the allocation manager
	avsAddr := common.HexToAddress(avsAddress)
	avsRegistrarAddress, err := cc.allocationManager.GetAVSRegistrar(&bind.CallOpts{}, avsAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get AVS registrar address: %w", err)
	}

	// Create new registrar caller
	// TODO(seanmcgary): this will be more specific later rather than just the socket registry
	caller, err := ISocketRegistryV2.NewISocketRegistryV2Caller(avsRegistrarAddress, cc.ethclient)
	if err != nil {
		return nil, fmt.Errorf("failed to create AVS registrar caller: %w", err)
	}
	socket, err := caller.GetOperatorSocket(&bind.CallOpts{}, operatorAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get operator socket: %w", err)
	}

	curveTypeSolidity, err := cc.keyRegistrar.GetOperatorSetCurveType(&bind.CallOpts{}, opset)
	if err != nil {
		cc.logger.Sugar().Errorf("failed to get operator set curve type: %v", err)
		return nil, err
	}

	curveType, err := config.ConvertSolidityEnumToCurveType(curveTypeSolidity)
	if err != nil {
		cc.logger.Sugar().Errorf("failed to convert curve type: %v", err)
		return nil, fmt.Errorf("failed to convert curve type: %w", err)
	}

	peeringOpset := &peering.OperatorSetPeer{
		OperatorAddress: operatorAddress,
		SocketAddress:   socket,
		CurveType:       curveType,
	}

	if curveType == config.CurveTypeBN254 {
		solidityPubKey, err := cc.keyRegistrar.GetBN254Key(&bind.CallOpts{}, opset, operatorAddress)
		if err != nil {
			cc.logger.Sugar().Errorf("failed to get operator set public key: %v", err)
			return nil, err
		}

		pubKey, err := bn254.NewPublicKeyFromSolidity(
			&bn254.SolidityBN254G1Point{
				X: solidityPubKey.G1Point.X,
				Y: solidityPubKey.G1Point.Y,
			},
			&bn254.SolidityBN254G2Point{
				X: [2]*big.Int{
					solidityPubKey.G2Point.X[0],
					solidityPubKey.G2Point.X[1],
				},
				Y: [2]*big.Int{
					solidityPubKey.G2Point.Y[0],
					solidityPubKey.G2Point.Y[1],
				},
			},
		)
		if err != nil {
			cc.logger.Sugar().Errorf("failed to convert public key: %v", err)
			return nil, err
		}
		peeringOpset.WrappedPublicKey = peering.WrappedPublicKey{
			PublicKey: pubKey,
		}
		return peeringOpset, nil
	}

	if curveType == config.CurveTypeECDSA {
		ecdsaAddr, err := cc.keyRegistrar.GetECDSAAddress(&bind.CallOpts{}, opset, operatorAddress)
		if err != nil {
			cc.logger.Sugar().Errorf("failed to get operator set public key: %v", err)
			return nil, err
		}
		peeringOpset.WrappedPublicKey = peering.WrappedPublicKey{
			ECDSAAddress: ecdsaAddr,
		}
		return peeringOpset, nil
	}
	cc.logger.Sugar().Errorf("unsupported curve type: %s", curveType)
	return nil, fmt.Errorf("unsupported curve type: %s", curveType)
}

func (cc *ContractCaller) GetOperatorSetMembers(avsAddress string, operatorSetId uint32) ([]string, error) {
	avsAddr := common.HexToAddress(avsAddress)
	operatorSet, err := cc.allocationManager.GetMembers(&bind.CallOpts{}, IAllocationManager.OperatorSet{
		Avs: avsAddr,
		Id:  operatorSetId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get operator set members: %w", err)
	}
	members := make([]string, len(operatorSet))
	for i, member := range operatorSet {
		members[i] = member.String()
	}
	return members, nil
}
