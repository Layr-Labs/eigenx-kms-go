package caller

import (
	"context"
	"fmt"
	"math/big"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/eigenlayer-contracts/pkg/bindings/IAllocationManager"
	"github.com/Layr-Labs/eigenlayer-contracts/pkg/bindings/IDelegationManager"
	"github.com/Layr-Labs/eigenlayer-contracts/pkg/bindings/IKeyRegistrar"
	"github.com/Layr-Labs/eigenlayer-contracts/pkg/bindings/IReleaseManager"
	ethereum "github.com/Layr-Labs/eigenx-kms-go/pkg/clients"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/middleware-bindings/IEigenKMSRegistrar"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/transactionSigner"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/util"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"
)

type ContractCaller struct {
	ethclient     *ethclient.Client
	logger        *zap.Logger
	coreContracts *config.CoreContractAddresses

	allocationManager *IAllocationManager.IAllocationManager
	delegationManager *IDelegationManager.IDelegationManager
	keyRegistrar      *IKeyRegistrar.IKeyRegistrar
	releaseManager    *IReleaseManager.IReleaseManager

	signer transactionSigner.ITransactionSigner
}

func NewContractCallerFromEthereumClient(
	ethClient *ethereum.Client,
	signer transactionSigner.ITransactionSigner,
	logger *zap.Logger,
) (*ContractCaller, error) {
	client, err := ethClient.GetEthereumContractCaller()
	if err != nil {
		return nil, err
	}

	return NewContractCaller(client, signer, logger)
}

func NewContractCaller(
	ethclient *ethclient.Client,
	signer transactionSigner.ITransactionSigner,
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

	delegationManager, err := IDelegationManager.NewIDelegationManager(common.HexToAddress(coreContracts.DelegationManager), ethclient)
	if err != nil {
		return nil, fmt.Errorf("failed to create delegation manager contract instance: %w", err)
	}

	return &ContractCaller{
		ethclient:     ethclient,
		coreContracts: coreContracts,
		logger:        logger,

		allocationManager: allocationManager,
		delegationManager: delegationManager,
		keyRegistrar:      keyRegistrar,
		releaseManager:    releaseManager,

		signer: signer,
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
	caller, err := IEigenKMSRegistrar.NewIEigenKMSRegistrarCaller(avsRegistrarAddress, cc.ethclient)
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

func (cc *ContractCaller) EncodeBN254KeyData(pubKey *bn254.PublicKey) ([]byte, error) {
	// Convert G1 point
	g1Point := &bn254.G1Point{
		G1Affine: pubKey.GetG1Point(),
	}
	g1Bytes, err := g1Point.ToPrecompileFormat()
	if err != nil {
		return nil, fmt.Errorf("public key not in correct subgroup: %w", err)
	}

	keyRegG1 := IKeyRegistrar.BN254G1Point{
		X: new(big.Int).SetBytes(g1Bytes[0:32]),
		Y: new(big.Int).SetBytes(g1Bytes[32:64]),
	}

	g2Point := bn254.NewZeroG2Point().AddPublicKey(pubKey)
	g2Bytes, err := g2Point.ToPrecompileFormat()
	if err != nil {
		return nil, fmt.Errorf("public key not in correct subgroup: %w", err)
	}
	// Convert to IKeyRegistrar G2 point format
	keyRegG2 := IKeyRegistrar.BN254G2Point{
		X: [2]*big.Int{
			new(big.Int).SetBytes(g2Bytes[0:32]),
			new(big.Int).SetBytes(g2Bytes[32:64]),
		},
		Y: [2]*big.Int{
			new(big.Int).SetBytes(g2Bytes[64:96]),
			new(big.Int).SetBytes(g2Bytes[96:128]),
		},
	}

	return cc.keyRegistrar.EncodeBN254KeyData(
		&bind.CallOpts{},
		keyRegG1,
		keyRegG2,
	)
}

func (cc *ContractCaller) GetOperatorSetCurveType(avsAddress string, operatorSetId uint32, blockNumber uint64) (config.CurveType, error) {
	blockHeightOpts := &bind.CallOpts{}
	if blockNumber > 0 {
		blockHeightOpts.BlockNumber = big.NewInt(int64(blockNumber))
	}

	curveType, err := cc.keyRegistrar.GetOperatorSetCurveType(blockHeightOpts, IKeyRegistrar.OperatorSet{
		Avs: common.HexToAddress(avsAddress),
		Id:  operatorSetId,
	})
	if err != nil {
		return config.CurveTypeUnknown, fmt.Errorf("failed to get operator set curve type: %w", err)
	}

	return config.ConvertSolidityEnumToCurveType(curveType)
}

func (cc *ContractCaller) GetOperatorECDSAKeyRegistrationMessageHash(
	ctx context.Context,
	operatorAddress common.Address,
	avsAddress common.Address,
	operatorSetId uint32,
	signingKeyAddress common.Address,
) ([32]byte, error) {
	cc.logger.Sugar().Infow("Getting ECDSA key registration message hash",
		zap.String("operatorAddress", operatorAddress.String()),
		zap.String("avsAddress", avsAddress.Hex()),
		zap.Uint32("operatorSetId", operatorSetId),
		zap.String("signingKeyAddress", signingKeyAddress.String()),
	)
	return cc.keyRegistrar.GetECDSAKeyRegistrationMessageHash(&bind.CallOpts{Context: ctx}, operatorAddress, IKeyRegistrar.OperatorSet{
		Avs: avsAddress,
		Id:  operatorSetId,
	}, signingKeyAddress)
}

func (cc *ContractCaller) GetOperatorBN254KeyRegistrationMessageHash(
	ctx context.Context,
	operatorAddress common.Address,
	avsAddress common.Address,
	operatorSetId uint32,
	keyData []byte,
) ([32]byte, error) {
	return cc.keyRegistrar.GetBN254KeyRegistrationMessageHash(&bind.CallOpts{Context: ctx}, operatorAddress, IKeyRegistrar.OperatorSet{
		Avs: avsAddress,
		Id:  operatorSetId,
	}, keyData)
}

func (cc *ContractCaller) RegisterKeyWithKeyRegistrar(
	ctx context.Context,
	operatorAddress common.Address,
	avsAddress common.Address,
	operatorSetId uint32,
	sigBytes []byte,
	keyData []byte,
) (*types.Receipt, error) {
	txOpts, err := cc.buildTransactionOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction options: %w", err)
	}

	// Create operator set struct
	operatorSet := IKeyRegistrar.OperatorSet{
		Avs: avsAddress,
		Id:  operatorSetId,
	}

	cc.logger.Sugar().Debugw("Registering key with KeyRegistrar",
		"operatorAddress:", operatorAddress.String(),
		"avsAddress:", avsAddress.String(),
		"operatorSetId:", operatorSetId,
		"keyData", hexutil.Encode(keyData),
		"sigButes:", hexutil.Encode(sigBytes),
	)

	tx, err := cc.keyRegistrar.RegisterKey(
		txOpts,
		operatorAddress,
		operatorSet,
		keyData,
		sigBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register key: %w", err)
	}

	return cc.signAndSendTransaction(ctx, tx, "ConfigureOperatorSet")
}

func (cc *ContractCaller) createOperator(ctx context.Context, operatorAddress common.Address, allocationDelay uint32, metadataUri string) (*types.Receipt, error) {
	noSendTxOpts, err := cc.buildTransactionOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction options: %w", err)
	}

	exists, err := cc.delegationManager.IsOperator(&bind.CallOpts{}, operatorAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to check if operator exists: %w", err)
	}
	if exists {
		cc.logger.Sugar().Infow("Operator already exists, skipping creation",
			zap.String("operatorAddress", operatorAddress.String()),
		)
		return nil, nil
	}

	tx, err := cc.delegationManager.RegisterAsOperator(
		noSendTxOpts,
		common.Address{},
		allocationDelay,
		metadataUri,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	return cc.signAndSendTransaction(ctx, tx, "RegisterAsOperator")
}

func (cc *ContractCaller) registerOperatorWithAvs(
	ctx context.Context,
	operatorAddress common.Address,
	avsAddress common.Address,
	operatorSetIds []uint32,
	socket string,
) (*types.Receipt, error) {
	txOpts, err := cc.buildTransactionOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction options: %w", err)
	}

	encodedSocket, err := util.EncodeString(socket)
	if err != nil {
		return nil, fmt.Errorf("failed to encode socket string: %w", err)
	}

	tx, err := cc.allocationManager.RegisterForOperatorSets(txOpts, operatorAddress, IAllocationManager.IAllocationManagerTypesRegisterParams{
		Avs:            avsAddress,
		OperatorSetIds: operatorSetIds,
		Data:           encodedSocket,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	return cc.signAndSendTransaction(ctx, tx, "registerOperatorWithAvs")
}

func (cc *ContractCaller) CreateOperatorAndRegisterWithAvs(
	ctx context.Context,
	avsAddress common.Address,
	operatorAddress common.Address,
	operatorSetIds []uint32,
	socket string,
	allocationDelay uint32,
	metadataUri string,
) (*types.Receipt, error) {
	createdOperator, err := cc.createOperator(ctx, operatorAddress, allocationDelay, metadataUri)
	if err != nil {
		return nil, fmt.Errorf("failed to register as operator: %w", err)
	}
	cc.logger.Sugar().Infow("Successfully created operator",
		zap.Any("receipt", createdOperator),
	)

	cc.logger.Sugar().Infow("Registering operator socket with AVS")
	socketReceipt, err := cc.registerOperatorWithAvs(ctx, operatorAddress, avsAddress, operatorSetIds, socket)
	if err != nil {
		return nil, fmt.Errorf("failed to register operator socket with AVS: %w", err)
	}
	cc.logger.Sugar().Infow("Successfully registered operator socket with AVS",
		zap.Any("receipt", socketReceipt),
	)

	return socketReceipt, nil
}
