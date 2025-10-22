package config

import "fmt"

type CurveType string

func (c CurveType) String() string {
	return string(c)
}
func (c CurveType) Uint8() (uint8, error) {
	return ConvertCurveTypeToSolidityEnum(c)
}

const (
	CurveTypeUnknown CurveType = "unknown"
	CurveTypeECDSA   CurveType = "ecdsa"
	CurveTypeBN254   CurveType = "bn254" // BN254 is the only supported curve type for now
)

func ConvertCurveTypeToSolidityEnum(curveType CurveType) (uint8, error) {
	switch curveType {
	case CurveTypeUnknown:
		return 0, nil
	case CurveTypeECDSA:
		return 1, nil
	case CurveTypeBN254:
		return 2, nil
	default:
		return 0, fmt.Errorf("unsupported curve type: %s", curveType)
	}
}

func ConvertSolidityEnumToCurveType(enumValue uint8) (CurveType, error) {
	switch enumValue {
	case 0:
		return CurveTypeUnknown, nil
	case 1:
		return CurveTypeECDSA, nil
	case 2:
		return CurveTypeBN254, nil
	default:
		return "", fmt.Errorf("unsupported curve type enum value: %d", enumValue)
	}
}

type ChainId uint

const (
	ChainId_EthereumMainnet ChainId = 1
	ChainId_EthereumSepolia ChainId = 11155111
	ChainId_EthereumAnvil   ChainId = 31337
)

type CoreContractAddresses struct {
	AllocationManager string
	DelegationManager string
	ReleaseManager    string
	KeyRegistrar      string
}

var (
	ethereumSepoliaCoreContracts = &CoreContractAddresses{
		AllocationManager: "0x42583067658071247ec8ce0a516a58f682002d07",
		DelegationManager: "0xd4a7e1bd8015057293f0d0a557088c286942e84b",
		ReleaseManager:    "0x59c8D715DCa616e032B744a753C017c9f3E16bf4",
		KeyRegistrar:      "0xa4db30d08d8bbca00d40600bee9f029984db162a",
	}

	CoreContracts = map[ChainId]*CoreContractAddresses{
		ChainId_EthereumMainnet: {
			AllocationManager: "0x42583067658071247ec8CE0A516A58f682002d07",
			DelegationManager: "0xD4A7E1Bd8015057293f0D0A557088c286942e84b",
		},
		ChainId_EthereumSepolia: ethereumSepoliaCoreContracts,
		ChainId_EthereumAnvil:   ethereumSepoliaCoreContracts, // fork of ethereum sepolia
	}
)

func GetCoreContractsForChainId(chainId ChainId) (*CoreContractAddresses, error) {
	contracts, ok := CoreContracts[chainId]
	if !ok {
		return nil, fmt.Errorf("unsupported chain ID: %d", chainId)
	}
	return contracts, nil
}
