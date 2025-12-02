package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Environment variable names for KMS Server configuration
const (
	EnvKMSOperatorAddress  = "KMS_OPERATOR_ADDRESS"
	EnvKMSPort             = "KMS_PORT"
	EnvKMSChainID          = "KMS_CHAIN_ID"
	EnvKMSBN254PrivateKey  = "KMS_BN254_PRIVATE_KEY"
	EnvKMSRPCURL           = "KMS_RPC_URL"
	EnvKMSAVSAddress       = "KMS_AVS_ADDRESS"
	EnvKMSOperatorSetID    = "KMS_OPERATOR_SET_ID"
	EnvKMSVerbose          = "KMS_VERBOSE"
)

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

type ChainName string

const (
	ChainName_EthereumMainnet ChainName = "mainnet"
	ChainName_EthereumSepolia ChainName = "sepolia"
	ChainName_EthereumAnvil   ChainName = "devnet"
)

var ChainIdToName = map[ChainId]ChainName{
	ChainId_EthereumMainnet: ChainName_EthereumMainnet,
	ChainId_EthereumSepolia: ChainName_EthereumSepolia,
	ChainId_EthereumAnvil:   ChainName_EthereumAnvil,
}
var ChainNameToId = map[ChainName]ChainId{
	ChainName_EthereumMainnet: ChainId_EthereumMainnet,
	ChainName_EthereumSepolia: ChainId_EthereumSepolia,
	ChainName_EthereumAnvil:   ChainId_EthereumAnvil,
}

// Block interval constants by chain (block-based scheduling)
const (
	ReshareBlockInterval_Mainnet = 50 // 50 blocks ~10 minutes (12s per block)
	ReshareBlockInterval_Sepolia = 10 // 10 blocks ~2 minutes (12s per block)
	ReshareBlockInterval_Anvil   = 10 // 10 blocks for testing (20 seconds with 2s blocks)
)

// GetReshareBlockIntervalForChain returns the block interval for reshares on a given chain
func GetReshareBlockIntervalForChain(chainId ChainId) int64 {
	switch chainId {
	case ChainId_EthereumMainnet:
		return ReshareBlockInterval_Mainnet
	case ChainId_EthereumSepolia:
		return ReshareBlockInterval_Sepolia
	case ChainId_EthereumAnvil:
		return ReshareBlockInterval_Anvil
	default:
		return ReshareBlockInterval_Mainnet // Default to mainnet interval
	}
}

// GetProtocolTimeoutForChain returns the timeout for protocol operations
// The timeout should be less than one block interval to prevent overlap
func GetProtocolTimeoutForChain(chainId ChainId) time.Duration {
	switch chainId {
	case ChainId_EthereumMainnet:
		// 50 blocks * 12s = 10 minutes, use 8 minutes for protocol timeout
		return 8 * time.Minute
	case ChainId_EthereumSepolia:
		// 10 blocks * 12s = 2 minutes, use 90 seconds for protocol timeout
		return 90 * time.Second
	case ChainId_EthereumAnvil:
		// 10 blocks * 2s = 20 seconds, use 15 seconds for protocol timeout
		return 15 * time.Second
	default:
		return 8 * time.Minute // Default to mainnet timeout
	}
}

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

// KMSServerConfig represents the complete configuration for a KMS server
type KMSServerConfig struct {
	// Node identity
	OperatorAddress string `json:"operator_address"` // Ethereum address of the operator
	Port            int    `json:"port"`

	// Chain configuration
	ChainID   ChainId   `json:"chain_id"`
	ChainName ChainName `json:"chain_name"`

	// Cryptographic keys
	BN254PrivateKey string `json:"bn254_private_key"` // BN254 private key for threshold crypto and P2P

	// Blockchain configuration
	RpcUrl        string `json:"rpc_url"`         // Ethereum RPC endpoint
	AVSAddress    string `json:"avs_address"`     // AVS contract address
	OperatorSetId uint32 `json:"operator_set_id"` // Operator set ID

	// Operational settings
	Debug   bool `json:"debug"`
	Verbose bool `json:"verbose"`

	// Contract addresses (populated from chain)
	CoreContracts *CoreContractAddresses `json:"core_contracts,omitempty"`
}

// Validate validates the KMS server configuration
func (c *KMSServerConfig) Validate() error {
	// Validate operator address
	if c.OperatorAddress == "" {
		return fmt.Errorf("operator address cannot be empty")
	}
	if !common.IsHexAddress(c.OperatorAddress) {
		return fmt.Errorf("invalid operator address format: %s", c.OperatorAddress)
	}

	// Validate BN254 private key format
	if c.BN254PrivateKey == "" {
		return fmt.Errorf("BN254 private key cannot be empty")
	}
	bn254Key := c.BN254PrivateKey
	if !strings.HasPrefix(bn254Key, "0x") {
		bn254Key = "0x" + bn254Key
	}
	if len(bn254Key) != 66 { // 0x + 64 hex chars
		return fmt.Errorf("BN254 private key must be 32 bytes (64 hex chars), got %d chars", len(bn254Key)-2)
	}

	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1-65535, got %d", c.Port)
	}

	// Validate chain ID
	chainName, exists := ChainIdToName[c.ChainID]
	if !exists {
		return fmt.Errorf("unsupported chain ID %d. Supported: %d (mainnet), %d (sepolia), %d (anvil)",
			c.ChainID, ChainId_EthereumMainnet, ChainId_EthereumSepolia, ChainId_EthereumAnvil)
	}

	c.ChainName = chainName

	// Get core contracts for this chain
	coreContracts, err := GetCoreContractsForChainId(c.ChainID)
	if err != nil {
		return fmt.Errorf("failed to get core contracts: %w", err)
	}
	c.CoreContracts = coreContracts

	return nil
}

// GetSupportedChainIDs returns all supported chain IDs
func GetSupportedChainIDs() []ChainId {
	return []ChainId{
		ChainId_EthereumMainnet,
		ChainId_EthereumSepolia,
		ChainId_EthereumAnvil,
	}
}

// GetSupportedChainIDsString returns supported chain IDs as strings for CLI help
func GetSupportedChainIDsString() string {
	return fmt.Sprintf("%d (mainnet), %d (sepolia), %d (anvil)",
		ChainId_EthereumMainnet, ChainId_EthereumSepolia, ChainId_EthereumAnvil)
}

type RemoteSignerConfig struct {
	Url         string `json:"url" yaml:"url"`
	CACert      string `json:"caCert" yaml:"caCert"`
	Cert        string `json:"cert" yaml:"cert"`
	Key         string `json:"key" yaml:"key"`
	FromAddress string `json:"fromAddress" yaml:"fromAddress"`
	PublicKey   string `json:"publicKey" yaml:"publicKey"`
}

func (rsc *RemoteSignerConfig) Validate() error {
	var allErrors field.ErrorList
	if rsc.FromAddress == "" {
		allErrors = append(allErrors, field.Required(field.NewPath("fromAddress"), "fromAddress is required"))
	}
	if rsc.PublicKey == "" {
		allErrors = append(allErrors, field.Required(field.NewPath("publicKey"), "publicKey is required"))
	}
	if len(allErrors) > 0 {
		return allErrors.ToAggregate()
	}
	return nil
}
