package config

import (
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Environment variable names for KMS Server configuration
const (
	EnvKMSOperatorAddress        = "KMS_OPERATOR_ADDRESS"
	EnvKMSPort                   = "KMS_PORT"
	EnvKMSChainID                = "KMS_CHAIN_ID"
	EnvKMSRPCURL                 = "KMS_RPC_URL"
	EnvKMSAVSAddress             = "KMS_AVS_ADDRESS"
	EnvKMSOperatorSetID          = "KMS_OPERATOR_SET_ID"
	EnvKMSVerbose                = "KMS_VERBOSE"
	EnvKMSBaseRPCURL             = "KMS_BASE_RPC_URL"
	EnvKMSCommitmentRegistryAddr = "KMS_COMMITMENT_REGISTRY_ADDRESS"
	// ECDSA operator signing configuration
	EnvKMSECDSAPrivateKey       = "KMS_ECDSA_PRIVATE_KEY"
	EnvKMSUseRemoteSigner       = "KMS_USE_REMOTE_SIGNER"
	EnvKMSWeb3SignerURL         = "KMS_WEB3SIGNER_URL"
	EnvKMSWeb3SignerCACert      = "KMS_WEB3SIGNER_CA_CERT"
	EnvKMSWeb3SignerCert        = "KMS_WEB3SIGNER_CERT"
	EnvKMSWeb3SignerKey         = "KMS_WEB3SIGNER_KEY"
	EnvKMSWeb3SignerFromAddress = "KMS_WEB3SIGNER_FROM_ADDRESS"
	EnvKMSWeb3SignerPublicKey   = "KMS_WEB3SIGNER_PUBLIC_KEY"
	// Persistence configuration
	EnvKMSPersistenceType     = "KMS_PERSISTENCE_TYPE"
	EnvKMSPersistenceDataPath = "KMS_PERSISTENCE_DATA_PATH"
	// Redis persistence configuration
	EnvKMSRedisAddress   = "KMS_REDIS_ADDRESS"
	EnvKMSRedisPassword  = "KMS_REDIS_PASSWORD"
	EnvKMSRedisDB        = "KMS_REDIS_DB"
	EnvKMSRedisKeyPrefix = "KMS_REDIS_KEY_PREFIX"
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
	ChainId_BaseAnvil       ChainId = 31338
	ChainId_BaseSepolia     ChainId = 84532
)

type ChainName string

const (
	ChainName_EthereumMainnet ChainName = "mainnet"
	ChainName_EthereumSepolia ChainName = "sepolia"
	ChainName_PreProdSepolia  ChainName = "dev"
	ChainName_EthereumAnvil   ChainName = "devnet"
	ChainName_BaseAnvil       ChainName = "base-devnet"
	ChainName_BaseSepolia     ChainName = "base-sepolia"
)

var ChainIdToName = map[ChainId]ChainName{
	ChainId_EthereumMainnet: ChainName_EthereumMainnet,
	ChainId_EthereumSepolia: ChainName_EthereumSepolia,
	ChainId_EthereumAnvil:   ChainName_EthereumAnvil,
	ChainId_BaseAnvil:       ChainName_BaseAnvil,
	ChainId_BaseSepolia:     ChainName_BaseSepolia,
}
var ChainNameToId = map[ChainName]ChainId{
	ChainName_EthereumMainnet: ChainId_EthereumMainnet,
	ChainName_EthereumSepolia: ChainId_EthereumSepolia,
	ChainName_EthereumAnvil:   ChainId_EthereumAnvil,
	ChainName_BaseAnvil:       ChainId_BaseAnvil,
	ChainName_BaseSepolia:     ChainId_BaseSepolia,
}

func IsEthereum(chainId ChainId) bool {
	return chainId == ChainId_EthereumMainnet || chainId == ChainId_EthereumSepolia || chainId == ChainId_EthereumAnvil
}

func GetDefaultPollerIntervalForChainId(chainId ChainId) time.Duration {
	switch chainId {
	case ChainId_EthereumMainnet:
		return 6 * time.Second
	case ChainId_EthereumSepolia:
		return 6 * time.Second
	case ChainId_BaseAnvil:
		return 1 * time.Second
	case ChainId_BaseSepolia:
		return 1 * time.Second
	case ChainId_EthereumAnvil:
		return 2 * time.Second
	default:
		return 6 * time.Second // Default to mainnet interval
	}
}

// Block interval constants by chain (block-based scheduling)
const (
	ReshareBlockInterval_Mainnet = 50 // 50 blocks ~10 minutes (12s per block)
	ReshareBlockInterval_Sepolia = 10 // 10 blocks ~2 minutes (12s per block)
	ReshareBlockInterval_Anvil   = 10 // 10 blocks for testing (20 seconds with 2s blocks)
)

func GetEnvironmentNameForChainName(chainName ChainName) (string, error) {
	switch chainName {
	case ChainName_EthereumMainnet:
		return "mainnet-ethereum", nil
	case ChainName_EthereumSepolia:
		return "testnet-sepolia", nil
	case ChainName_EthereumAnvil:
		return "devnet-sepolia", nil
	case ChainName_PreProdSepolia:
		return "preprod-sepolia", nil
	}
	return "", fmt.Errorf("unsupported chain name: %s", chainName)
}

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
		ChainId_BaseAnvil:       ethereumSepoliaCoreContracts, // fork of ethereum sepolia (for L2 testing)
		ChainId_BaseSepolia:     &CoreContractAddresses{},     // No core contracts on Base for now
	}
)

func GetCoreContractsForChainId(chainId ChainId) (*CoreContractAddresses, error) {
	contracts, ok := CoreContracts[chainId]
	if !ok {
		return nil, fmt.Errorf("unsupported chain ID: %d", chainId)
	}
	return contracts, nil
}

type ECDSAKeyConfig struct {
	UseRemoteSigner    bool                `json:"remoteSigner" yaml:"remoteSigner"`
	RemoteSignerConfig *RemoteSignerConfig `json:"remoteSignerConfig" yaml:"remoteSignerConfig"`
	PrivateKey         string              `json:"privateKey" yaml:"privateKey"`
}

func (ekc *ECDSAKeyConfig) Validate() error {
	var allErrors field.ErrorList
	if ekc.UseRemoteSigner {
		if ekc.RemoteSignerConfig == nil {
			allErrors = append(allErrors, field.Required(field.NewPath("remoteSignerConfig"), "remoteSignerConfig is required when UseRemoteSigner is true"))
		} else if err := ekc.RemoteSignerConfig.Validate(); err != nil {
			allErrors = append(allErrors, field.Invalid(field.NewPath("remoteSignerConfig"), ekc.RemoteSignerConfig, err.Error()))
		}
	}
	if len(allErrors) > 0 {
		return allErrors.ToAggregate()
	}
	return nil
}

type OperatorConfig struct {
	Address       string          `json:"address"`        // Ethereum address of the operator
	SigningConfig *ECDSAKeyConfig `json:"signing_config"` // ECDSA key config for signing transactions
}

func (oc *OperatorConfig) Validate() error {
	var allErrors field.ErrorList
	if oc.Address == "" {
		allErrors = append(allErrors, field.Required(field.NewPath("address"), "address is required"))
	}
	if oc.SigningConfig == nil {
		allErrors = append(allErrors, field.Required(field.NewPath("signingConfig"), "signingConfig is required"))
	}
	if len(allErrors) > 0 {
		return allErrors.ToAggregate()
	}
	return nil
}

// PersistenceConfig represents the persistence layer configuration
type PersistenceConfig struct {
	// Type specifies the persistence backend: "memory", "badger", or "redis"
	Type string `json:"type"`

	// DataPath is the directory path for file-based persistence (used by badger)
	// Not used for memory or redis persistence
	DataPath string `json:"data_path"`

	// Redis configuration (only used when Type is "redis")
	RedisConfig *RedisConfig `json:"redis_config,omitempty"`
}

// RedisConfig holds configuration for Redis persistence
type RedisConfig struct {
	// Address is the Redis server address (host:port)
	Address string `json:"address"`
	// Password is the optional Redis password
	Password string `json:"password,omitempty"`
	// DB is the Redis database number (0-15)
	DB int `json:"db"`
	// KeyPrefix is an optional custom prefix for all keys (for multi-tenant setups).
	// If set, this prefix is prepended to all keys, e.g., "myapp:" would result in
	// keys like "myapp:kms:keyshare:123". If empty, keys use the default "kms:" prefix.
	KeyPrefix string `json:"key_prefix,omitempty"`
}

// Validate validates the persistence configuration
func (pc *PersistenceConfig) Validate() error {
	// Default to badger if not specified
	if pc.Type == "" {
		pc.Type = "badger"
	}

	// Validate type
	if pc.Type != "memory" && pc.Type != "badger" && pc.Type != "redis" {
		return fmt.Errorf("persistence type must be 'memory', 'badger', or 'redis', got '%s'", pc.Type)
	}

	// Validate data path for badger
	if pc.Type == "badger" && pc.DataPath == "" {
		pc.DataPath = "./kms-data" // Default path
	}

	// Validate redis config
	if pc.Type == "redis" {
		if pc.RedisConfig == nil {
			return fmt.Errorf("redis_config is required when persistence type is 'redis'")
		}
		if pc.RedisConfig.Address == "" {
			return fmt.Errorf("redis address cannot be empty")
		}
		if pc.RedisConfig.DB < 0 || pc.RedisConfig.DB > 15 {
			return fmt.Errorf("redis DB must be between 0 and 15, got %d", pc.RedisConfig.DB)
		}
	}

	return nil
}

// KMSServerConfig represents the complete configuration for a KMS server
type KMSServerConfig struct {
	// Node identity
	OperatorAddress string `json:"operator_address"` // Ethereum address of the operator
	Port            int    `json:"port"`

	// Chain configuration
	ChainID   ChainId   `json:"chain_id"`
	ChainName ChainName `json:"chain_name"`

	// Blockchain configuration
	RpcUrl        string `json:"rpc_url"`         // Ethereum RPC endpoint
	AVSAddress    string `json:"avs_address"`     // AVS contract address
	OperatorSetId uint32 `json:"operator_set_id"` // Operator set ID

	// Base chain configuration (for commitment registry)
	BaseRpcUrl                string `json:"base_rpc_url"`                // Base chain RPC endpoint
	CommitmentRegistryAddress string `json:"commitment_registry_address"` // Commitment registry contract address on Base

	// Operational settings
	Debug   bool `json:"debug"`
	Verbose bool `json:"verbose"`

	// Persistence configuration
	PersistenceConfig PersistenceConfig `json:"persistence_config"`

	// Contract addresses (populated from chain)
	CoreContracts *CoreContractAddresses `json:"core_contracts,omitempty"`

	OperatorConfig *OperatorConfig `json:"operator_config,omitempty"`
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

	// Validate operator config (ECDSA signing configuration)
	if c.OperatorConfig == nil {
		return fmt.Errorf("operator config cannot be nil")
	} else {
		if err := c.OperatorConfig.Validate(); err != nil {
			return fmt.Errorf("invalid operator config: %w", err)
		}
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

	// Validate persistence configuration
	if err := c.PersistenceConfig.Validate(); err != nil {
		return fmt.Errorf("invalid persistence config: %w", err)
	}

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
