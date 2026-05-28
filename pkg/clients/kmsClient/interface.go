package kmsClient

import (
	"github.com/ethereum/go-ethereum/common"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/peering"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// KMSClient defines the interface for interacting with the distributed KMS.
// Consumers can mock this interface for testing.
type KMSClient interface {
	GetOperators() (*peering.OperatorSetPeers, error)
	GetMasterPublicKey(operators *peering.OperatorSetPeers) (*types.G2Point, error)
	GetPublicKeyForApp(appID string) (*types.G1Point, *types.G2Point, error)

	Encrypt(appID string, data []byte, operators *peering.OperatorSetPeers) ([]byte, error)
	Decrypt(appID string, encryptedData []byte, operators *peering.OperatorSetPeers, threshold int) ([]byte, error)
	EncryptForApp(appID string, plaintext []byte) ([]byte, error)
	DecryptForApp(appID string, ciphertext []byte, attestationTime int64) ([]byte, error)

	CollectPartialSignatures(appID string, operators *peering.OperatorSetPeers, threshold int) (map[common.Address]types.G1Point, error)
	RetrieveSecretsWithOptions(appID string, opts *SecretsOptions) (*SecretsResult, error)
	GetEncryptedSecretsFromKMSNodesWithPartialSigs(operators *peering.OperatorSetPeers, req types.SecretsRequestV1, rsaPrivateKeyPEM []byte) ([]types.SecretsResponseV1, map[common.Address]types.G1Point, error)
}

// Compile-time assertion that Client implements KMSClient.
var _ KMSClient = (*Client)(nil)
