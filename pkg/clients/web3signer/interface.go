package web3signer

import (
	"context"
	"net/http"
)

// IWeb3Signer defines the interface for interacting with Web3Signer services.
// This interface abstracts the Web3Signer client implementation to allow for
// easier testing and potential alternative implementations.
type IWeb3Signer interface {
	// SetHttpClient allows setting a custom HTTP client for the Web3Signer client.
	// This is useful for testing or when custom HTTP client configuration is needed.
	SetHttpClient(client *http.Client)

	// EthAccounts returns a list of accounts available for signing.
	// This corresponds to the eth_accounts JSON-RPC method.
	EthAccounts(ctx context.Context) ([]string, error)

	// EthSignTransaction signs a transaction and returns the signature.
	// This corresponds to the eth_signTransaction JSON-RPC method.
	EthSignTransaction(ctx context.Context, from string, transaction map[string]interface{}) (string, error)

	// EthSign signs data with the specified account.
	// This corresponds to the eth_sign JSON-RPC method.
	EthSign(ctx context.Context, account string, data string) (string, error)

	// EthSignTypedData signs typed data with the specified account.
	// This corresponds to the eth_signTypedData JSON-RPC method.
	EthSignTypedData(ctx context.Context, account string, typedData interface{}) (string, error)

	// ListPublicKeys retrieves all available public keys from the Web3Signer service.
	// This is a convenience method that calls EthAccounts.
	ListPublicKeys(ctx context.Context) ([]string, error)

	// Sign signs data with the specified account using eth_sign.
	// This is a convenience method that calls EthSign.
	Sign(ctx context.Context, account string, data string) (string, error)

	// SignRaw performs raw ECDSA signing using the REST API endpoint.
	// This method signs raw data without Ethereum message prefixes, making it
	// compatible with generic ECDSA libraries like crypto-libs.
	// The identifier parameter is the signing key identifier (typically an address).
	SignRaw(ctx context.Context, identifier string, data []byte) (string, error)

	ReloadKeys(ctx context.Context) error

	ReloadKeysAndWaitForPublicKey(ctx context.Context, publicKey string) error
}

// Compile-time check to ensure Client implements IWeb3Signer
var _ IWeb3Signer = (*Client)(nil)
