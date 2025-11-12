package web3signer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

// Test_ClientImplementsInterface verifies that Client implements IWeb3Signer
func Test_ClientImplementsInterface(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultConfig()

	client, err := NewClient(config, logger)
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// This will fail at compile time if Client doesn't implement IWeb3Signer
	var _ IWeb3Signer = client

	// Verify we can assign the client to an interface variable
	//nolint:gosimple,staticcheck
	var signer IWeb3Signer
	signer = client
	assert.NotNil(t, signer)
}

// Test_InterfaceMethodsMatch verifies that the interface has all expected methods
func Test_InterfaceMethodsMatch(t *testing.T) {
	// This test ensures that if new methods are added to Client,
	// they're also added to the interface (if they should be public)

	logger := zaptest.NewLogger(t)
	config := DefaultConfig()

	client, err := NewClient(config, logger)
	assert.NoError(t, err)

	// Create an interface variable
	var signer IWeb3Signer = client

	// Verify that we can call all interface methods (type checking)
	// These are compile-time checks, so they'll fail during build if methods don't match
	_ = signer.SetHttpClient
	_ = signer.EthAccounts
	_ = signer.EthSignTransaction
	_ = signer.EthSign
	_ = signer.EthSignTypedData
	_ = signer.ListPublicKeys
	_ = signer.Sign
	_ = signer.SignRaw
}

// Test_NewClientReturnsInterface verifies that NewClient can be used to return an interface
func Test_NewClientReturnsInterface(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultConfig()

	// Function that returns IWeb3Signer interface
	createSigner := func() (IWeb3Signer, error) {
		return NewClient(config, logger)
	}

	signer, err := createSigner()
	assert.NoError(t, err)
	assert.NotNil(t, signer)
}

// Test_NewWeb3SignerClientFromRemoteSignerConfigReturnsInterface verifies the config-based constructor
func Test_NewWeb3SignerClientFromRemoteSignerConfigReturnsInterface(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Test with nil config (uses defaults)
	var signer IWeb3Signer
	var err error

	signer, err = NewWeb3SignerClientFromRemoteSignerConfig(nil, logger)
	assert.NoError(t, err)
	assert.NotNil(t, signer)
}
