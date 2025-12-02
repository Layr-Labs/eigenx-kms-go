package localKeyGenerator

import (
	"context"
	"fmt"
	"sync"

	"github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	"github.com/Layr-Labs/eigenx-kms-go/internal/keyGenerator"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// keyEntry stores both the private key and metadata for a key
type keyEntry struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey // Public key is needed for signing
	keyName    string
	aliasName  string
	address    string
}

type LocalKeyGenerator struct {
	logger   *zap.Logger
	keyStore map[string]*keyEntry // keyId -> keyEntry
	mu       sync.RWMutex         // protect concurrent access to keyStore
}

func NewLocalKeyGenerator(logger *zap.Logger) *LocalKeyGenerator {
	return &LocalKeyGenerator{
		logger:   logger,
		keyStore: make(map[string]*keyEntry),
	}
}

func (l *LocalKeyGenerator) GenerateECDSAKey(ctx context.Context, keyName string, aliasName string) (*keyGenerator.GeneratedECDSAKey, error) {
	// Generate a new ECDSA key pair using secp256k1 curve (Ethereum standard)
	privateKey, publicKey, err := ecdsa.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Convert public key to Ethereum address
	address, err := privateKey.DeriveAddress()
	if err != nil {
		return nil, fmt.Errorf("failed to derive Ethereum address from public key: %w", err)
	}

	// Generate a unique key ID
	keyId := fmt.Sprintf("local-key-%s", uuid.New().String())

	// Store the key in our keyStore
	l.mu.Lock()
	l.keyStore[keyId] = &keyEntry{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyName:    keyName,
		aliasName:  aliasName,
		address:    address.String(),
	}
	l.mu.Unlock()

	l.logger.Info("Generated local ECDSA key",
		zap.String("keyName", keyName),
		zap.String("aliasName", aliasName),
		zap.String("keyId", keyId),
		zap.String("address", address.String()),
	)

	return &keyGenerator.GeneratedECDSAKey{
		PublicKey: publicKey,
		Address:   address.String(),
		KeyId:     keyId,
	}, nil
}

func (l *LocalKeyGenerator) GetECDSAKeyById(ctx context.Context, keyId string) (*keyGenerator.GeneratedECDSAKey, error) {
	l.mu.RLock()
	entry, exists := l.keyStore[keyId]
	l.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("key with ID %s not found", keyId)
	}

	l.logger.Debug("Retrieved ECDSA key by ID",
		zap.String("keyId", keyId),
		zap.String("address", entry.address),
	)

	return &keyGenerator.GeneratedECDSAKey{
		PublicKey: entry.publicKey,
		Address:   entry.address,
		KeyId:     keyId,
	}, nil
}

func (l *LocalKeyGenerator) SignMessage(ctx context.Context, keyId string, message []byte) ([]byte, error) {
	l.mu.RLock()
	entry, exists := l.keyStore[keyId]
	l.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("key with ID %s not found", keyId)
	}

	// If message is already 32 bytes (likely a hash), use it directly
	// Otherwise, hash it first
	// var messageToSign []byte
	// if len(message) == 32 {
	// 	messageToSign = message
	// } else {
	// 	// Hash the message using Keccak256 (Ethereum standard)
	// 	hash := crypto.Keccak256Hash(message)
	// 	messageToSign = hash.Bytes()
	// }

	// Sign the message using the private key
	signature, err := entry.privateKey.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message with key %s: %w", keyId, err)
	}

	l.logger.Debug("Signed message with ECDSA key",
		zap.String("keyId", keyId),
		zap.Int("originalMessageLen", len(message)),
		zap.Int("signatureLen", len(signature.Bytes())),
	)

	return signature.Bytes(), nil
}

// Helper functions for testing

// LoadPrivateKey loads a pre-existing private key into the key store.
// This is useful for testing when you need to use a specific key.
func (l *LocalKeyGenerator) LoadPrivateKey(keyId string, privateKey *ecdsa.PrivateKey, keyName string, aliasName string) error {
	if privateKey == nil {
		return fmt.Errorf("private key cannot be nil")
	}

	address, err := privateKey.DeriveAddress()
	if err != nil {
		return fmt.Errorf("failed to derive Ethereum address from private key: %w", err)
	}

	publicKey := privateKey.Public()

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.keyStore[keyId]; exists {
		return fmt.Errorf("key with ID %s already exists", keyId)
	}

	l.keyStore[keyId] = &keyEntry{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyName:    keyName,
		aliasName:  aliasName,
		address:    address.String(),
	}

	l.logger.Info("Loaded private key into store",
		zap.String("keyId", keyId),
		zap.String("keyName", keyName),
		zap.String("aliasName", aliasName),
		zap.String("address", address.String()),
	)

	return nil
}

// LoadPrivateKeyFromHex loads a private key from a hex string into the key store.
// The hex string can optionally start with "0x".
func (l *LocalKeyGenerator) LoadPrivateKeyFromHex(keyId string, privateKeyHex string, keyName string, aliasName string) error {
	privateKey, err := ecdsa.NewPrivateKeyFromHexString(privateKeyHex)
	if err != nil {
		return fmt.Errorf("failed to parse private key from hex: %w", err)
	}

	return l.LoadPrivateKey(keyId, privateKey, keyName, aliasName)
}

// GenerateAndLoadKey generates a new key and returns both the key ID and the private key.
// This is useful for testing when you need access to the private key.
func (l *LocalKeyGenerator) GenerateAndLoadKey(keyName string, aliasName string) error {
	privateKey, _, err := ecdsa.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	keyId := fmt.Sprintf("local-key-%s", uuid.New().String())
	return l.LoadPrivateKey(keyId, privateKey, keyName, aliasName)
}

// GetKeyCount returns the number of keys in the store.
// This is useful for testing.
func (l *LocalKeyGenerator) GetKeyCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.keyStore)
}

// ClearKeys removes all keys from the store.
// This is useful for testing cleanup.
func (l *LocalKeyGenerator) ClearKeys() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keyStore = make(map[string]*keyEntry)
	l.logger.Info("Cleared all keys from store")
}

// KeyExists checks if a key with the given ID exists in the store.
func (l *LocalKeyGenerator) KeyExists(keyId string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, exists := l.keyStore[keyId]
	return exists
}

func (l *LocalKeyGenerator) GetKeyByAlias(alias string) *keyEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for _, entry := range l.keyStore {
		if entry.aliasName == alias {
			return entry
		}
	}
	return nil
}
