package keystore

import (
	"fmt"
	"sync"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// KeyStore manages key versions and provides thread-safe access
type KeyStore struct {
	mu sync.RWMutex

	keyVersions    []*types.KeyShareVersion
	activeVersion  *types.KeyShareVersion
	pendingVersion *types.KeyShareVersion
}

// NewKeyStore creates a new key store
func NewKeyStore() *KeyStore {
	return &KeyStore{
		keyVersions: make([]*types.KeyShareVersion, 0),
	}
}

// AddVersion adds a new key version
func (ks *KeyStore) AddVersion(version *types.KeyShareVersion) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.keyVersions = append(ks.keyVersions, version)
	if version.IsActive {
		if ks.activeVersion != nil {
			ks.activeVersion.IsActive = false
		}
		ks.activeVersion = version
	}
}

// SetActiveVersion sets the active key version
func (ks *KeyStore) SetActiveVersion(version *types.KeyShareVersion) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.activeVersion != nil {
		ks.activeVersion.IsActive = false
	}
	version.IsActive = true
	ks.activeVersion = version
}

// GetActiveVersion returns the currently active key version
func (ks *KeyStore) GetActiveVersion() *types.KeyShareVersion {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	return ks.activeVersion
}

// GetActivePrivateShare returns the active private key share
func (ks *KeyStore) GetActivePrivateShare() (*fr.Element, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.activeVersion == nil {
		return nil, fmt.Errorf("no active key version")
	}
	return new(fr.Element).Set(ks.activeVersion.PrivateShare), nil
}

// SetPendingVersion sets a pending version during reshare
func (ks *KeyStore) SetPendingVersion(version *types.KeyShareVersion) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.pendingVersion = version
}

// GetPendingVersion returns the pending version
func (ks *KeyStore) GetPendingVersion() *types.KeyShareVersion {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	return ks.pendingVersion
}

// ActivatePendingVersion activates the pending version
func (ks *KeyStore) ActivatePendingVersion() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.pendingVersion == nil {
		return fmt.Errorf("no pending version to activate")
	}

	ks.pendingVersion.IsActive = true
	if ks.activeVersion != nil {
		ks.activeVersion.IsActive = false
	}
	ks.activeVersion = ks.pendingVersion
	ks.keyVersions = append(ks.keyVersions, ks.pendingVersion)
	ks.pendingVersion = nil

	return nil
}

// ClearPendingVersion clears the pending version
func (ks *KeyStore) ClearPendingVersion() {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.pendingVersion = nil
}

// GetKeyVersionAtTime returns the key version for a specific time
func (ks *KeyStore) GetKeyVersionAtTime(timestamp int64, reshareFrequency int64) *types.KeyShareVersion {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	epoch := timestamp / reshareFrequency

	for _, version := range ks.keyVersions {
		if version.Version == epoch {
			return version
		}
	}

	return ks.activeVersion
}