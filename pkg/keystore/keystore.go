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
	poisoned       map[int64]struct{}
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

// GetActiveVersion returns the currently active key version.
//
// The active pointer is normally never set to a poisoned version: on a
// successful demotion the rollback re-points active to a non-poisoned target
// (see the auto-heal / rollback path). The ONE exception is the floor case in
// performRollback (autoheal.go): when no non-poisoned version below the poisoned
// one exists — or the chosen target is missing from the persisted set — the
// active pointer intentionally stays on the poisoned version. That is deliberate:
// rotation is halted pending manual intervention (never auto re-DKG), but decrypt
// must keep being served, so this accessor returns activeVersion unchanged and
// does NOT filter on the poisoned set. Silently returning nil for a poisoned
// active would break serving on the floor path.
func (ks *KeyStore) GetActiveVersion() *types.KeyShareVersion {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	return ks.activeVersion
}

// MarkPoisoned records a version as poisoned; poisoned versions are excluded
// from all version-resolution accessors.
func (ks *KeyStore) MarkPoisoned(version int64) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.poisoned == nil {
		ks.poisoned = map[int64]struct{}{}
	}
	ks.poisoned[version] = struct{}{}
}

// IsPoisoned reports whether a version has been marked poisoned.
func (ks *KeyStore) IsPoisoned(version int64) bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	_, ok := ks.poisoned[version]
	return ok
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

	// Defense-in-depth for the "active is never poisoned" invariant: refuse to
	// promote a poisoned pending version. Read the poisoned set inline under the
	// Lock already held here; do NOT call IsPoisoned (which takes its own RLock) —
	// that would be lock re-entrancy (matches GetPrivateShareForVersion /
	// GetKeyVersionAtTime).
	if _, bad := ks.poisoned[ks.pendingVersion.Version]; bad {
		return fmt.Errorf("cannot activate poisoned pending version %d", ks.pendingVersion.Version)
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

// GetPrivateShareForVersion returns a copy of the private share for the EXACT version.
//
// Unlike GetKeyVersionAtTime, this does NOT fall back to a nearest/earlier version: it
// errors if the exact version is absent. Reshare source-version agreement (docs/012)
// depends on this — a lagging node that asked for the quorum's version and silently got
// its own stale version back would deal from a mismatched-source polynomial and re-corrupt
// the master secret. Callers must treat the error as "I must catch up, not deal."
func (ks *KeyStore) GetPrivateShareForVersion(version int64) (*fr.Element, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Read the poisoned set inline under the RLock already held here; do NOT call
	// IsPoisoned (which takes its own RLock) — that would be lock re-entrancy.
	if _, bad := ks.poisoned[version]; bad {
		return nil, fmt.Errorf("key version %d is poisoned and must not be used", version)
	}
	for _, v := range ks.keyVersions {
		if v.Version == version {
			if v.PrivateShare == nil {
				return nil, fmt.Errorf("key version %d has no private share", version)
			}
			return new(fr.Element).Set(v.PrivateShare), nil
		}
	}
	return nil, fmt.Errorf("no key version %d in keystore", version)
}

// GetKeyVersionAtTime returns the key version that was active at the given timestamp.
// It returns the latest version whose Version (block timestamp) is <= the given timestamp.
func (ks *KeyStore) GetKeyVersionAtTime(timestamp int64) *types.KeyShareVersion {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	var best *types.KeyShareVersion
	for _, version := range ks.keyVersions {
		// Skip poisoned versions so resolution falls back to the next-lower good
		// version. Read the poisoned set inline under the RLock already held here;
		// do NOT call IsPoisoned (which takes its own RLock) — lock re-entrancy.
		if _, bad := ks.poisoned[version.Version]; bad {
			continue
		}
		if version.Version <= timestamp {
			if best == nil || version.Version > best.Version {
				best = version
			}
		}
	}

	return best
}
