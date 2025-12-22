package attestation

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
)

// AttestationManager manages multiple attestation methods and routes
// verification requests to the appropriate method.
type AttestationManager struct {
	methods map[string]AttestationMethod
	mu      sync.RWMutex
	logger  *slog.Logger
}

// NewAttestationManager creates a new attestation manager
func NewAttestationManager(logger *slog.Logger) *AttestationManager {
	return &AttestationManager{
		methods: make(map[string]AttestationMethod),
		logger:  logger,
	}
}

// RegisterMethod registers an attestation method with the manager.
// If a method with the same name already exists, it will be replaced.
func (m *AttestationManager) RegisterMethod(method AttestationMethod) error {
	if method == nil {
		return fmt.Errorf("attestation method is nil")
	}

	name := method.Name()
	if name == "" {
		return fmt.Errorf("attestation method has empty name")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.methods[name] = method
	m.logger.Info("Registered attestation method", "method", name)

	return nil
}

// UnregisterMethod removes an attestation method from the manager
func (m *AttestationManager) UnregisterMethod(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.methods, name)
	m.logger.Info("Unregistered attestation method", "method", name)
}

// HasMethod checks if a method is registered
func (m *AttestationManager) HasMethod(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.methods[name]
	return exists
}

// ListMethods returns the names of all registered methods
func (m *AttestationManager) ListMethods() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.methods))
	for name := range m.methods {
		names = append(names, name)
	}
	return names
}

// VerifyWithMethod verifies an attestation using the specified method.
// Returns an error if the method is not registered or verification fails.
func (m *AttestationManager) VerifyWithMethod(methodName string, request *AttestationRequest) (*types.AttestationClaims, error) {
	m.mu.RLock()
	method, exists := m.methods[methodName]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("attestation method '%s' is not registered. Available methods: %v", methodName, m.ListMethods())
	}

	m.logger.Debug("Verifying attestation", "method", methodName, "app_id", request.AppID)

	claims, err := method.Verify(request)
	if err != nil {
		m.logger.Warn("Attestation verification failed", "method", methodName, "error", err)
		return nil, fmt.Errorf("verification failed with method '%s': %w", methodName, err)
	}

	m.logger.Info("Attestation verified successfully", "method", methodName, "app_id", claims.AppID, "image_digest", claims.ImageDigest)
	return claims, nil
}

// Verify is a convenience method that extracts the method name from the request
// and calls VerifyWithMethod. If no method is specified in the request, returns an error.
func (m *AttestationManager) Verify(request *AttestationRequest) (*types.AttestationClaims, error) {
	if request == nil {
		return nil, fmt.Errorf("attestation request is nil")
	}

	if request.Method == "" {
		return nil, fmt.Errorf("attestation method not specified in request")
	}

	return m.VerifyWithMethod(request.Method, request)
}

// MethodCount returns the number of registered methods
func (m *AttestationManager) MethodCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.methods)
}
