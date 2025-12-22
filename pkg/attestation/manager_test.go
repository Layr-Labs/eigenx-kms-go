package attestation

import (
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAttestationMethod is a mock implementation for testing
type mockAttestationMethod struct {
	name        string
	shouldError bool
	claims      *types.AttestationClaims
}

func (m *mockAttestationMethod) Name() string {
	return m.name
}

func (m *mockAttestationMethod) Verify(request *AttestationRequest) (*types.AttestationClaims, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock verification error")
	}
	return m.claims, nil
}

func TestNewAttestationManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	assert.NotNil(t, manager)
	assert.Equal(t, 0, manager.MethodCount())
}

func TestRegisterMethod(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	mock := &mockAttestationMethod{
		name: "test-method",
		claims: &types.AttestationClaims{
			AppID:       "test-app",
			ImageDigest: "sha256:test",
		},
	}

	err := manager.RegisterMethod(mock)
	require.NoError(t, err)

	assert.Equal(t, 1, manager.MethodCount())
	assert.True(t, manager.HasMethod("test-method"))
}

func TestRegisterMethodNil(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	err := manager.RegisterMethod(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestRegisterMethodEmptyName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	mock := &mockAttestationMethod{name: ""}
	err := manager.RegisterMethod(mock)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty name")
}

func TestRegisterMethodReplacement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	mock1 := &mockAttestationMethod{name: "test", claims: &types.AttestationClaims{AppID: "app1"}}
	mock2 := &mockAttestationMethod{name: "test", claims: &types.AttestationClaims{AppID: "app2"}}

	require.NoError(t, manager.RegisterMethod(mock1))
	require.NoError(t, manager.RegisterMethod(mock2))

	assert.Equal(t, 1, manager.MethodCount())
}

func TestUnregisterMethod(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	mock := &mockAttestationMethod{name: "test-method"}
	require.NoError(t, manager.RegisterMethod(mock))

	assert.True(t, manager.HasMethod("test-method"))

	manager.UnregisterMethod("test-method")
	assert.False(t, manager.HasMethod("test-method"))
	assert.Equal(t, 0, manager.MethodCount())
}

func TestListMethods(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	mock1 := &mockAttestationMethod{name: "method1"}
	mock2 := &mockAttestationMethod{name: "method2"}

	require.NoError(t, manager.RegisterMethod(mock1))
	require.NoError(t, manager.RegisterMethod(mock2))

	methods := manager.ListMethods()
	assert.Len(t, methods, 2)
	assert.Contains(t, methods, "method1")
	assert.Contains(t, methods, "method2")
}

func TestVerifyWithMethod(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	expectedClaims := &types.AttestationClaims{
		AppID:       "test-app",
		ImageDigest: "sha256:test123",
	}

	mock := &mockAttestationMethod{
		name:   "test-method",
		claims: expectedClaims,
	}

	require.NoError(t, manager.RegisterMethod(mock))

	request := &AttestationRequest{
		Method:      "test-method",
		Attestation: []byte("test-attestation"),
		AppID:       "test-app",
	}

	claims, err := manager.VerifyWithMethod("test-method", request)
	require.NoError(t, err)
	assert.Equal(t, expectedClaims.AppID, claims.AppID)
	assert.Equal(t, expectedClaims.ImageDigest, claims.ImageDigest)
}

func TestVerifyWithMethodNotRegistered(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	request := &AttestationRequest{
		Method:      "nonexistent",
		Attestation: []byte("test"),
	}

	_, err := manager.VerifyWithMethod("nonexistent", request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered")
}

func TestVerifyWithMethodError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	mock := &mockAttestationMethod{
		name:        "error-method",
		shouldError: true,
	}

	require.NoError(t, manager.RegisterMethod(mock))

	request := &AttestationRequest{
		Method:      "error-method",
		Attestation: []byte("test"),
	}

	_, err := manager.VerifyWithMethod("error-method", request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestVerify(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	expectedClaims := &types.AttestationClaims{
		AppID:       "test-app",
		ImageDigest: "sha256:test123",
	}

	mock := &mockAttestationMethod{
		name:   "test-method",
		claims: expectedClaims,
	}

	require.NoError(t, manager.RegisterMethod(mock))

	request := &AttestationRequest{
		Method:      "test-method",
		Attestation: []byte("test-attestation"),
		AppID:       "test-app",
	}

	claims, err := manager.Verify(request)
	require.NoError(t, err)
	assert.Equal(t, expectedClaims.AppID, claims.AppID)
}

func TestVerifyNilRequest(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	_, err := manager.Verify(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestVerifyNoMethod(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	request := &AttestationRequest{
		Attestation: []byte("test"),
	}

	_, err := manager.Verify(request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not specified")
}

func TestConcurrentAccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	manager := NewAttestationManager(logger)

	// Test concurrent registration and verification
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			mock := &mockAttestationMethod{
				name: fmt.Sprintf("method-%d", id),
				claims: &types.AttestationClaims{
					AppID: fmt.Sprintf("app-%d", id),
				},
			}
			_ = manager.RegisterMethod(mock)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	assert.Equal(t, 10, manager.MethodCount())
}
