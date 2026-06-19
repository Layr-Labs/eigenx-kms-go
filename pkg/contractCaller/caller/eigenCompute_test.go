package caller

import (
	"testing"

	iappctl "github.com/Layr-Labs/eigenx-kms-go/pkg/middleware-bindings/IAppController"
	"github.com/stretchr/testify/assert"
)

// TestContractPolicyToTypes covers the v1.5.x tuple-array env mapping that the
// real-event ABI fixture does not exercise (its ContainerPolicy is empty).
func TestContractPolicyToTypes(t *testing.T) {
	p := iappctl.IAppControllerContainerPolicy{
		Args:        []string{"--flag"},
		CmdOverride: []string{"/bin/run"},
		Env: []iappctl.IAppControllerEnvVar{
			{Key: "FOO", Value: "bar"},
			{Key: "LOG_LEVEL", Value: "debug"},
		},
		EnvOverride:   []iappctl.IAppControllerEnvVar{{Key: "BAZ", Value: "qux"}},
		RestartPolicy: "always",
	}

	got := contractPolicyToTypes(p)

	assert.Equal(t, []string{"--flag"}, got.Args)
	assert.Equal(t, []string{"/bin/run"}, got.CmdOverride)
	assert.Equal(t, map[string]string{"FOO": "bar", "LOG_LEVEL": "debug"}, got.Env)
	assert.Equal(t, map[string]string{"BAZ": "qux"}, got.EnvOverride)
	assert.Equal(t, "always", got.RestartPolicy)
}

// TestContractPolicyToTypes_Empty mirrors the real-event fixture (all-empty
// policy) so the zero case is explicitly covered.
func TestContractPolicyToTypes_Empty(t *testing.T) {
	got := contractPolicyToTypes(iappctl.IAppControllerContainerPolicy{})
	assert.Empty(t, got.Env)
	assert.Empty(t, got.EnvOverride)
}
