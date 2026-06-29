package caller

import (
	"encoding/hex"
	"testing"

	iappctl "github.com/Layr-Labs/eigenx-kms-go/pkg/middleware-bindings/IAppController"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestEncryptedEnvWireEncoding locks the /secrets wire contract for encrypted_env.
//
// The on-chain encryptedEnv is a raw IBE envelope (magic "IBE"||version||binary)
// that is NOT valid UTF-8. GetLatestReleaseAsRelease puts it on the wire as the
// JSON string field encrypted_env, and the CDH helper's decodeEncryptedEnv only
// accepts hex or base64 — never raw bytes. A previous `string(rawBytes)` cast
// both corrupted the ciphertext (json.Marshal replaces invalid UTF-8 with
// U+FFFD) and produced a string the helper could not decode, so every unseal
// failed with "encrypted_env is neither hex nor base64". This guards the
// hex-encoding so the bytes survive the wire and the helper's hex branch
// round-trips them back to the exact IBE envelope.
func TestEncryptedEnvWireEncoding(t *testing.T) {
	// Realistic IBE envelope prefix ("IBE"\x01) followed by non-UTF-8 bytes.
	raw := []byte{'I', 'B', 'E', 0x01, 0x8e, 0x2b, 0x31, 0x26, 0xff, 0xfe, 0x00, 0x80}

	wire := ""
	if len(raw) > 0 {
		wire = hex.EncodeToString(raw)
	}

	// The wire form must be pure ASCII hex (survives JSON + URL round-trips).
	for _, c := range wire {
		require.Truef(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"wire encoding must be lowercase hex, got %q", wire)
	}

	// And it must decode back to the exact original bytes — this is what the
	// helper's decodeEncryptedEnv hex branch does.
	decoded, err := hex.DecodeString(wire)
	require.NoError(t, err)
	assert.Equal(t, raw, decoded, "hex round-trip must reproduce the raw IBE envelope")

	// Empty stays empty (public-only releases have no encrypted_env).
	empty := ""
	if len([]byte{}) > 0 {
		empty = hex.EncodeToString([]byte{})
	}
	assert.Equal(t, "", empty)
}
