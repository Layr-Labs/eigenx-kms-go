package logger

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TestNewLogger_PreservesCallerSuppliedOptions guards against the copy/append
// regression where caller-supplied zap.Option args were silently dropped.
func TestNewLogger_PreservesCallerSuppliedOptions(t *testing.T) {
	var hookCalls atomic.Int32
	hook := zap.Hooks(func(zapcore.Entry) error {
		hookCalls.Add(1)
		return nil
	})

	log, err := NewLogger(&LoggerConfig{Debug: false}, hook)
	require.NoError(t, err)

	log.Info("trigger")

	require.Equal(t, int32(1), hookCalls.Load(), "caller-supplied zap.Option must be applied")
}

func TestNewLogger_DefaultCallerOption(t *testing.T) {
	log, err := NewLogger(&LoggerConfig{Debug: false})
	require.NoError(t, err)
	require.NotNil(t, log)
}
