package badger

import (
	"fmt"

	badgerdb "github.com/dgraph-io/badger/v3"
	"go.uber.org/zap"
)

// badgerLoggerAdapter adapts zap.Logger to badger.Logger interface
type badgerLoggerAdapter struct {
	logger *zap.Logger
}

// Ensure badgerLoggerAdapter implements badger.Logger
var _ badgerdb.Logger = (*badgerLoggerAdapter)(nil)

// Errorf logs an error message
func (b *badgerLoggerAdapter) Errorf(format string, args ...interface{}) {
	b.logger.Error(fmt.Sprintf(format, args...))
}

// Warningf logs a warning message
func (b *badgerLoggerAdapter) Warningf(format string, args ...interface{}) {
	b.logger.Warn(fmt.Sprintf(format, args...))
}

// Infof logs an info message
func (b *badgerLoggerAdapter) Infof(format string, args ...interface{}) {
	b.logger.Info(fmt.Sprintf(format, args...))
}

// Debugf logs a debug message
func (b *badgerLoggerAdapter) Debugf(format string, args ...interface{}) {
	b.logger.Debug(fmt.Sprintf(format, args...))
}
