// FILE: src/internal/stream/noop_logger.go
package stream

// noopLogger implements gnet's Logger interface but discards everything
type noopLogger struct{}

func (n noopLogger) Debugf(format string, args ...any) {}
func (n noopLogger) Infof(format string, args ...any)  {}
func (n noopLogger) Warnf(format string, args ...any)  {}
func (n noopLogger) Errorf(format string, args ...any) {}
func (n noopLogger) Fatalf(format string, args ...any) {}