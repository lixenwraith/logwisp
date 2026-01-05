package tcp

import (
	"time"
)

const (
	// Server lifecycle
	TCPServerStartTimeout    = 100 * time.Millisecond
	TCPServerShutdownTimeout = 2 * time.Second

	// Connection management
	TCPMaxConsecutiveWriteErrors = 3
	TCPMaxPort                   = 65535

	// Defaults
	DefaultTCPHost            = "0.0.0.0"
	DefaultTCPBufferSize      = 1000
	DefaultTCPWriteTimeoutMS  = 5000
	DefaultTCPKeepAlivePeriod = 30000
)