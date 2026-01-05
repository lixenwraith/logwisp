package http

import "time"

const (
	// Server lifecycle
	HttpServerStartTimeout    = 100 * time.Millisecond
	HttpServerShutdownTimeout = 2 * time.Second

	// Defaults
	DefaultHTTPHost       = "0.0.0.0"
	DefaultHTTPBufferSize = 1000
	DefaultHTTPStreamPath = "/stream"
	DefaultHTTPStatusPath = "/status"
	HTTPMaxPort           = 65535
)