package http

import "time"

const (
	HttpServerStartTimeout    = 100 * time.Millisecond
	HttpServerShutdownTimeout = 2 * time.Second
)