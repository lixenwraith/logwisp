// FILE: logwisp/src/internal/core/const.go
package core

import (
	"time"
)

const (
	MaxLogEntryBytes = 1024 * 1024

	MaxSessionTime = time.Minute * 30

	FileWatcherPollInterval = 100 * time.Millisecond

	HttpServerStartTimeout = 100 * time.Millisecond

	HttpServerShutdownTimeout = 2 * time.Second

	SessionDefaultMaxIdleTime = 30 * time.Minute

	SessionCleanupInterval = 5 * time.Minute

	NetLimitCleanupInterval = 30 * time.Second
	NetLimitCleanupTimeout  = 2 * time.Second
	NetLimitStaleTimeout    = 5 * time.Minute

	NetLimitPeriodicCleanupInterval = 1 * time.Minute

	ServiceStatsUpdateInterval = 1 * time.Second

	ShutdownTimeout = 10 * time.Second

	ConfigReloadTimeout = 30 * time.Second

	LoggerShutdownTimeout = 2 * time.Second

	ReloadWatchPollInterval = time.Second

	ReloadWatchDebounce = 500 * time.Millisecond

	ReloadWatchTimeout = 30 * time.Second
)