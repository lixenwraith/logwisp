package core

import (
	"time"
)

const (
	MaxLogEntryBytes = 1024 * 1024

	FileWatcherPollInterval = 100 * time.Millisecond

	SessionDefaultMaxIdleTime = 30 * time.Minute

	SessionCleanupInterval = 5 * time.Minute

	// Idle keepalive for a served stream. Well under SessionDefaultMaxIdleTime,
	// so a quiet stream refreshes its session long before the sweep expires it.
	StreamKeepaliveInterval = 15 * time.Second

	ServiceStatsUpdateInterval = 1 * time.Second

	ShutdownTimeout = 10 * time.Second

	ConfigReloadTimeout = 30 * time.Second

	LoggerShutdownTimeout = 2 * time.Second

	ReloadWatchPollInterval = time.Second

	ReloadWatchDebounce = 500 * time.Millisecond

	ReloadWatchTimeout = 30 * time.Second
)