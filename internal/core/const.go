package core

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Network is what a listener on, or a dialer to, host uses: tcp4 for an IPv4
// literal or "" (the IPv4 wildcard, as the default 0.0.0.0), tcp6 for an IPv6
// literal, which Go binds IPv6-only, and tcp for a hostname, which resolves.
func Network(host string) (string, error) {
	addr, err := netip.ParseAddr(host)
	switch {
	case host == "" || err == nil && addr.Is4():
		return "tcp4", nil
	case err == nil && addr.Is4In6():
		// tcp6 refuses it at bind or dial, long after the config loaded
		return "", fmt.Errorf("%q is an IPv4-mapped address; write it as IPv4", host)
	case err == nil:
		return "tcp6", nil
	case strings.ContainsAny(host, "[]:"):
		return "", fmt.Errorf("%q is neither an address nor a hostname (write an IPv6 address without brackets or port)", host)
	}
	return "tcp", nil
}

const (
	MaxLogEntryBytes = 1024 * 1024

	FileWatcherPollInterval = 100 * time.Millisecond

	SessionDefaultMaxIdleTime = 30 * time.Minute

	SessionCleanupInterval = 5 * time.Minute

	// Idle keepalive for a served stream. Well under SessionDefaultMaxIdleTime,
	// so a quiet stream refreshes its session long before the sweep expires it.
	StreamKeepaliveInterval = 15 * time.Second

	ServiceStatsUpdateInterval = 1 * time.Second

	// Bounds the flush of a network sink's queues at Stop
	SinkFlushTimeout = 2 * time.Second

	ConfigReloadTimeout = 30 * time.Second

	LoggerShutdownTimeout = 2 * time.Second

	ReloadWatchPollInterval = time.Second

	ReloadWatchDebounce = 500 * time.Millisecond

	ReloadWatchTimeout = 30 * time.Second
)
