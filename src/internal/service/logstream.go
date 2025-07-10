// FILE: src/internal/service/logstream.go
package service

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/filter"
	"logwisp/src/internal/monitor"
	"logwisp/src/internal/transport"

	"github.com/lixenwraith/log"
)

type LogStream struct {
	Name        string
	Config      config.StreamConfig
	Monitor     monitor.Monitor
	FilterChain *filter.Chain
	TCPServer   *transport.TCPStreamer
	HTTPServer  *transport.HTTPStreamer
	Stats       *StreamStats
	logger      *log.Logger

	ctx    context.Context
	cancel context.CancelFunc
}

type StreamStats struct {
	StartTime          time.Time
	MonitorStats       monitor.Stats
	TCPConnections     int32
	HTTPConnections    int32
	TotalBytesServed   uint64
	TotalEntriesServed uint64
	FilterStats        map[string]any
}

func (ls *LogStream) Shutdown() {
	ls.logger.Info("msg", "Shutting down stream",
		"component", "logstream",
		"stream", ls.Name)

	// Stop servers first
	var wg sync.WaitGroup

	if ls.TCPServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ls.TCPServer.Stop()
		}()
	}

	if ls.HTTPServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ls.HTTPServer.Stop()
		}()
	}

	// Cancel context
	ls.cancel()

	// Wait for servers
	wg.Wait()

	// Stop monitor
	ls.Monitor.Stop()

	ls.logger.Info("msg", "Stream shutdown complete",
		"component", "logstream",
		"stream", ls.Name)
}

func (ls *LogStream) GetStats() map[string]any {
	monStats := ls.Monitor.GetStats()

	stats := map[string]any{
		"name":           ls.Name,
		"uptime_seconds": int(time.Since(ls.Stats.StartTime).Seconds()),
		"monitor":        monStats,
	}

	if ls.FilterChain != nil {
		stats["filters"] = ls.FilterChain.GetStats()
	}

	if ls.TCPServer != nil {
		currentConnections := ls.TCPServer.GetActiveConnections()

		stats["tcp"] = map[string]interface{}{
			"enabled":     true,
			"port":        ls.Config.TCPServer.Port,
			"connections": currentConnections,
		}
	}

	if ls.HTTPServer != nil {
		currentConnections := ls.HTTPServer.GetActiveConnections()

		stats["http"] = map[string]interface{}{
			"enabled":     true,
			"port":        ls.Config.HTTPServer.Port,
			"connections": currentConnections,
			"stream_path": ls.Config.HTTPServer.StreamPath,
			"status_path": ls.Config.HTTPServer.StatusPath,
		}
	}

	return stats
}

func (ls *LogStream) UpdateTargets(targets []config.MonitorTarget) error {
	// Validate new targets first
	validatedTargets := make([]config.MonitorTarget, 0, len(targets))
	for _, target := range targets {
		// Basic validation
		absPath, err := filepath.Abs(target.Path)
		if err != nil {
			ls.logger.Error("msg", "Invalid target path",
				"component", "logstream",
				"stream", ls.Name,
				"path", target.Path,
				"error", err)
			return fmt.Errorf("invalid target path %s: %w", target.Path, err)
		}
		target.Path = absPath
		validatedTargets = append(validatedTargets, target)
	}

	// Get current watchers
	oldWatchers := ls.Monitor.GetActiveWatchers()

	// Add new targets
	for _, target := range validatedTargets {
		if err := ls.Monitor.AddTarget(target.Path, target.Pattern, target.IsFile); err != nil {
			ls.logger.Error("msg", "Failed to add monitor target - rolling back",
				"component", "logstream",
				"stream", ls.Name,
				"target", target.Path,
				"pattern", target.Pattern,
				"error", err)
			// Rollback: restore old watchers
			for _, watcher := range oldWatchers {
				// Best effort restoration
				ls.Monitor.AddTarget(watcher.Path, "", false)
			}
			return fmt.Errorf("failed to add target %s: %w", target.Path, err)
		}
	}

	// Only remove old targets after new ones are successfully added
	for _, watcher := range oldWatchers {
		ls.Monitor.RemoveTarget(watcher.Path)
	}

	ls.logger.Info("msg", "Updated monitor targets",
		"component", "logstream",
		"stream", ls.Name,
		"old_count", len(oldWatchers),
		"new_count", len(validatedTargets))

	return nil
}

func (ls *LogStream) startStatsUpdater(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Update cached values
				if ls.TCPServer != nil {
					oldTCP := ls.Stats.TCPConnections
					ls.Stats.TCPConnections = ls.TCPServer.GetActiveConnections()
					if oldTCP != ls.Stats.TCPConnections {
						// This debug should now show changes
						ls.logger.Debug("msg", "TCP connection count changed",
							"component", "logstream",
							"stream", ls.Name,
							"old", oldTCP,
							"new", ls.Stats.TCPConnections)
					}
				}
				if ls.HTTPServer != nil {
					oldHTTP := ls.Stats.HTTPConnections
					ls.Stats.HTTPConnections = ls.HTTPServer.GetActiveConnections()
					if oldHTTP != ls.Stats.HTTPConnections {
						// This debug should now show changes
						ls.logger.Debug("msg", "HTTP connection count changed",
							"component", "logstream",
							"stream", ls.Name,
							"old", oldHTTP,
							"new", ls.Stats.HTTPConnections)
					}
				}
			}
		}
	}()
}