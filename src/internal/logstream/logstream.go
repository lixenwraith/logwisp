// FILE: src/internal/logstream/logstream.go
package logstream

import (
	"context"
	"fmt"
	"sync"
	"time"

	"logwisp/src/internal/config"
)

func (ls *LogStream) Shutdown() {
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
}

func (ls *LogStream) GetStats() map[string]interface{} {
	monStats := ls.Monitor.GetStats()

	stats := map[string]interface{}{
		"name":           ls.Name,
		"uptime_seconds": int(time.Since(ls.Stats.StartTime).Seconds()),
		"monitor":        monStats,
	}

	if ls.TCPServer != nil {
		currentConnections := ls.TCPServer.GetActiveConnections()

		stats["tcp"] = map[string]interface{}{
			"enabled":     true,
			"port":        ls.Config.TCPServer.Port,
			"connections": currentConnections, // Use current value
		}
	}

	if ls.HTTPServer != nil {
		currentConnections := ls.HTTPServer.GetActiveConnections()

		stats["http"] = map[string]interface{}{
			"enabled":     true,
			"port":        ls.Config.HTTPServer.Port,
			"connections": currentConnections, // Use current value
			"stream_path": ls.Config.HTTPServer.StreamPath,
			"status_path": ls.Config.HTTPServer.StatusPath,
		}
	}

	return stats
}

func (ls *LogStream) UpdateTargets(targets []config.MonitorTarget) error {
	// Clear existing targets
	for _, watcher := range ls.Monitor.GetActiveWatchers() {
		ls.Monitor.RemoveTarget(watcher.Path)
	}

	// Add new targets
	for _, target := range targets {
		if err := ls.Monitor.AddTarget(target.Path, target.Pattern, target.IsFile); err != nil {
			return err
		}
	}

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
						fmt.Printf("[STATS DEBUG] %s TCP: %d -> %d\n",
							ls.Name, oldTCP, ls.Stats.TCPConnections)
					}
				}
				if ls.HTTPServer != nil {
					oldHTTP := ls.Stats.HTTPConnections
					ls.Stats.HTTPConnections = ls.HTTPServer.GetActiveConnections()
					if oldHTTP != ls.Stats.HTTPConnections {
						// This debug should now show changes
						fmt.Printf("[STATS DEBUG] %s HTTP: %d -> %d\n",
							ls.Name, oldHTTP, ls.Stats.HTTPConnections)
					}
				}
			}
		}
	}()
}