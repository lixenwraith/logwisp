// FILE: src/cmd/logwisp/status.go
package main

import (
	"fmt"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/service"
)

// statusReporter periodically logs service status
func statusReporter(service *service.Service) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := service.GetGlobalStats()
		totalStreams := stats["total_streams"].(int)
		if totalStreams == 0 {
			logger.Warn("msg", "No active streams in status report",
				"component", "status_reporter")
			return
		}

		// Log status at DEBUG level to avoid cluttering INFO logs
		logger.Debug("msg", "Status report",
			"component", "status_reporter",
			"active_streams", totalStreams,
			"time", time.Now().Format("15:04:05"))

		// Log individual stream status
		for name, streamStats := range stats["streams"].(map[string]interface{}) {
			logStreamStatus(name, streamStats.(map[string]interface{}))
		}
	}
}

// logStreamStatus logs the status of an individual stream
func logStreamStatus(name string, stats map[string]interface{}) {
	statusFields := []interface{}{
		"msg", "Stream status",
		"stream", name,
	}

	// Add monitor statistics
	if monitor, ok := stats["monitor"].(map[string]interface{}); ok {
		statusFields = append(statusFields,
			"watchers", monitor["active_watchers"],
			"entries", monitor["total_entries"])
	}

	// Add TCP server statistics
	if tcp, ok := stats["tcp"].(map[string]interface{}); ok && tcp["enabled"].(bool) {
		statusFields = append(statusFields, "tcp_conns", tcp["connections"])
	}

	// Add HTTP server statistics
	if http, ok := stats["http"].(map[string]interface{}); ok && http["enabled"].(bool) {
		statusFields = append(statusFields, "http_conns", http["connections"])
	}

	logger.Debug(statusFields...)
}

// displayStreamEndpoints logs the configured endpoints for a stream
func displayStreamEndpoints(cfg config.StreamConfig, routerMode bool) {
	// Display TCP endpoints
	if cfg.TCPServer != nil && cfg.TCPServer.Enabled {
		logger.Info("msg", "TCP endpoint configured",
			"component", "main",
			"transport", cfg.Name,
			"port", cfg.TCPServer.Port)

		if cfg.TCPServer.RateLimit != nil && cfg.TCPServer.RateLimit.Enabled {
			logger.Info("msg", "TCP rate limiting enabled",
				"transport", cfg.Name,
				"requests_per_second", cfg.TCPServer.RateLimit.RequestsPerSecond,
				"burst_size", cfg.TCPServer.RateLimit.BurstSize)
		}
	}

	// Display HTTP endpoints
	if cfg.HTTPServer != nil && cfg.HTTPServer.Enabled {
		if routerMode {
			logger.Info("msg", "HTTP endpoints configured",
				"transport", cfg.Name,
				"stream_path", fmt.Sprintf("/%s%s", cfg.Name, cfg.HTTPServer.StreamPath),
				"status_path", fmt.Sprintf("/%s%s", cfg.Name, cfg.HTTPServer.StatusPath))
		} else {
			logger.Info("msg", "HTTP endpoints configured",
				"transport", cfg.Name,
				"stream_url", fmt.Sprintf("http://localhost:%d%s", cfg.HTTPServer.Port, cfg.HTTPServer.StreamPath),
				"status_url", fmt.Sprintf("http://localhost:%d%s", cfg.HTTPServer.Port, cfg.HTTPServer.StatusPath))
		}

		if cfg.HTTPServer.RateLimit != nil && cfg.HTTPServer.RateLimit.Enabled {
			logger.Info("msg", "HTTP rate limiting enabled",
				"transport", cfg.Name,
				"requests_per_second", cfg.HTTPServer.RateLimit.RequestsPerSecond,
				"burst_size", cfg.HTTPServer.RateLimit.BurstSize,
				"limit_by", cfg.HTTPServer.RateLimit.LimitBy)
		}

		// Display authentication information
		if cfg.Auth != nil && cfg.Auth.Type != "none" {
			logger.Info("msg", "Authentication enabled",
				"transport", cfg.Name,
				"auth_type", cfg.Auth.Type)
		}
	}

	// Display filter information
	if len(cfg.Filters) > 0 {
		logger.Info("msg", "Filters configured",
			"transport", cfg.Name,
			"filter_count", len(cfg.Filters))
	}
}