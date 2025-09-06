// FILE: logwisp/src/cmd/logwisp/status.go
package main

import (
	"context"
	"fmt"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/service"
)

// statusReporter periodically logs service status
func statusReporter(service *service.Service, ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Clean shutdown
			return
		case <-ticker.C:
			if service == nil {
				logger.Warn("msg", "Status reporter: service is nil",
					"component", "status_reporter")
				return
			}

			// Safely get stats with recovery
			func() {
				defer func() {
					if r := recover(); r != nil {
						logger.Error("msg", "Panic in status reporter",
							"component", "status_reporter",
							"panic", r)
					}
				}()

				stats := service.GetGlobalStats()
				totalPipelines, ok := stats["total_pipelines"].(int)
				if !ok || totalPipelines == 0 {
					logger.Warn("msg", "No active pipelines in status report",
						"component", "status_reporter")
					return
				}

				logger.Debug("msg", "Status report",
					"component", "status_reporter",
					"active_pipelines", totalPipelines,
					"time", time.Now().Format("15:04:05"))

				// Log individual pipeline status
				pipelines := stats["pipelines"].(map[string]any)
				for name, pipelineStats := range pipelines {
					logPipelineStatus(name, pipelineStats.(map[string]any))
				}
			}()
		}
	}
}

// logPipelineStatus logs the status of an individual pipeline
func logPipelineStatus(name string, stats map[string]any) {
	statusFields := []any{
		"msg", "Pipeline status",
		"pipeline", name,
	}

	// Add processing statistics
	if totalProcessed, ok := stats["total_processed"].(uint64); ok {
		statusFields = append(statusFields, "entries_processed", totalProcessed)
	}
	if totalFiltered, ok := stats["total_filtered"].(uint64); ok {
		statusFields = append(statusFields, "entries_filtered", totalFiltered)
	}

	// Add source count
	if sourceCount, ok := stats["source_count"].(int); ok {
		statusFields = append(statusFields, "sources", sourceCount)
	}

	// Add sink statistics
	if sinks, ok := stats["sinks"].([]map[string]any); ok {
		tcpConns := int64(0)
		httpConns := int64(0)

		for _, sink := range sinks {
			sinkType := sink["type"].(string)
			if activeConns, ok := sink["active_connections"].(int64); ok {
				switch sinkType {
				case "tcp":
					tcpConns += activeConns
				case "http":
					httpConns += activeConns
				}
			}
		}

		if tcpConns > 0 {
			statusFields = append(statusFields, "tcp_connections", tcpConns)
		}
		if httpConns > 0 {
			statusFields = append(statusFields, "http_connections", httpConns)
		}
	}

	logger.Debug(statusFields...)
}

// displayPipelineEndpoints logs the configured endpoints for a pipeline
func displayPipelineEndpoints(cfg config.PipelineConfig) {
	// Display sink endpoints
	for i, sinkCfg := range cfg.Sinks {
		switch sinkCfg.Type {
		case "tcp":
			if port, ok := sinkCfg.Options["port"].(int64); ok {
				logger.Info("msg", "TCP endpoint configured",
					"component", "main",
					"pipeline", cfg.Name,
					"sink_index", i,
					"port", port)

				// Display net limit info if configured
				if rl, ok := sinkCfg.Options["net_limit"].(map[string]any); ok {
					if enabled, ok := rl["enabled"].(bool); ok && enabled {
						logger.Info("msg", "TCP net limiting enabled",
							"pipeline", cfg.Name,
							"sink_index", i,
							"requests_per_second", rl["requests_per_second"],
							"burst_size", rl["burst_size"])
					}
				}
			}

		case "http":
			if port, ok := sinkCfg.Options["port"].(int64); ok {
				streamPath := "/transport"
				statusPath := "/status"
				if path, ok := sinkCfg.Options["stream_path"].(string); ok {
					streamPath = path
				}
				if path, ok := sinkCfg.Options["status_path"].(string); ok {
					statusPath = path
				}

				logger.Info("msg", "HTTP endpoints configured",
					"pipeline", cfg.Name,
					"sink_index", i,
					"stream_url", fmt.Sprintf("http://localhost:%d%s", port, streamPath),
					"status_url", fmt.Sprintf("http://localhost:%d%s", port, statusPath))

				// Display net limit info if configured
				if rl, ok := sinkCfg.Options["net_limit"].(map[string]any); ok {
					if enabled, ok := rl["enabled"].(bool); ok && enabled {
						logger.Info("msg", "HTTP net limiting enabled",
							"pipeline", cfg.Name,
							"sink_index", i,
							"requests_per_second", rl["requests_per_second"],
							"burst_size", rl["burst_size"],
							"limit_by", rl["limit_by"])
					}
				}
			}

		case "file":
			if dir, ok := sinkCfg.Options["directory"].(string); ok {
				name, _ := sinkCfg.Options["name"].(string)
				logger.Info("msg", "File sink configured",
					"pipeline", cfg.Name,
					"sink_index", i,
					"directory", dir,
					"name", name)
			}

		case "stdout", "stderr":
			logger.Info("msg", "Console sink configured",
				"pipeline", cfg.Name,
				"sink_index", i,
				"type", sinkCfg.Type)
		}
	}

	// Display authentication information
	if cfg.Auth != nil && cfg.Auth.Type != "none" {
		logger.Info("msg", "Authentication enabled",
			"pipeline", cfg.Name,
			"auth_type", cfg.Auth.Type)
	}

	// Display filter information
	if len(cfg.Filters) > 0 {
		logger.Info("msg", "Filters configured",
			"pipeline", cfg.Name,
			"filter_count", len(cfg.Filters))
	}
}