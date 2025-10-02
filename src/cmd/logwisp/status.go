// FILE: logwisp/src/cmd/logwisp/status.go
package main

import (
	"context"
	"fmt"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/service"
)

// Periodically logs service status
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

// Logs the status of an individual pipeline
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

// Logs the configured endpoints for a pipeline
func displayPipelineEndpoints(cfg config.PipelineConfig) {
	// Display sink endpoints
	for i, sinkCfg := range cfg.Sinks {
		switch sinkCfg.Type {
		case "tcp":
			if port, ok := sinkCfg.Options["port"].(int64); ok {
				host := "0.0.0.0" // Get host or default to 0.0.0.0
				if h, ok := sinkCfg.Options["host"].(string); ok && h != "" {
					host = h
				}

				logger.Info("msg", "TCP endpoint configured",
					"component", "main",
					"pipeline", cfg.Name,
					"sink_index", i,
					"listen", fmt.Sprintf("%s:%d", host, port))

				// Display net limit info if configured
				if nl, ok := sinkCfg.Options["net_limit"].(map[string]any); ok {
					if enabled, ok := nl["enabled"].(bool); ok && enabled {
						logger.Info("msg", "TCP net limiting enabled",
							"pipeline", cfg.Name,
							"sink_index", i,
							"requests_per_second", nl["requests_per_second"],
							"burst_size", nl["burst_size"])
					}
				}
			}

		case "http":
			if port, ok := sinkCfg.Options["port"].(int64); ok {
				host := "0.0.0.0"
				if h, ok := sinkCfg.Options["host"].(string); ok && h != "" {
					host = h
				}

				streamPath := "/stream"
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
					"listen", fmt.Sprintf("%s:%d", host, port),
					"stream_url", fmt.Sprintf("http://%s:%d%s", host, port, streamPath),
					"status_url", fmt.Sprintf("http://%s:%d%s", host, port, statusPath))

				// Display net limit info if configured
				if nl, ok := sinkCfg.Options["net_limit"].(map[string]any); ok {
					if enabled, ok := nl["enabled"].(bool); ok && enabled {
						logger.Info("msg", "HTTP net limiting enabled",
							"pipeline", cfg.Name,
							"sink_index", i,
							"requests_per_second", nl["requests_per_second"],
							"burst_size", nl["burst_size"])
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

		case "console":
			if target, ok := sinkCfg.Options["target"].(string); ok {
				logger.Info("msg", "Console sink configured",
					"pipeline", cfg.Name,
					"sink_index", i,
					"target", target)
			}
		}
	}

	// Display source endpoints with host support
	for i, sourceCfg := range cfg.Sources {
		switch sourceCfg.Type {
		case "http":
			if port, ok := sourceCfg.Options["port"].(int64); ok {
				host := "0.0.0.0"
				if h, ok := sourceCfg.Options["host"].(string); ok && h != "" {
					host = h
				}

				displayHost := host
				if host == "0.0.0.0" {
					displayHost = "localhost"
				}

				ingestPath := "/ingest"
				if path, ok := sourceCfg.Options["ingest_path"].(string); ok {
					ingestPath = path
				}

				logger.Info("msg", "HTTP source configured",
					"pipeline", cfg.Name,
					"source_index", i,
					"listen", fmt.Sprintf("%s:%d", host, port),
					"ingest_url", fmt.Sprintf("http://%s:%d%s", displayHost, port, ingestPath))
			}

		case "tcp":
			if port, ok := sourceCfg.Options["port"].(int64); ok {
				host := "0.0.0.0"
				if h, ok := sourceCfg.Options["host"].(string); ok && h != "" {
					host = h
				}

				displayHost := host
				if host == "0.0.0.0" {
					displayHost = "localhost"
				}

				logger.Info("msg", "TCP source configured",
					"pipeline", cfg.Name,
					"source_index", i,
					"listen", fmt.Sprintf("%s:%d", host, port),
					"endpoint", fmt.Sprintf("%s:%d", displayHost, port))
			}

			// TODO: missing other types of source, to be added
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