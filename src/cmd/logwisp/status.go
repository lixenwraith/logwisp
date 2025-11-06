// FILE: logwisp/src/cmd/logwisp/status.go
package main

import (
	"context"
	"fmt"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/service"
)

// statusReporter is a goroutine that periodically logs the health and statistics of the service.
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

// displayPipelineEndpoints logs the configured source and sink endpoints for a pipeline at startup.
func displayPipelineEndpoints(cfg config.PipelineConfig) {
	// Display sink endpoints
	for i, sinkCfg := range cfg.Sinks {
		switch sinkCfg.Type {
		case "tcp":
			if sinkCfg.TCP != nil {
				host := "0.0.0.0"
				if sinkCfg.TCP.Host != "" {
					host = sinkCfg.TCP.Host
				}

				logger.Info("msg", "TCP endpoint configured",
					"component", "main",
					"pipeline", cfg.Name,
					"sink_index", i,
					"listen", fmt.Sprintf("%s:%d", host, sinkCfg.TCP.Port))

				// Display net limit info if configured
				if sinkCfg.TCP.NetLimit != nil && sinkCfg.TCP.NetLimit.Enabled {
					logger.Info("msg", "TCP net limiting enabled",
						"pipeline", cfg.Name,
						"sink_index", i,
						"requests_per_second", sinkCfg.TCP.NetLimit.RequestsPerSecond,
						"burst_size", sinkCfg.TCP.NetLimit.BurstSize)
				}
			}

		case "http":
			if sinkCfg.HTTP != nil {
				host := "0.0.0.0"
				if sinkCfg.HTTP.Host != "" {
					host = sinkCfg.HTTP.Host
				}

				streamPath := "/stream"
				statusPath := "/status"
				if sinkCfg.HTTP.StreamPath != "" {
					streamPath = sinkCfg.HTTP.StreamPath
				}
				if sinkCfg.HTTP.StatusPath != "" {
					statusPath = sinkCfg.HTTP.StatusPath
				}

				logger.Info("msg", "HTTP endpoints configured",
					"pipeline", cfg.Name,
					"sink_index", i,
					"listen", fmt.Sprintf("%s:%d", host, sinkCfg.HTTP.Port),
					"stream_url", fmt.Sprintf("http://%s:%d%s", host, sinkCfg.HTTP.Port, streamPath),
					"status_url", fmt.Sprintf("http://%s:%d%s", host, sinkCfg.HTTP.Port, statusPath))

				// Display net limit info if configured
				if sinkCfg.HTTP.NetLimit != nil && sinkCfg.HTTP.NetLimit.Enabled {
					logger.Info("msg", "HTTP net limiting enabled",
						"pipeline", cfg.Name,
						"sink_index", i,
						"requests_per_second", sinkCfg.HTTP.NetLimit.RequestsPerSecond,
						"burst_size", sinkCfg.HTTP.NetLimit.BurstSize)
				}
			}

		case "file":
			if sinkCfg.File != nil {
				logger.Info("msg", "File sink configured",
					"pipeline", cfg.Name,
					"sink_index", i,
					"directory", sinkCfg.File.Directory,
					"name", sinkCfg.File.Name)
			}

		case "console":
			if sinkCfg.Console != nil {
				logger.Info("msg", "Console sink configured",
					"pipeline", cfg.Name,
					"sink_index", i,
					"target", sinkCfg.Console.Target)
			}
		}
	}

	// Display source endpoints with host support
	for i, sourceCfg := range cfg.Sources {
		switch sourceCfg.Type {
		case "http":
			if sourceCfg.HTTP != nil {
				host := "0.0.0.0"
				if sourceCfg.HTTP.Host != "" {
					host = sourceCfg.HTTP.Host
				}

				displayHost := host
				if host == "0.0.0.0" {
					displayHost = "localhost"
				}

				ingestPath := "/ingest"
				if sourceCfg.HTTP.IngestPath != "" {
					ingestPath = sourceCfg.HTTP.IngestPath
				}

				logger.Info("msg", "HTTP source configured",
					"pipeline", cfg.Name,
					"source_index", i,
					"listen", fmt.Sprintf("%s:%d", host, sourceCfg.HTTP.Port),
					"ingest_url", fmt.Sprintf("http://%s:%d%s", displayHost, sourceCfg.HTTP.Port, ingestPath))
			}

		case "tcp":
			if sourceCfg.TCP != nil {
				host := "0.0.0.0"
				if sourceCfg.TCP.Host != "" {
					host = sourceCfg.TCP.Host
				}

				displayHost := host
				if host == "0.0.0.0" {
					displayHost = "localhost"
				}

				logger.Info("msg", "TCP source configured",
					"pipeline", cfg.Name,
					"source_index", i,
					"listen", fmt.Sprintf("%s:%d", host, sourceCfg.TCP.Port),
					"endpoint", fmt.Sprintf("%s:%d", displayHost, sourceCfg.TCP.Port))
			}

		case "directory":
			if sourceCfg.Directory != nil {
				logger.Info("msg", "Directory source configured",
					"pipeline", cfg.Name,
					"source_index", i,
					"path", sourceCfg.Directory.Path,
					"pattern", sourceCfg.Directory.Pattern)
			}

		case "stdin":
			logger.Info("msg", "Stdin source configured",
				"pipeline", cfg.Name,
				"source_index", i)
		}
	}

	// Display filter information
	if len(cfg.Filters) > 0 {
		logger.Info("msg", "Filters configured",
			"pipeline", cfg.Name,
			"filter_count", len(cfg.Filters))
	}
}

// logPipelineStatus logs the detailed status and statistics of an individual pipeline.
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