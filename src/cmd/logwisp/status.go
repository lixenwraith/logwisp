// FILE: logwisp/src/cmd/logwisp/status.go
package main

import (
	"context"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/service"
)

// statusReporter is a goroutine that periodically logs the health and statistics of the service
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

// displayPipelineEndpoints logs the configured source and sink endpoints for a pipeline at startup
func displayPipelineEndpoints(cfg config.PipelineConfig) {
	// Display sink endpoints
	for i, sinkCfg := range cfg.Sinks {
		switch sinkCfg.Type {
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
		case "file":
			if sourceCfg.File != nil {
				logger.Info("msg", "File source configured",
					"pipeline", cfg.Name,
					"source_index", i,
					"path", sourceCfg.File.Directory,
					"pattern", sourceCfg.File.Pattern)
			}

		case "console":
			logger.Info("msg", "Console source configured",
				"pipeline", cfg.Name,
				"source_index", i)
		}
	}

	// Display filter information
	if cfg.Flow != nil && len(cfg.Flow.Filters) > 0 {
		logger.Info("msg", "Filters configured",
			"pipeline", cfg.Name,
			"filter_count", len(cfg.Flow.Filters))
	}
}

// logPipelineStatus logs the detailed status and statistics of an individual pipeline
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
		fileCount := 0
		consoleCount := 0

		for _, sink := range sinks {
			sinkType := sink["type"].(string)
			switch sinkType {
			case "file":
				fileCount++
			case "console":
				consoleCount++
			}
		}

		if fileCount > 0 {
			statusFields = append(statusFields, "file_sinks", fileCount)
		}
		if consoleCount > 0 {
			statusFields = append(statusFields, "console_sinks", consoleCount)
		}
		statusFields = append(statusFields, "total_sinks", len(sinks))
	}

	// Add flow statistics if present
	if flow, ok := stats["flow"].(map[string]any); ok {
		// Add total from flow
		if totalFormatted, ok := flow["total_formatted"].(uint64); ok {
			statusFields = append(statusFields, "entries_formatted", totalFormatted)
		}

		// Check if filters are active
		if filters, ok := flow["filters"].(map[string]any); ok {
			if filterCount, ok := filters["filter_count"].(int); ok && filterCount > 0 {
				statusFields = append(statusFields, "filters_active", filterCount)

				// Add filter stats
				if totalFiltered, ok := filters["total_passed"].(uint64); ok {
					statusFields = append(statusFields, "entries_passed_filters", totalFiltered)
				}
			}
		}

		// Check if rate limiter is active
		if rateLimiter, ok := flow["rate_limiter"].(map[string]any); ok {
			if enabled, ok := rateLimiter["enabled"].(bool); ok && enabled {
				statusFields = append(statusFields, "rate_limiter", "active")

				// Add rate limit stats
				if droppedTotal, ok := rateLimiter["dropped_total"].(uint64); ok {
					statusFields = append(statusFields, "rate_limited", droppedTotal)
				}
			}
		}

		// Check formatter type
		if formatter, ok := flow["formatter"].(string); ok {
			statusFields = append(statusFields, "formatter", formatter)
		}

		// Check if heartbeat is enabled
		if heartbeatEnabled, ok := flow["heartbeat_enabled"].(bool); ok && heartbeatEnabled {
			if intervalMs, ok := flow["heartbeat_interval_ms"].(int64); ok {
				statusFields = append(statusFields, "heartbeat_interval_ms", intervalMs)
			}
		}
	}

	logger.Debug(statusFields...)
}