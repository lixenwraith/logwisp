package main

import (
	"context"
	"fmt"
	"time"

	"logwisp/internal/service"
)

// startStatusReporter starts a new status reporter for a service and returns its cancel function.
func startStatusReporter(ctx context.Context, svc *service.Service) context.CancelFunc {
	reporterCtx, cancel := context.WithCancel(ctx)
	go statusReporter(svc, reporterCtx)
	logger.Debug("msg", "Started status reporter")
	return cancel
}

// statusReporter periodically logs the health and statistics of the service
func statusReporter(service *service.Service, ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
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

				// Log service-level summary
				logger.Debug("msg", "Status report",
					"component", "status_reporter",
					"active_pipelines", totalPipelines,
					"time", time.Now().Format("15:04:05"))

				// Log each pipeline's stats recursively
				if pipelines, ok := stats["pipelines"].(map[string]any); ok {
					for name, pipelineStats := range pipelines {
						logStats("Pipeline status", name, pipelineStats)
					}
				}
			}()
		}
	}
}

// logStats recursively logs statistics with automatic field extraction
func logStats(msg string, name string, stats any) {
	// Build base log fields
	fields := []any{
		"msg", msg,
		"name", name,
	}

	// Extract and flatten important metrics from stats map
	if statsMap, ok := stats.(map[string]any); ok {
		// Add scalar values directly
		for key, value := range statsMap {
			switch v := value.(type) {
			case string, bool, int, int64, uint64, float64:
				fields = append(fields, key, v)
			case time.Time:
				if !v.IsZero() {
					fields = append(fields, key, v.Format(time.RFC3339))
				}
			case map[string]any:
				// For nested maps, log summary counts if they contain arrays/maps
				if count := getItemCount(v); count > 0 {
					fields = append(fields, fmt.Sprintf("%s_count", key), count)
				}
			case []any, []map[string]any:
				// For arrays, just log the count
				fields = append(fields, fmt.Sprintf("%s_count", key), getArrayLength(value))
			}
		}

		// Log the flattened stats
		logger.Debug(fields...)

		// Recursively log nested structures with detail
		for key, value := range statsMap {
			switch v := value.(type) {
			case map[string]any:
				// Log nested component stats
				if key == "flow" || key == "rate_limiter" || key == "filters" {
					logStats(fmt.Sprintf("%s %s", name, key), key, v)
				}
			case []map[string]any:
				// Log array items (sources, sinks, filters)
				for i, item := range v {
					if itemName, ok := item["id"].(string); ok {
						logStats(fmt.Sprintf("%s %s", name, key), itemName, item)
					} else {
						logStats(fmt.Sprintf("%s %s", name, key), fmt.Sprintf("%s[%d]", key, i), item)
					}
				}
			}
		}
	}
}

// getItemCount returns the count of items in a map (for nested structures)
func getItemCount(m map[string]any) int {
	for _, v := range m {
		switch v.(type) {
		case []any:
			return len(v.([]any))
		case []map[string]any:
			return len(v.([]map[string]any))
		}
	}
	return 0
}

// getArrayLength safely gets the length of various array types
func getArrayLength(v any) int {
	switch arr := v.(type) {
	case []any:
		return len(arr)
	case []map[string]any:
		return len(arr)
	default:
		return 0
	}
}