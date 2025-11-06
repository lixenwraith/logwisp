// FILE: logwisp/src/internal/service/service.go
package service

import (
	"context"
	"fmt"
	"sync"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/format"
	"logwisp/src/internal/sink"
	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// Service manages a collection of log processing pipelines.
type Service struct {
	pipelines map[string]*Pipeline
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	logger    *log.Logger
}

// NewService creates a new, empty service.
func NewService(ctx context.Context, logger *log.Logger) *Service {
	serviceCtx, cancel := context.WithCancel(ctx)
	return &Service{
		pipelines: make(map[string]*Pipeline),
		ctx:       serviceCtx,
		cancel:    cancel,
		logger:    logger,
	}
}

// GetPipeline returns a pipeline by its name.
func (s *Service) GetPipeline(name string) (*Pipeline, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pipeline, exists := s.pipelines[name]
	if !exists {
		return nil, fmt.Errorf("pipeline '%s' not found", name)
	}
	return pipeline, nil
}

// ListPipelines returns the names of all currently managed pipelines.
func (s *Service) ListPipelines() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.pipelines))
	for name := range s.pipelines {
		names = append(names, name)
	}
	return names
}

// RemovePipeline stops and removes a pipeline from the service.
func (s *Service) RemovePipeline(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pipeline, exists := s.pipelines[name]
	if !exists {
		err := fmt.Errorf("pipeline '%s' not found", name)
		s.logger.Warn("msg", "Cannot remove non-existent pipeline",
			"component", "service",
			"pipeline", name,
			"error", err)
		return err
	}

	s.logger.Info("msg", "Removing pipeline", "pipeline", name)
	pipeline.Shutdown()
	delete(s.pipelines, name)
	return nil
}

// Shutdown gracefully stops all pipelines managed by the service.
func (s *Service) Shutdown() {
	s.logger.Info("msg", "Service shutdown initiated")

	s.mu.Lock()
	pipelines := make([]*Pipeline, 0, len(s.pipelines))
	for _, pipeline := range s.pipelines {
		pipelines = append(pipelines, pipeline)
	}
	s.mu.Unlock()

	// Stop all pipelines concurrently
	var wg sync.WaitGroup
	for _, pipeline := range pipelines {
		wg.Add(1)
		go func(p *Pipeline) {
			defer wg.Done()
			p.Shutdown()
		}(pipeline)
	}
	wg.Wait()

	s.cancel()
	s.wg.Wait()

	s.logger.Info("msg", "Service shutdown complete")
}

// GetGlobalStats returns statistics for all pipelines.
func (s *Service) GetGlobalStats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]any{
		"pipelines":       make(map[string]any),
		"total_pipelines": len(s.pipelines),
	}

	for name, pipeline := range s.pipelines {
		stats["pipelines"].(map[string]any)[name] = pipeline.GetStats()
	}

	return stats
}

// wirePipeline connects a pipeline's sources to its sinks through its filter chain.
func (s *Service) wirePipeline(p *Pipeline) {
	// For each source, subscribe and process entries
	for _, src := range p.Sources {
		srcChan := src.Subscribe()

		// Create a processing goroutine for this source
		p.wg.Add(1)
		go func(source source.Source, entries <-chan core.LogEntry) {
			defer p.wg.Done()

			// Panic recovery to prevent single source from crashing pipeline
			defer func() {
				if r := recover(); r != nil {
					s.logger.Error("msg", "Panic in pipeline processing",
						"pipeline", p.Config.Name,
						"source", source.GetStats().Type,
						"panic", r)

					// Ensure failed pipelines don't leave resources hanging
					go func() {
						s.logger.Warn("msg", "Shutting down pipeline due to panic",
							"pipeline", p.Config.Name)
						if err := s.RemovePipeline(p.Config.Name); err != nil {
							s.logger.Error("msg", "Failed to remove panicked pipeline",
								"pipeline", p.Config.Name,
								"error", err)
						}
					}()
				}
			}()

			for {
				select {
				case <-p.ctx.Done():
					return
				case entry, ok := <-entries:
					if !ok {
						return
					}

					p.Stats.TotalEntriesProcessed.Add(1)

					// Apply pipeline rate limiter
					if p.RateLimiter != nil {
						if !p.RateLimiter.Allow(entry) {
							p.Stats.TotalEntriesDroppedByRateLimit.Add(1)
							continue // Drop the entry
						}
					}

					// Apply filters if configured
					if p.FilterChain != nil {
						if !p.FilterChain.Apply(entry) {
							p.Stats.TotalEntriesFiltered.Add(1)
							continue
						}
					}

					// Send to all sinks
					for _, sinkInst := range p.Sinks {
						select {
						case sinkInst.Input() <- entry:
						case <-p.ctx.Done():
							return
						default:
							// Drop if sink buffer is full, may flood logging for slow client
							s.logger.Debug("msg", "Dropped log entry - sink buffer full",
								"pipeline", p.Config.Name)
						}
					}
				}
			}
		}(src, srcChan)
	}
}

// createSource is a factory function for creating a source instance from configuration.
func (s *Service) createSource(cfg *config.SourceConfig) (source.Source, error) {
	switch cfg.Type {
	case "directory":
		return source.NewDirectorySource(cfg.Directory, s.logger)
	case "stdin":
		return source.NewStdinSource(cfg.Stdin, s.logger)
	case "http":
		return source.NewHTTPSource(cfg.HTTP, s.logger)
	case "tcp":
		return source.NewTCPSource(cfg.TCP, s.logger)
	default:
		return nil, fmt.Errorf("unknown source type: %s", cfg.Type)
	}
}

// createSink is a factory function for creating a sink instance from configuration.
func (s *Service) createSink(cfg config.SinkConfig, formatter format.Formatter) (sink.Sink, error) {

	switch cfg.Type {
	case "http":
		if cfg.HTTP == nil {
			return nil, fmt.Errorf("HTTP sink configuration missing")
		}
		return sink.NewHTTPSink(cfg.HTTP, s.logger, formatter)

	case "tcp":
		if cfg.TCP == nil {
			return nil, fmt.Errorf("TCP sink configuration missing")
		}
		return sink.NewTCPSink(cfg.TCP, s.logger, formatter)

	case "http_client":
		return sink.NewHTTPClientSink(cfg.HTTPClient, s.logger, formatter)
	case "tcp_client":
		return sink.NewTCPClientSink(cfg.TCPClient, s.logger, formatter)
	case "file":
		return sink.NewFileSink(cfg.File, s.logger, formatter)
	case "console":
		return sink.NewConsoleSink(cfg.Console, s.logger, formatter)
	default:
		return nil, fmt.Errorf("unknown sink type: %s", cfg.Type)
	}
}