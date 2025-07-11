// FILE: src/internal/service/service.go
package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/filter"
	"logwisp/src/internal/sink"
	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// Service manages multiple pipelines
type Service struct {
	pipelines map[string]*Pipeline
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	logger    *log.Logger
}

// New creates a new service
func New(ctx context.Context, logger *log.Logger) *Service {
	serviceCtx, cancel := context.WithCancel(ctx)
	return &Service{
		pipelines: make(map[string]*Pipeline),
		ctx:       serviceCtx,
		cancel:    cancel,
		logger:    logger,
	}
}

// NewPipeline creates and starts a new pipeline
func (s *Service) NewPipeline(cfg config.PipelineConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.pipelines[cfg.Name]; exists {
		err := fmt.Errorf("pipeline '%s' already exists", cfg.Name)
		s.logger.Error("msg", "Failed to create pipeline - duplicate name",
			"component", "service",
			"pipeline", cfg.Name,
			"error", err)
		return err
	}

	s.logger.Debug("msg", "Creating pipeline", "pipeline", cfg.Name)

	// Create pipeline context
	pipelineCtx, pipelineCancel := context.WithCancel(s.ctx)

	// Create pipeline instance
	pipeline := &Pipeline{
		Name:   cfg.Name,
		Config: cfg,
		Stats: &PipelineStats{
			StartTime: time.Now(),
		},
		ctx:    pipelineCtx,
		cancel: pipelineCancel,
		logger: s.logger,
	}

	// Create sources
	for i, srcCfg := range cfg.Sources {
		src, err := s.createSource(srcCfg)
		if err != nil {
			pipelineCancel()
			return fmt.Errorf("failed to create source[%d]: %w", i, err)
		}
		pipeline.Sources = append(pipeline.Sources, src)
	}

	// Create filter chain
	if len(cfg.Filters) > 0 {
		chain, err := filter.NewChain(cfg.Filters, s.logger)
		if err != nil {
			pipelineCancel()
			return fmt.Errorf("failed to create filter chain: %w", err)
		}
		pipeline.FilterChain = chain
	}

	// Create sinks
	for i, sinkCfg := range cfg.Sinks {
		sinkInst, err := s.createSink(sinkCfg)
		if err != nil {
			pipelineCancel()
			return fmt.Errorf("failed to create sink[%d]: %w", i, err)
		}
		pipeline.Sinks = append(pipeline.Sinks, sinkInst)

		// Track HTTP/TCP sinks for router mode
		switch s := sinkInst.(type) {
		case *sink.HTTPSink:
			pipeline.HTTPSinks = append(pipeline.HTTPSinks, s)
		case *sink.TCPSink:
			pipeline.TCPSinks = append(pipeline.TCPSinks, s)
		}
	}

	// Start all sources
	for i, src := range pipeline.Sources {
		if err := src.Start(); err != nil {
			pipeline.Shutdown()
			return fmt.Errorf("failed to start source[%d]: %w", i, err)
		}
	}

	// Start all sinks
	for i, sinkInst := range pipeline.Sinks {
		if err := sinkInst.Start(pipelineCtx); err != nil {
			pipeline.Shutdown()
			return fmt.Errorf("failed to start sink[%d]: %w", i, err)
		}
	}

	// Wire sources to sinks through filters
	s.wirePipeline(pipeline)

	// Start stats updater
	pipeline.startStatsUpdater(pipelineCtx)

	s.pipelines[cfg.Name] = pipeline
	s.logger.Info("msg", "Pipeline created successfully", "pipeline", cfg.Name)
	return nil
}

// wirePipeline connects sources to sinks through filters
func (s *Service) wirePipeline(p *Pipeline) {
	// For each source, subscribe and process entries
	for _, src := range p.Sources {
		srcChan := src.Subscribe()

		// Create a processing goroutine for this source
		p.wg.Add(1)
		go func(source source.Source, entries <-chan source.LogEntry) {
			defer p.wg.Done()

			for {
				select {
				case <-p.ctx.Done():
					return
				case entry, ok := <-entries:
					if !ok {
						return
					}

					p.Stats.TotalEntriesProcessed.Add(1)

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
							// Drop if sink buffer is full
							s.logger.Debug("msg", "Dropped log entry - sink buffer full",
								"pipeline", p.Name)
						}
					}
				}
			}
		}(src, srcChan)
	}
}

// createSource creates a source instance based on configuration
func (s *Service) createSource(cfg config.SourceConfig) (source.Source, error) {
	switch cfg.Type {
	case "directory":
		return source.NewDirectorySource(cfg.Options, s.logger)
	case "stdin":
		return source.NewStdinSource(cfg.Options, s.logger)
	default:
		return nil, fmt.Errorf("unknown source type: %s", cfg.Type)
	}
}

// createSink creates a sink instance based on configuration
func (s *Service) createSink(cfg config.SinkConfig) (sink.Sink, error) {
	switch cfg.Type {
	case "http":
		return sink.NewHTTPSink(cfg.Options, s.logger)
	case "tcp":
		return sink.NewTCPSink(cfg.Options, s.logger)
	case "file":
		return sink.NewFileSink(cfg.Options, s.logger)
	case "stdout":
		return sink.NewStdoutSink(cfg.Options, s.logger)
	case "stderr":
		return sink.NewStderrSink(cfg.Options, s.logger)
	default:
		return nil, fmt.Errorf("unknown sink type: %s", cfg.Type)
	}
}

// GetPipeline returns a pipeline by name
func (s *Service) GetPipeline(name string) (*Pipeline, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pipeline, exists := s.pipelines[name]
	if !exists {
		return nil, fmt.Errorf("pipeline '%s' not found", name)
	}
	return pipeline, nil
}

// ListStreams is deprecated, use ListPipelines
func (s *Service) ListStreams() []string {
	s.logger.Warn("msg", "ListStreams is deprecated, use ListPipelines",
		"component", "service")
	return s.ListPipelines()
}

// ListPipelines returns all pipeline names
func (s *Service) ListPipelines() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.pipelines))
	for name := range s.pipelines {
		names = append(names, name)
	}
	return names
}

// RemoveStream is deprecated, use RemovePipeline
func (s *Service) RemoveStream(name string) error {
	s.logger.Warn("msg", "RemoveStream is deprecated, use RemovePipeline",
		"component", "service")
	return s.RemovePipeline(name)
}

// RemovePipeline stops and removes a pipeline
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

// Shutdown stops all pipelines
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

// GetGlobalStats returns statistics for all pipelines
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