// FILE: logwisp/src/internal/service/service.go
package service

import (
	"context"
	"errors"
	"fmt"
	"logwisp/src/internal/pipeline"
	"sync"

	"logwisp/src/internal/config"
	// "logwisp/src/internal/core"

	// lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
)

// Service manages a collection of log processing pipelines
type Service struct {
	pipelines map[string]*pipeline.Pipeline
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	logger    *log.Logger
}

// NewService creates a new, empty service
func NewService(ctx context.Context, cfg *config.Config, logger *log.Logger) (*Service, error) {
	serviceCtx, cancel := context.WithCancel(ctx)
	svc := &Service{
		pipelines: make(map[string]*pipeline.Pipeline),
		ctx:       serviceCtx,
		cancel:    cancel,
		logger:    logger,
	}

	var errs error
	// Initialize pipelines
	for _, pipelineCfg := range cfg.Pipelines {
		pipelineName := pipelineCfg.Name
		logger.Info("msg", "Initializing pipeline", "pipeline", pipelineName)

		// Create the pipeline
		if pl, err := pipeline.NewPipeline(&pipelineCfg, logger); err != nil {
			logger.Error("msg", "Failed to create pipeline",
				"pipeline", pipelineCfg.Name,
				"error", err)
			errs = errors.Join(errs, fmt.Errorf("failed to initialize pipeline %s: %w", pipelineName, err))
		} else {
			svc.pipelines[pipelineName] = pl
		}
	}

	logger.Info("msg", "Service initialization completed", "pipelines", len(svc.pipelines))

	return svc, errs
}

// GetPipeline returns a pipeline by its name
func (s *Service) GetPipeline(name string) (*pipeline.Pipeline, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pipeline, exists := s.pipelines[name]
	if !exists {
		return nil, fmt.Errorf("pipeline '%s' not found", name)
	}
	return pipeline, nil
}

// ListPipelines returns the names of all currently managed pipelines
func (s *Service) ListPipelines() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.pipelines))
	for name := range s.pipelines {
		names = append(names, name)
	}
	return names
}

// RemovePipeline stops and removes a pipeline from the service
func (s *Service) RemovePipeline(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pl, exists := s.pipelines[name]
	if !exists {
		err := fmt.Errorf("pipeline '%s' not found", name)
		s.logger.Warn("msg", "Cannot remove non-existent pipeline",
			"component", "service",
			"pipeline", name,
			"error", err)
		return err
	}

	s.logger.Info("msg", "Removing pipeline", "pipeline", name)
	pl.Shutdown()
	delete(s.pipelines, name)
	return nil
}

// Shutdown gracefully stops all pipelines managed by the service
func (s *Service) Shutdown() {
	s.logger.Info("msg", "Service shutdown initiated")

	s.mu.Lock()
	pipelines := make([]*pipeline.Pipeline, 0, len(s.pipelines))
	for _, pl := range s.pipelines {
		pipelines = append(pipelines, pl)
	}
	s.mu.Unlock()

	// Stop all pipelines concurrently
	var wg sync.WaitGroup
	for _, pl := range pipelines {
		wg.Add(1)
		go func(p *pipeline.Pipeline) {
			defer wg.Done()
			p.Shutdown()
		}(pl)
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

	for name, pl := range s.pipelines {
		stats["pipelines"].(map[string]any)[name] = pl.GetStats()
	}

	return stats
}