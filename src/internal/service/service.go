package service

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"logwisp/src/internal/config"
	"logwisp/src/internal/pipeline"

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

// Start starts all or specific pipelines
func (svc *Service) Start(names ...string) error {
	svc.mu.RLock()
	defer svc.mu.RUnlock()

	var errs error
	// If no names are provided, start all pipelines
	if len(names) == 0 {
		svc.logger.Info("msg", "Starting all pipelines")
		for name, p := range svc.pipelines {
			if err := p.Start(); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to start pipeline %s: %w", name, err))
			}
		}
	} else {
		// Start only the specified pipelines
		svc.logger.Info("msg", "Starting specified pipelines", "pipelines", names)
		for _, name := range names {
			if p, exists := svc.pipelines[name]; exists {
				if err := p.Start(); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to start pipeline %s: %w", name, err))
				}
			} else {
				errs = errors.Join(errs, fmt.Errorf("pipeline %s not found", name))
			}
		}
	}

	svc.logger.Debug("msg", "Finished starting pipeline(s)", "pipelines", names)

	return errs
}

// Stop stops all or specific pipeline
func (svc *Service) Stop(names ...string) error {
	svc.mu.RLock()
	defer svc.mu.RUnlock()

	var errs error

	// If no names are provided, stop all pipelines
	if len(names) == 0 {
		svc.logger.Info("msg", "Stopping all pipelines")
		for name, p := range svc.pipelines {
			if err := p.Stop(); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to stop pipeline %s: %w", name, err))
			}
		}
	} else {
		// Stop only the specified pipelines
		svc.logger.Info("msg", "Stopping specified pipelines", "pipelines", names)
		for _, name := range names {
			if p, exists := svc.pipelines[name]; exists {
				if err := p.Stop(); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to stop pipeline %s: %w", name, err))
				}
			} else {
				errs = errors.Join(errs, fmt.Errorf("pipeline %s not found", name))
			}
		}
	}

	svc.logger.Debug("msg", "Finished stopping pipeline(s)", "pipelines", names)

	return errs
}

// GetPipeline returns a pipeline by its name
func (svc *Service) GetPipeline(name string) (*pipeline.Pipeline, error) {
	svc.mu.RLock()
	defer svc.mu.RUnlock()

	pipeline, exists := svc.pipelines[name]
	if !exists {
		return nil, fmt.Errorf("pipeline '%s' not found", name)
	}
	return pipeline, nil
}

// ListPipelines returns the names of all currently managed pipelines
func (svc *Service) ListPipelines() []string {
	svc.mu.RLock()
	defer svc.mu.RUnlock()

	names := make([]string, 0, len(svc.pipelines))
	for name := range svc.pipelines {
		names = append(names, name)
	}
	return names
}

// RemovePipeline stops and removes a pipeline from the service
func (svc *Service) RemovePipeline(name string) error {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	pl, exists := svc.pipelines[name]
	if !exists {
		err := fmt.Errorf("pipeline '%s' not found", name)
		svc.logger.Warn("msg", "Cannot remove non-existent pipeline",
			"component", "service",
			"pipeline", name,
			"error", err)
		return err
	}

	svc.logger.Info("msg", "Removing pipeline", "pipeline", name)
	pl.Shutdown()
	delete(svc.pipelines, name)
	return nil
}

// Shutdown gracefully stops all pipelines managed by the service
func (svc *Service) Shutdown() {
	svc.logger.Info("msg", "Service shutdown initiated")

	svc.mu.Lock()
	pipelines := make([]*pipeline.Pipeline, 0, len(svc.pipelines))
	for _, pl := range svc.pipelines {
		pipelines = append(pipelines, pl)
	}
	svc.mu.Unlock()

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

	svc.cancel()
	svc.wg.Wait()

	svc.logger.Info("msg", "Service shutdown complete")
}

// GetGlobalStats returns statistics for all pipelines
func (svc *Service) GetGlobalStats() map[string]any {
	svc.mu.RLock()
	defer svc.mu.RUnlock()

	stats := map[string]any{
		"pipelines":       make(map[string]any),
		"total_pipelines": len(svc.pipelines),
	}

	for name, pl := range svc.pipelines {
		stats["pipelines"].(map[string]any)[name] = pl.GetStats()
	}

	return stats
}