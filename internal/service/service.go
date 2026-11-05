// Package service holds the pipelines of one configuration: it builds all of
// them or none, starts and stops them together, swaps their flows in place
// when nothing else changed, gives a viewer's tap to each, and reports when
// every one has finished.
package service

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/flow"
	"github.com/lixenwraith/logwisp/internal/pipeline"

	"github.com/lixenwraith/log"
)

// Service manages a collection of log processing pipelines
type Service struct {
	pipelines    map[string]*pipeline.Pipeline
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	logger       *log.Logger
	shutdownOnce sync.Once
	watchOnce    sync.Once
	done         chan struct{} // closed when every pipeline has finished
	closed       atomic.Bool   // shutdown began: nothing is patched
}

func NewService(ctx context.Context, cfg *config.Config, logger *log.Logger) (*Service, error) {
	serviceCtx, cancel := context.WithCancel(ctx)
	svc := &Service{
		pipelines: make(map[string]*pipeline.Pipeline),
		ctx:       serviceCtx,
		cancel:    cancel,
		logger:    logger,
		done:      make(chan struct{}),
	}

	var errs error
	for _, pipelineCfg := range cfg.Pipelines {
		pipelineName := pipelineCfg.Name
		logger.Info("msg", "Initializing pipeline", "pipeline", pipelineName)

		if pl, err := pipeline.NewPipeline(&pipelineCfg, logger); err != nil {
			logger.Error("msg", "Failed to create pipeline",
				"pipeline", pipelineCfg.Name,
				"error", err)
			errs = errors.Join(errs, fmt.Errorf("failed to initialize pipeline %s: %w", pipelineName, err))
		} else {
			svc.pipelines[pipelineName] = pl
		}
	}

	if errs != nil {
		// A rejected reload must not retain prepared pipelines or their workers.
		svc.Shutdown()
		return nil, errs
	}
	logger.Info("msg", "Service initialization completed", "pipelines", len(svc.pipelines))

	return svc, nil
}

// Start starts the named pipelines, or all of them without names
func (svc *Service) Start(names ...string) error {
	svc.mu.RLock()
	defer svc.mu.RUnlock()

	var errs error
	if len(names) == 0 {
		svc.logger.Info("msg", "Starting all pipelines")
		for name, p := range svc.pipelines {
			if err := p.Start(); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to start pipeline %s: %w", name, err))
			}
		}
	} else {
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
	svc.watchOnce.Do(func() {
		pipelines := make([]*pipeline.Pipeline, 0, len(svc.pipelines))
		for _, p := range svc.pipelines {
			pipelines = append(pipelines, p)
		}
		go func() {
			for _, p := range pipelines {
				<-p.Finished()
			}
			close(svc.done)
		}()
	})

	return errs
}

// Patch puts cfg's flows in place of the running ones when cfg differs from
// what runs in flows alone, and reports whether it did: sources and sinks run
// on, their clients, sessions and file positions kept. Every changed flow is
// built before any is swapped, so an error changes nothing. False, with no
// error, changes nothing either: the pipelines differ in more than their
// flows, or the service shut down, and the caller rebuilds.
func (svc *Service) Patch(cfg *config.Config) (bool, error) {
	svc.mu.Lock() // SetFlow sets a pipeline's Config.Flow, which Patch reads
	defer svc.mu.Unlock()
	if svc.closed.Load() || len(cfg.Pipelines) != len(svc.pipelines) {
		return false, nil
	}
	type swap struct {
		p   *pipeline.Pipeline
		cfg *config.FlowConfig
		f   *flow.Flow
	}
	var swaps []swap
	for i := range cfg.Pipelines {
		next := &cfg.Pipelines[i]
		p, ok := svc.pipelines[next.Name]
		switch {
		case !ok || !p.SameParts(next):
			return false, nil
		case reflect.DeepEqual(p.Config.Flow, next.Flow):
			continue
		}
		f, err := flow.NewFlow(next.Flow, svc.logger)
		if err != nil {
			return false, fmt.Errorf("pipeline %s: %w", next.Name, err)
		}
		swaps = append(swaps, swap{p, next.Flow, f})
	}
	for _, s := range swaps {
		s.p.SetFlow(s.cfg, s.f)
		svc.logger.Info("msg", "Pipeline flow swapped in place", "pipeline", s.p.Config.Name)
	}
	return true, nil
}

// SetTap gives every pipeline the viewer's tap; nil takes it away
func (svc *Service) SetTap(t *core.Tap) {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	for _, p := range svc.pipelines {
		p.SetTap(t)
	}
}

// Done is closed once every pipeline has finished: all their sources reached
// the end of their input (stdin), or the service shut down.
func (svc *Service) Done() <-chan struct{} { return svc.done }

// Stop stops the named pipelines, or all of them without names
func (svc *Service) Stop(names ...string) error {
	svc.mu.RLock()
	defer svc.mu.RUnlock()

	var errs error

	if len(names) == 0 {
		svc.logger.Info("msg", "Stopping all pipelines")
		for name, p := range svc.pipelines {
			if err := p.Stop(); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to stop pipeline %s: %w", name, err))
			}
		}
	} else {
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

func (svc *Service) GetPipeline(name string) (*pipeline.Pipeline, error) {
	svc.mu.RLock()
	defer svc.mu.RUnlock()

	pipeline, exists := svc.pipelines[name]
	if !exists {
		return nil, fmt.Errorf("pipeline '%s' not found", name)
	}
	return pipeline, nil
}

func (svc *Service) ListPipelines() []string {
	svc.mu.RLock()
	defer svc.mu.RUnlock()

	names := make([]string, 0, len(svc.pipelines))
	for name := range svc.pipelines {
		names = append(names, name)
	}
	return names
}

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

// Shutdown stops every pipeline for good, concurrently
func (svc *Service) Shutdown() {
	svc.shutdownOnce.Do(svc.shutdown)
}

func (svc *Service) shutdown() {
	svc.closed.Store(true)
	svc.logger.Info("msg", "Service shutdown initiated")

	svc.mu.Lock()
	pipelines := make([]*pipeline.Pipeline, 0, len(svc.pipelines))
	for _, pl := range svc.pipelines {
		pipelines = append(pipelines, pl)
	}
	svc.mu.Unlock()

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
