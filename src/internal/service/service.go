// FILE: src/internal/service/service.go
package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/filter"
	"logwisp/src/internal/monitor"
	"logwisp/src/internal/transport"

	"github.com/lixenwraith/log"
)

type Service struct {
	streams map[string]*LogStream
	mu      sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	logger  *log.Logger
}

func New(ctx context.Context, logger *log.Logger) *Service {
	serviceCtx, cancel := context.WithCancel(ctx)
	return &Service{
		streams: make(map[string]*LogStream),
		ctx:     serviceCtx,
		cancel:  cancel,
		logger:  logger,
	}
}

func (s *Service) CreateStream(cfg config.StreamConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.streams[cfg.Name]; exists {
		err := fmt.Errorf("transport '%s' already exists", cfg.Name)
		s.logger.Error("msg", "Failed to create stream - duplicate name",
			"component", "service",
			"stream", cfg.Name,
			"error", err)
		return err
	}

	s.logger.Debug("msg", "Creating stream", "stream", cfg.Name)

	// Create transport context
	streamCtx, streamCancel := context.WithCancel(s.ctx)

	// Create monitor - pass the service logger directly
	mon := monitor.New(s.logger)
	mon.SetCheckInterval(time.Duration(cfg.GetCheckInterval(100)) * time.Millisecond)

	// Add targets
	for _, target := range cfg.GetTargets(nil) {
		if err := mon.AddTarget(target.Path, target.Pattern, target.IsFile); err != nil {
			streamCancel()
			return fmt.Errorf("failed to add target %s: %w", target.Path, err)
		}
	}

	// Start monitor
	if err := mon.Start(streamCtx); err != nil {
		streamCancel()
		s.logger.Error("msg", "Failed to start monitor",
			"component", "service",
			"stream", cfg.Name,
			"error", err)
		return fmt.Errorf("failed to start monitor: %w", err)
	}

	// Create filter chain
	var filterChain *filter.Chain
	if len(cfg.Filters) > 0 {
		chain, err := filter.NewChain(cfg.Filters, s.logger)
		if err != nil {
			streamCancel()
			s.logger.Error("msg", "Failed to create filter chain",
				"component", "service",
				"stream", cfg.Name,
				"filter_count", len(cfg.Filters),
				"error", err)
			return fmt.Errorf("failed to create filter chain: %w", err)
		}
		filterChain = chain
	}

	// Create log transport
	ls := &LogStream{
		Name:        cfg.Name,
		Config:      cfg,
		Monitor:     mon,
		FilterChain: filterChain,
		Stats: &StreamStats{
			StartTime: time.Now(),
		},
		ctx:    streamCtx,
		cancel: streamCancel,
		logger: s.logger, // Use parent logger
	}

	// Start TCP server if configured
	if cfg.TCPServer != nil && cfg.TCPServer.Enabled {
		// Create filtered channel
		rawChan := mon.Subscribe()
		tcpChan := make(chan monitor.LogEntry, cfg.TCPServer.BufferSize)

		// Start filter goroutine for TCP
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer close(tcpChan)
			s.filterLoop(streamCtx, rawChan, tcpChan, filterChain)
		}()

		ls.TCPServer = transport.NewTCPStreamer(
			tcpChan,
			*cfg.TCPServer,
			s.logger) // Pass parent logger

		if err := s.startTCPServer(ls); err != nil {
			ls.Shutdown()
			s.logger.Error("msg", "Failed to start TCP server",
				"component", "service",
				"stream", cfg.Name,
				"port", cfg.TCPServer.Port,
				"error", err)
			return fmt.Errorf("TCP server failed: %w", err)
		}
	}

	// Start HTTP server if configured
	if cfg.HTTPServer != nil && cfg.HTTPServer.Enabled {
		// Create filtered channel
		rawChan := mon.Subscribe()
		httpChan := make(chan monitor.LogEntry, cfg.HTTPServer.BufferSize)

		// Start filter goroutine for HTTP
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer close(httpChan)
			s.filterLoop(streamCtx, rawChan, httpChan, filterChain)
		}()

		ls.HTTPServer = transport.NewHTTPStreamer(
			httpChan,
			*cfg.HTTPServer,
			s.logger) // Pass parent logger

		if err := s.startHTTPServer(ls); err != nil {
			ls.Shutdown()
			s.logger.Error("msg", "Failed to start HTTP server",
				"component", "service",
				"stream", cfg.Name,
				"port", cfg.HTTPServer.Port,
				"error", err)
			return fmt.Errorf("HTTP server failed: %w", err)
		}
	}

	ls.startStatsUpdater(streamCtx)

	s.streams[cfg.Name] = ls
	s.logger.Info("msg", "Stream created successfully", "stream", cfg.Name)
	return nil
}

// filterLoop applies filters to log entries
func (s *Service) filterLoop(ctx context.Context, in <-chan monitor.LogEntry, out chan<- monitor.LogEntry, chain *filter.Chain) {
	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-in:
			if !ok {
				return
			}

			// Apply filter chain if configured
			if chain == nil || chain.Apply(entry) {
				select {
				case out <- entry:
				case <-ctx.Done():
					return
				default:
					// Drop if output buffer is full
					s.logger.Debug("msg", "Dropped log entry - buffer full")
				}
			}
		}
	}
}

func (s *Service) GetStream(name string) (*LogStream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stream, exists := s.streams[name]
	if !exists {
		return nil, fmt.Errorf("transport '%s' not found", name)
	}
	return stream, nil
}

func (s *Service) ListStreams() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.streams))
	for name := range s.streams {
		names = append(names, name)
	}
	return names
}

func (s *Service) RemoveStream(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stream, exists := s.streams[name]
	if !exists {
		err := fmt.Errorf("transport '%s' not found", name)
		s.logger.Warn("msg", "Cannot remove non-existent stream",
			"component", "service",
			"stream", name,
			"error", err)
		return err
	}

	s.logger.Info("msg", "Removing stream", "stream", name)
	stream.Shutdown()
	delete(s.streams, name)
	return nil
}

func (s *Service) Shutdown() {
	s.logger.Info("msg", "Service shutdown initiated")

	s.mu.Lock()
	streams := make([]*LogStream, 0, len(s.streams))
	for _, stream := range s.streams {
		streams = append(streams, stream)
	}
	s.mu.Unlock()

	// Stop all streams concurrently
	var wg sync.WaitGroup
	for _, stream := range streams {
		wg.Add(1)
		go func(ls *LogStream) {
			defer wg.Done()
			ls.Shutdown()
		}(stream)
	}
	wg.Wait()

	s.cancel()
	s.wg.Wait()

	s.logger.Info("msg", "Service shutdown complete")
}

func (s *Service) GetGlobalStats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]any{
		"streams":       make(map[string]any),
		"total_streams": len(s.streams),
	}

	for name, stream := range s.streams {
		stats["streams"].(map[string]any)[name] = stream.GetStats()
	}

	return stats
}

func (s *Service) startTCPServer(ls *LogStream) error {
	errChan := make(chan error, 1)
	s.wg.Add(1)

	go func() {
		defer s.wg.Done()
		if err := ls.TCPServer.Start(); err != nil {
			errChan <- err
		}
	}()

	// Check startup
	select {
	case err := <-errChan:
		s.logger.Error("msg", "TCP server startup failed immediately",
			"component", "service",
			"stream", ls.Name,
			"error", err)
		return err
	case <-time.After(time.Second):
		s.logger.Debug("msg", "TCP server started", "stream", ls.Name)
		return nil
	}
}

func (s *Service) startHTTPServer(ls *LogStream) error {
	errChan := make(chan error, 1)
	s.wg.Add(1)

	go func() {
		defer s.wg.Done()
		if err := ls.HTTPServer.Start(); err != nil {
			errChan <- err
		}
	}()

	// Check startup
	select {
	case err := <-errChan:
		s.logger.Error("msg", "HTTP server startup failed immediately",
			"component", "service",
			"stream", ls.Name,
			"error", err)
		return err
	case <-time.After(time.Second):
		s.logger.Debug("msg", "HTTP server started", "stream", ls.Name)
		return nil
	}
}