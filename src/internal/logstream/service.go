// FILE: src/internal/logstream/service.go
package logstream

import (
	"context"
	"fmt"
	"logwisp/src/internal/filter"
	"sync"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/monitor"
	"logwisp/src/internal/stream"
)

type Service struct {
	streams map[string]*LogStream
	mu      sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

type LogStream struct {
	Name        string
	Config      config.StreamConfig
	Monitor     monitor.Monitor
	FilterChain *filter.Chain
	TCPServer   *stream.TCPStreamer
	HTTPServer  *stream.HTTPStreamer
	Stats       *StreamStats

	ctx    context.Context
	cancel context.CancelFunc
}

type StreamStats struct {
	StartTime          time.Time
	MonitorStats       monitor.Stats
	TCPConnections     int32
	HTTPConnections    int32
	TotalBytesServed   uint64
	TotalEntriesServed uint64
	FilterStats        map[string]any
}

func New(ctx context.Context) *Service {
	serviceCtx, cancel := context.WithCancel(ctx)
	return &Service{
		streams: make(map[string]*LogStream),
		ctx:     serviceCtx,
		cancel:  cancel,
	}
}

func (s *Service) CreateStream(cfg config.StreamConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.streams[cfg.Name]; exists {
		return fmt.Errorf("stream '%s' already exists", cfg.Name)
	}

	// Create stream context
	streamCtx, streamCancel := context.WithCancel(s.ctx)

	// Create monitor
	mon := monitor.New()
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
		return fmt.Errorf("failed to start monitor: %w", err)
	}

	// Create filter chain
	var filterChain *filter.Chain
	if len(cfg.Filters) > 0 {
		chain, err := filter.NewChain(cfg.Filters)
		if err != nil {
			streamCancel()
			return fmt.Errorf("failed to create filter chain: %w", err)
		}
		filterChain = chain
	}

	// Create log stream
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

		ls.TCPServer = stream.NewTCPStreamer(tcpChan, *cfg.TCPServer)

		if err := s.startTCPServer(ls); err != nil {
			ls.Shutdown()
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

		ls.HTTPServer = stream.NewHTTPStreamer(httpChan, *cfg.HTTPServer)

		if err := s.startHTTPServer(ls); err != nil {
			ls.Shutdown()
			return fmt.Errorf("HTTP server failed: %w", err)
		}
	}

	ls.startStatsUpdater(streamCtx)

	s.streams[cfg.Name] = ls
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
		return nil, fmt.Errorf("stream '%s' not found", name)
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
		return fmt.Errorf("stream '%s' not found", name)
	}

	stream.Shutdown()
	delete(s.streams, name)
	return nil
}

func (s *Service) Shutdown() {
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
		return err
	case <-time.After(time.Second):
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
		return err
	case <-time.After(time.Second):
		return nil
	}
}