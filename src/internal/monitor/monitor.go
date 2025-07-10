// FILE: src/internal/monitor/monitor.go
package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/log"
)

type LogEntry struct {
	Time    time.Time       `json:"time"`
	Source  string          `json:"source"`
	Level   string          `json:"level,omitempty"`
	Message string          `json:"message"`
	Fields  json.RawMessage `json:"fields,omitempty"`
}

type Monitor interface {
	Start(ctx context.Context) error
	Stop()
	Subscribe() chan LogEntry
	AddTarget(path, pattern string, isFile bool) error
	RemoveTarget(path string) error
	SetCheckInterval(interval time.Duration)
	GetStats() Stats
	GetActiveWatchers() []WatcherInfo
}

type Stats struct {
	ActiveWatchers int
	TotalEntries   uint64
	DroppedEntries uint64
	StartTime      time.Time
	LastEntryTime  time.Time
}

type WatcherInfo struct {
	Path         string
	Size         int64
	Position     int64
	ModTime      time.Time
	EntriesRead  uint64
	LastReadTime time.Time
	Rotations    int
}

type monitor struct {
	subscribers    []chan LogEntry
	targets        []target
	watchers       map[string]*fileWatcher
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	checkInterval  time.Duration
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
	logger         *log.Logger
}

type target struct {
	path    string
	pattern string
	isFile  bool
	regex   *regexp.Regexp
}

func New(logger *log.Logger) Monitor {
	m := &monitor{
		watchers:      make(map[string]*fileWatcher),
		checkInterval: 100 * time.Millisecond,
		startTime:     time.Now(),
		logger:        logger,
	}
	m.lastEntryTime.Store(time.Time{})
	return m
}

func (m *monitor) Subscribe() chan LogEntry {
	m.mu.Lock()
	defer m.mu.Unlock()

	ch := make(chan LogEntry, 1000)
	m.subscribers = append(m.subscribers, ch)
	return ch
}

func (m *monitor) publish(entry LogEntry) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.totalEntries.Add(1)
	m.lastEntryTime.Store(entry.Time)

	for _, ch := range m.subscribers {
		select {
		case ch <- entry:
		default:
			m.droppedEntries.Add(1)
			m.logger.Debug("msg", "Dropped log entry - subscriber buffer full")
		}
	}
}

func (m *monitor) SetCheckInterval(interval time.Duration) {
	m.mu.Lock()
	m.checkInterval = interval
	m.mu.Unlock()

	m.logger.Debug("msg", "Check interval updated", "interval_ms", interval.Milliseconds())
}

func (m *monitor) AddTarget(path, pattern string, isFile bool) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		m.logger.Error("msg", "Failed to resolve absolute path",
			"component", "monitor",
			"path", path,
			"error", err)
		return fmt.Errorf("invalid path %s: %w", path, err)
	}

	var compiledRegex *regexp.Regexp
	if !isFile && pattern != "" {
		regexPattern := globToRegex(pattern)
		compiledRegex, err = regexp.Compile(regexPattern)
		if err != nil {
			m.logger.Error("msg", "Failed to compile pattern regex",
				"component", "monitor",
				"pattern", pattern,
				"regex", regexPattern,
				"error", err)
			return fmt.Errorf("invalid pattern %s: %w", pattern, err)
		}
	}

	m.mu.Lock()
	m.targets = append(m.targets, target{
		path:    absPath,
		pattern: pattern,
		isFile:  isFile,
		regex:   compiledRegex,
	})
	m.mu.Unlock()

	m.logger.Info("msg", "Added monitor target",
		"component", "monitor",
		"path", absPath,
		"pattern", pattern,
		"is_file", isFile)

	return nil
}

func (m *monitor) RemoveTarget(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path %s: %w", path, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from targets
	newTargets := make([]target, 0, len(m.targets))
	for _, t := range m.targets {
		if t.path != absPath {
			newTargets = append(newTargets, t)
		}
	}
	m.targets = newTargets

	// Stop any watchers for this path
	if w, exists := m.watchers[absPath]; exists {
		w.stop()
		delete(m.watchers, absPath)
		m.logger.Info("msg", "Monitor started",
			"component", "monitor",
			"check_interval_ms", m.checkInterval.Milliseconds())
	}

	return nil
}

func (m *monitor) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.monitorLoop()

	m.logger.Info("msg", "Monitor started", "check_interval_ms", m.checkInterval.Milliseconds())
	return nil
}

func (m *monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()

	m.mu.Lock()
	for _, w := range m.watchers {
		w.close()
	}
	for _, ch := range m.subscribers {
		close(ch)
	}
	m.mu.Unlock()

	m.logger.Info("msg", "Monitor stopped")
}

func (m *monitor) GetStats() Stats {
	lastEntry, _ := m.lastEntryTime.Load().(time.Time)

	m.mu.RLock()
	watcherCount := len(m.watchers)
	m.mu.RUnlock()

	return Stats{
		ActiveWatchers: watcherCount,
		TotalEntries:   m.totalEntries.Load(),
		DroppedEntries: m.droppedEntries.Load(),
		StartTime:      m.startTime,
		LastEntryTime:  lastEntry,
	}
}

func (m *monitor) GetActiveWatchers() []WatcherInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info := make([]WatcherInfo, 0, len(m.watchers))
	for _, w := range m.watchers {
		info = append(info, w.getInfo())
	}
	return info
}

func (m *monitor) monitorLoop() {
	defer m.wg.Done()

	m.checkTargets()

	m.mu.RLock()
	interval := m.checkInterval
	m.mu.RUnlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkTargets()

			m.mu.RLock()
			newInterval := m.checkInterval
			m.mu.RUnlock()

			if newInterval != interval {
				ticker.Stop()
				ticker = time.NewTicker(newInterval)
				interval = newInterval
			}
		}
	}
}

func (m *monitor) checkTargets() {
	m.mu.RLock()
	targets := make([]target, len(m.targets))
	copy(targets, m.targets)
	m.mu.RUnlock()

	for _, t := range targets {
		if t.isFile {
			m.ensureWatcher(t.path)
		} else {
			// Directory scanning for pattern matching
			files, err := m.scanDirectory(t.path, t.regex)
			if err != nil {
				m.logger.Warn("msg", "Failed to scan directory",
					"component", "monitor",
					"path", t.path,
					"pattern", t.pattern,
					"error", err)
				continue
			}

			for _, file := range files {
				m.ensureWatcher(file)
			}
		}
	}

	m.cleanupWatchers()
}

func (m *monitor) scanDirectory(dir string, pattern *regexp.Regexp) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if pattern == nil || pattern.MatchString(name) {
			files = append(files, filepath.Join(dir, name))
		}
	}

	return files, nil
}

func (m *monitor) ensureWatcher(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.watchers[path]; exists {
		return
	}

	w := newFileWatcher(path, m.publish, m.logger)
	m.watchers[path] = w

	m.logger.Debug("msg", "Created watcher", "path", path)

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := w.watch(m.ctx); err != nil {
			// Log based on error type
			if errors.Is(err, context.Canceled) {
				m.logger.Debug("msg", "Watcher cancelled",
					"component", "monitor",
					"path", path)
			} else {
				m.logger.Error("msg", "Watcher failed",
					"component", "monitor",
					"path", path,
					"error", err)
			}
		}

		m.mu.Lock()
		delete(m.watchers, path)
		m.mu.Unlock()
	}()
}

func (m *monitor) cleanupWatchers() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for path, w := range m.watchers {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			w.stop()
			delete(m.watchers, path)
			m.logger.Debug("msg", "Cleaned up watcher for non-existent file", "path", path)
		}
	}
}