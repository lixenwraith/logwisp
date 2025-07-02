// FILE: src/internal/monitor/monitor.go
package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

type LogEntry struct {
	Time    time.Time       `json:"time"`
	Source  string          `json:"source"`
	Level   string          `json:"level,omitempty"`
	Message string          `json:"message"`
	Fields  json.RawMessage `json:"fields,omitempty"`
}

type Monitor struct {
	subscribers   []chan LogEntry
	targets       []target
	watchers      map[string]*fileWatcher
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	checkInterval time.Duration
}

type target struct {
	path    string
	pattern string
	isFile  bool
	regex   *regexp.Regexp
}

func New() *Monitor {
	return &Monitor{
		watchers:      make(map[string]*fileWatcher),
		checkInterval: 100 * time.Millisecond,
	}
}

func (m *Monitor) Subscribe() chan LogEntry {
	m.mu.Lock()
	defer m.mu.Unlock()

	ch := make(chan LogEntry, 1000)
	m.subscribers = append(m.subscribers, ch)
	return ch
}

func (m *Monitor) publish(entry LogEntry) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, ch := range m.subscribers {
		select {
		case ch <- entry:
		default:
			// Drop message if channel full
		}
	}
}

func (m *Monitor) SetCheckInterval(interval time.Duration) {
	m.mu.Lock()
	m.checkInterval = interval
	m.mu.Unlock()
}

func (m *Monitor) AddTarget(path, pattern string, isFile bool) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path %s: %w", path, err)
	}

	var compiledRegex *regexp.Regexp
	if !isFile && pattern != "" {
		regexPattern := globToRegex(pattern)
		compiledRegex, err = regexp.Compile(regexPattern)
		if err != nil {
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

	return nil
}

func (m *Monitor) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.monitorLoop()
	return nil
}

func (m *Monitor) Stop() {
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
}

func (m *Monitor) monitorLoop() {
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

func (m *Monitor) checkTargets() {
	m.mu.RLock()
	targets := make([]target, len(m.targets))
	copy(targets, m.targets)
	m.mu.RUnlock()

	for _, t := range targets {
		if t.isFile {
			m.ensureWatcher(t.path)
		} else {
			files, err := m.scanDirectory(t.path, t.regex)
			if err != nil {
				continue
			}
			for _, file := range files {
				m.ensureWatcher(file)
			}
		}
	}

	m.cleanupWatchers()
}

func (m *Monitor) scanDirectory(dir string, pattern *regexp.Regexp) ([]string, error) {
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

func (m *Monitor) ensureWatcher(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.watchers[path]; exists {
		return
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return
	}

	w := newFileWatcher(path, m.publish)
	m.watchers[path] = w

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		w.watch(m.ctx)

		m.mu.Lock()
		delete(m.watchers, path)
		m.mu.Unlock()
	}()
}

func (m *Monitor) cleanupWatchers() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for path, w := range m.watchers {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			w.stop()
			delete(m.watchers, path)
		}
	}
}