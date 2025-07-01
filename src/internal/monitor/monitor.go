// File: logwisp/src/internal/monitor/monitor.go
package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogEntry represents a log line to be streamed
type LogEntry struct {
	Time    time.Time       `json:"time"`
	Source  string          `json:"source"`
	Level   string          `json:"level,omitempty"`
	Message string          `json:"message"`
	Fields  json.RawMessage `json:"fields,omitempty"`
}

// Monitor watches files and directories for log entries
type Monitor struct {
	callback func(LogEntry)
	targets  []target
	watchers map[string]*fileWatcher
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

type target struct {
	path    string
	pattern string
}

// New creates a new monitor instance
func New(callback func(LogEntry)) *Monitor {
	return &Monitor{
		callback: callback,
		watchers: make(map[string]*fileWatcher),
	}
}

// AddTarget adds a path to monitor
func (m *Monitor) AddTarget(path, pattern string) error {
	// Validate path exists
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("invalid path %s: %w", path, err)
	}

	// Store target
	m.mu.Lock()
	m.targets = append(m.targets, target{
		path:    path,
		pattern: pattern,
	})
	m.mu.Unlock()

	// If monitoring a file directly
	if !info.IsDir() {
		pattern = filepath.Base(path)
		path = filepath.Dir(path)
	}

	return nil
}

// Start begins monitoring all targets
func (m *Monitor) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)

	// Start monitor loop
	m.wg.Add(1)
	go m.monitorLoop()

	return nil
}

// Stop halts monitoring
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()

	// Close all watchers
	m.mu.Lock()
	for _, w := range m.watchers {
		w.close()
	}
	m.mu.Unlock()
}

// monitorLoop periodically checks for new files and monitors them
func (m *Monitor) monitorLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkTargets()
		}
	}
}

// checkTargets scans for files matching patterns
func (m *Monitor) checkTargets() {
	m.mu.RLock()
	targets := make([]target, len(m.targets))
	copy(targets, m.targets)
	m.mu.RUnlock()

	for _, t := range targets {
		matches, err := filepath.Glob(filepath.Join(t.path, t.pattern))
		if err != nil {
			continue
		}

		for _, file := range matches {
			m.ensureWatcher(file)
		}
	}
}

// ensureWatcher creates a watcher if it doesn't exist
func (m *Monitor) ensureWatcher(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.watchers[path]; exists {
		return
	}

	w := newFileWatcher(path, m.callback)
	m.watchers[path] = w

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		w.watch(m.ctx)

		// Remove watcher when done
		m.mu.Lock()
		delete(m.watchers, path)
		m.mu.Unlock()
	}()
}

// fileWatcher monitors a single file
type fileWatcher struct {
	path     string
	callback func(LogEntry)
	position int64
	mu       sync.Mutex
}

func newFileWatcher(path string, callback func(LogEntry)) *fileWatcher {
	return &fileWatcher{
		path:     path,
		callback: callback,
	}
}

// watch monitors the file for new content
func (w *fileWatcher) watch(ctx context.Context) {
	// Initial read to position at end
	if err := w.seekToEnd(); err != nil {
		return
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.checkFile()
		}
	}
}

// seekToEnd positions at the end of file
func (w *fileWatcher) seekToEnd() error {
	file, err := os.Open(w.path)
	if err != nil {
		return err
	}
	defer file.Close()

	pos, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.position = pos
	w.mu.Unlock()

	return nil
}

// checkFile reads new content
func (w *fileWatcher) checkFile() error {
	file, err := os.Open(w.path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get current file size
	info, err := file.Stat()
	if err != nil {
		return err
	}

	w.mu.Lock()
	pos := w.position
	w.mu.Unlock()

	// Check for rotation (file smaller than position)
	if info.Size() < pos {
		pos = 0
	}

	// Seek to last position
	if _, err := file.Seek(pos, io.SeekStart); err != nil {
		return err
	}

	// Read new lines
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry := w.parseLine(line)
		w.callback(entry)
	}

	// Update position
	newPos, err := file.Seek(0, io.SeekCurrent)
	if err == nil {
		w.mu.Lock()
		w.position = newPos
		w.mu.Unlock()
	}

	return nil
}

// parseLine attempts to parse JSON or returns plain text
func (w *fileWatcher) parseLine(line string) LogEntry {
	// Try to parse as JSON log
	var jsonLog struct {
		Time    string          `json:"time"`
		Level   string          `json:"level"`
		Message string          `json:"msg"`
		Fields  json.RawMessage `json:"fields"`
	}

	if err := json.Unmarshal([]byte(line), &jsonLog); err == nil {
		// Parse timestamp
		timestamp, err := time.Parse(time.RFC3339Nano, jsonLog.Time)
		if err != nil {
			timestamp = time.Now()
		}

		return LogEntry{
			Time:    timestamp,
			Source:  filepath.Base(w.path),
			Level:   jsonLog.Level,
			Message: jsonLog.Message,
			Fields:  jsonLog.Fields,
		}
	}

	// Plain text log
	return LogEntry{
		Time:    time.Now(),
		Source:  filepath.Base(w.path),
		Message: line,
	}
}

// close cleans up the watcher
func (w *fileWatcher) close() {
	// Nothing to clean up in this simple implementation
}