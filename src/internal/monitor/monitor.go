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
	"regexp"
	"strings"
	"sync"
	"syscall"
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
	callback      func(LogEntry)
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
	regex   *regexp.Regexp // FIXED: Compiled pattern for performance
}

// New creates a new monitor instance
func New(callback func(LogEntry)) *Monitor {
	return &Monitor{
		callback:      callback,
		watchers:      make(map[string]*fileWatcher),
		checkInterval: 100 * time.Millisecond,
	}
}

// SetCheckInterval configures the file check frequency
func (m *Monitor) SetCheckInterval(interval time.Duration) {
	m.mu.Lock()
	m.checkInterval = interval
	m.mu.Unlock()
}

// AddTarget adds a path to monitor with enhanced pattern support
func (m *Monitor) AddTarget(path, pattern string, isFile bool) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path %s: %w", path, err)
	}

	var compiledRegex *regexp.Regexp
	if !isFile && pattern != "" {
		// FIXED: Convert glob pattern to regex for better matching
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

// Start begins monitoring with configurable interval
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
	m.mu.Unlock()
}

// FIXED: Enhanced monitoring loop with configurable interval
func (m *Monitor) monitorLoop() {
	defer m.wg.Done()

	// Initial scan
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

			// Update ticker interval if changed
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

// FIXED: Enhanced target checking with better file discovery
func (m *Monitor) checkTargets() {
	m.mu.RLock()
	targets := make([]target, len(m.targets))
	copy(targets, m.targets)
	m.mu.RUnlock()

	for _, t := range targets {
		if t.isFile {
			m.ensureWatcher(t.path)
		} else {
			// FIXED: More efficient directory scanning
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

// FIXED: Optimized directory scanning
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

	w := newFileWatcher(path, m.callback)
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

// fileWatcher with enhanced rotation detection
type fileWatcher struct {
	path        string
	callback    func(LogEntry)
	position    int64
	size        int64
	inode       uint64
	modTime     time.Time
	mu          sync.Mutex
	stopped     bool
	rotationSeq int // FIXED: Track rotation sequence for logging
}

func newFileWatcher(path string, callback func(LogEntry)) *fileWatcher {
	return &fileWatcher{
		path:     path,
		callback: callback,
	}
}

func (w *fileWatcher) watch(ctx context.Context) {
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
			if w.isStopped() {
				return
			}
			w.checkFile()
		}
	}
}

// FIXED: Enhanced file state tracking for better rotation detection
func (w *fileWatcher) seekToEnd() error {
	file, err := os.Open(w.path)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	pos, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.position = pos
	w.size = info.Size()
	w.modTime = info.ModTime()

	// Get inode for rotation detection (Unix-specific)
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		w.inode = stat.Ino
	}
	w.mu.Unlock()

	return nil
}

// FIXED: Enhanced rotation detection with multiple signals
func (w *fileWatcher) checkFile() error {
	file, err := os.Open(w.path)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	w.mu.Lock()
	oldPos := w.position
	oldSize := w.size
	oldInode := w.inode
	oldModTime := w.modTime
	w.mu.Unlock()

	currentSize := info.Size()
	currentModTime := info.ModTime()
	var currentInode uint64

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		currentInode = stat.Ino
	}

	// FIXED: Multiple rotation detection methods
	rotated := false
	rotationReason := ""

	// Method 1: Inode change (most reliable on Unix)
	if oldInode != 0 && currentInode != 0 && currentInode != oldInode {
		rotated = true
		rotationReason = "inode change"
	}

	// Method 2: File size decrease
	if !rotated && currentSize < oldSize {
		rotated = true
		rotationReason = "size decrease"
	}

	// Method 3: File modification time reset while size is same or smaller
	if !rotated && currentModTime.Before(oldModTime) && currentSize <= oldSize {
		rotated = true
		rotationReason = "modification time reset"
	}

	// Method 4: Large position vs current size discrepancy
	if !rotated && oldPos > currentSize+1024 { // Allow some buffer
		rotated = true
		rotationReason = "position beyond file size"
	}

	newPos := oldPos
	if rotated {
		newPos = 0
		w.mu.Lock()
		w.rotationSeq++
		seq := w.rotationSeq
		w.inode = currentInode
		w.mu.Unlock()

		// Log rotation event
		w.callback(LogEntry{
			Time:    time.Now(),
			Source:  filepath.Base(w.path),
			Level:   "INFO",
			Message: fmt.Sprintf("Log rotation detected (#%d): %s", seq, rotationReason),
		})
	}

	// Seek to position and read new content
	if _, err := file.Seek(newPos, io.SeekStart); err != nil {
		return err
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1MB max line

	lineCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry := w.parseLine(line)
		w.callback(entry)
		lineCount++
	}

	// Update file state
	if currentPos, err := file.Seek(0, io.SeekCurrent); err == nil {
		w.mu.Lock()
		w.position = currentPos
		w.size = currentSize
		w.modTime = currentModTime
		w.mu.Unlock()
	}

	return scanner.Err()
}

// FIXED: Enhanced log parsing with more level detection patterns
func (w *fileWatcher) parseLine(line string) LogEntry {
	var jsonLog struct {
		Time    string          `json:"time"`
		Level   string          `json:"level"`
		Message string          `json:"msg"`
		Fields  json.RawMessage `json:"fields"`
	}

	// Try JSON parsing first
	if err := json.Unmarshal([]byte(line), &jsonLog); err == nil {
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

	// Plain text with enhanced level extraction
	level := extractLogLevel(line)

	return LogEntry{
		Time:    time.Now(),
		Source:  filepath.Base(w.path),
		Level:   level,
		Message: line,
	}
}

// FIXED: More comprehensive log level extraction
func extractLogLevel(line string) string {
	patterns := []struct {
		patterns []string
		level    string
	}{
		{[]string{"[ERROR]", "ERROR:", " ERROR ", "ERR:", "[ERR]", "FATAL:", "[FATAL]"}, "ERROR"},
		{[]string{"[WARN]", "WARN:", " WARN ", "WARNING:", "[WARNING]"}, "WARN"},
		{[]string{"[INFO]", "INFO:", " INFO ", "[INF]", "INF:"}, "INFO"},
		{[]string{"[DEBUG]", "DEBUG:", " DEBUG ", "[DBG]", "DBG:"}, "DEBUG"},
		{[]string{"[TRACE]", "TRACE:", " TRACE "}, "TRACE"},
	}

	upperLine := strings.ToUpper(line)
	for _, group := range patterns {
		for _, pattern := range group.patterns {
			if strings.Contains(upperLine, pattern) {
				return group.level
			}
		}
	}

	return ""
}

// FIXED: Convert glob patterns to regex
func globToRegex(glob string) string {
	regex := regexp.QuoteMeta(glob)
	regex = strings.ReplaceAll(regex, `\*`, `.*`)
	regex = strings.ReplaceAll(regex, `\?`, `.`)
	return "^" + regex + "$"
}

func (w *fileWatcher) close() {
	w.stop()
}

func (w *fileWatcher) stop() {
	w.mu.Lock()
	w.stopped = true
	w.mu.Unlock()
}

func (w *fileWatcher) isStopped() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stopped
}