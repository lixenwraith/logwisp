// FILE: logwisp/src/internal/source/file.go
package source

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// FileSource monitors log files and tails them.
type FileSource struct {
	// Configuration
	config *config.FileSourceOptions

	// Application
	subscribers []chan core.LogEntry
	watchers    map[string]*fileWatcher
	logger      *log.Logger

	// Runtime
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Statistics
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
}

// NewFileSource creates a new file monitoring source.
func NewFileSource(opts *config.FileSourceOptions, logger *log.Logger) (*FileSource, error) {
	if opts == nil {
		return nil, fmt.Errorf("file source options cannot be nil")
	}

	ds := &FileSource{
		config:    opts,
		watchers:  make(map[string]*fileWatcher),
		startTime: time.Now(),
		logger:    logger,
	}
	ds.lastEntryTime.Store(time.Time{})

	return ds, nil
}

// Subscribe returns a channel for receiving log entries.
func (ds *FileSource) Subscribe() <-chan core.LogEntry {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	ch := make(chan core.LogEntry, 1000)
	ds.subscribers = append(ds.subscribers, ch)
	return ch
}

// Start begins the file monitoring loop.
func (ds *FileSource) Start() error {
	ds.ctx, ds.cancel = context.WithCancel(context.Background())
	ds.wg.Add(1)
	go ds.monitorLoop()

	ds.logger.Info("msg", "File source started",
		"component", "File_source",
		"path", ds.config.Directory,
		"pattern", ds.config.Pattern,
		"check_interval_ms", ds.config.CheckIntervalMS)
	return nil
}

// Stop gracefully shuts down the file source and all file watchers.
func (ds *FileSource) Stop() {
	if ds.cancel != nil {
		ds.cancel()
	}
	ds.wg.Wait()

	ds.mu.Lock()
	for _, w := range ds.watchers {
		w.stop()
	}
	for _, ch := range ds.subscribers {
		close(ch)
	}
	ds.mu.Unlock()

	ds.logger.Info("msg", "File source stopped",
		"component", "file_source",
		"path", ds.config.Directory)
}

// GetStats returns the source's statistics, including active watchers.
func (ds *FileSource) GetStats() SourceStats {
	lastEntry, _ := ds.lastEntryTime.Load().(time.Time)

	ds.mu.RLock()
	watcherCount := int64(len(ds.watchers))
	details := make(map[string]any)

	// Add watcher details
	watchers := make([]map[string]any, 0, watcherCount)
	for _, w := range ds.watchers {
		info := w.getInfo()
		watchers = append(watchers, map[string]any{
			"directory":    info.Directory,
			"size":         info.Size,
			"position":     info.Position,
			"entries_read": info.EntriesRead,
			"rotations":    info.Rotations,
			"last_read":    info.LastReadTime,
		})
	}
	details["watchers"] = watchers
	details["active_watchers"] = watcherCount
	ds.mu.RUnlock()

	return SourceStats{
		Type:           "file",
		TotalEntries:   ds.totalEntries.Load(),
		DroppedEntries: ds.droppedEntries.Load(),
		StartTime:      ds.startTime,
		LastEntryTime:  lastEntry,
		Details:        details,
	}
}

// monitorLoop periodically scans path for new or changed files.
func (ds *FileSource) monitorLoop() {
	defer ds.wg.Done()

	ds.checkTargets()

	ticker := time.NewTicker(time.Duration(ds.config.CheckIntervalMS) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ds.ctx.Done():
			return
		case <-ticker.C:
			ds.checkTargets()
		}
	}
}

// checkTargets finds matching files and ensures watchers are running for them.
func (ds *FileSource) checkTargets() {
	files, err := ds.scanFile()
	if err != nil {
		ds.logger.Warn("msg", "Failed to scan file",
			"component", "file_source",
			"path", ds.config.Directory,
			"pattern", ds.config.Pattern,
			"error", err)
		return
	}

	for _, file := range files {
		ds.ensureWatcher(file)
	}

	ds.cleanupWatchers()
}

// ensureWatcher creates and starts a new file watcher if one doesn't exist for the given path.
func (ds *FileSource) ensureWatcher(path string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, exists := ds.watchers[path]; exists {
		return
	}

	w := newFileWatcher(path, ds.publish, ds.logger)
	ds.watchers[path] = w

	ds.logger.Debug("msg", "Created file watcher",
		"component", "file_source",
		"path", path)

	ds.wg.Add(1)
	go func() {
		defer ds.wg.Done()
		if err := w.watch(ds.ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				ds.logger.Debug("msg", "Watcher cancelled",
					"component", "file_source",
					"path", path)
			} else {
				ds.logger.Error("msg", "Watcher failed",
					"component", "file_source",
					"path", path,
					"error", err)
			}
		}

		ds.mu.Lock()
		delete(ds.watchers, path)
		ds.mu.Unlock()
	}()
}

// cleanupWatchers stops and removes watchers for files that no longer exist.
func (ds *FileSource) cleanupWatchers() {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	for path, w := range ds.watchers {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			w.stop()
			delete(ds.watchers, path)
			ds.logger.Debug("msg", "Cleaned up watcher for non-existent file",
				"component", "file_source",
				"path", path)
		}
	}
}

// publish sends a log entry to all subscribers.
func (ds *FileSource) publish(entry core.LogEntry) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	ds.totalEntries.Add(1)
	ds.lastEntryTime.Store(entry.Time)

	for _, ch := range ds.subscribers {
		select {
		case ch <- entry:
		default:
			ds.droppedEntries.Add(1)
			ds.logger.Debug("msg", "Dropped log entry - subscriber buffer full",
				"component", "file_source")
		}
	}
}

// scanFile finds all files in the configured path that match the pattern.
func (ds *FileSource) scanFile() ([]string, error) {
	entries, err := os.ReadDir(ds.config.Directory)
	if err != nil {
		return nil, err
	}

	// Convert glob pattern to regex
	regexPattern := globToRegex(ds.config.Pattern)
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern regex: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if re.MatchString(name) {
			files = append(files, filepath.Join(ds.config.Directory, name))
		}
	}

	return files, nil
}

// globToRegex converts a simple glob pattern to a regular expression.
func globToRegex(glob string) string {
	regex := regexp.QuoteMeta(glob)
	regex = strings.ReplaceAll(regex, `\*`, `.*`)
	regex = strings.ReplaceAll(regex, `\?`, `.`)
	return "^" + regex + "$"
}