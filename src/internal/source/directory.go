// FILE: logwisp/src/internal/source/directory.go
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

// Monitors a directory for log files
type DirectorySource struct {
	path           string
	pattern        string
	checkInterval  time.Duration
	subscribers    []chan core.LogEntry
	watchers       map[string]*fileWatcher
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
	logger         *log.Logger
}

// Creates a new directory monitoring source
func NewDirectorySource(options map[string]any, logger *log.Logger) (*DirectorySource, error) {
	path, ok := options["path"].(string)
	if !ok {
		return nil, fmt.Errorf("directory source requires 'path' option")
	}

	pattern, _ := options["pattern"].(string)
	if pattern == "" {
		pattern = "*"
	}

	checkInterval := 100 * time.Millisecond
	if ms, ok := options["check_interval_ms"].(int64); ok && ms > 0 {
		checkInterval = time.Duration(ms) * time.Millisecond
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path %s: %w", path, err)
	}

	ds := &DirectorySource{
		path:          absPath,
		pattern:       pattern,
		checkInterval: checkInterval,
		watchers:      make(map[string]*fileWatcher),
		startTime:     time.Now(),
		logger:        logger,
	}
	ds.lastEntryTime.Store(time.Time{})

	return ds, nil
}

func (ds *DirectorySource) Subscribe() <-chan core.LogEntry {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	ch := make(chan core.LogEntry, 1000)
	ds.subscribers = append(ds.subscribers, ch)
	return ch
}

func (ds *DirectorySource) Start() error {
	ds.ctx, ds.cancel = context.WithCancel(context.Background())
	ds.wg.Add(1)
	go ds.monitorLoop()

	ds.logger.Info("msg", "Directory source started",
		"component", "directory_source",
		"path", ds.path,
		"pattern", ds.pattern,
		"check_interval_ms", ds.checkInterval.Milliseconds())
	return nil
}

func (ds *DirectorySource) Stop() {
	if ds.cancel != nil {
		ds.cancel()
	}
	ds.wg.Wait()

	ds.mu.Lock()
	for _, w := range ds.watchers {
		w.close()
	}
	for _, ch := range ds.subscribers {
		close(ch)
	}
	ds.mu.Unlock()

	ds.logger.Info("msg", "Directory source stopped",
		"component", "directory_source",
		"path", ds.path)
}

func (ds *DirectorySource) GetStats() SourceStats {
	lastEntry, _ := ds.lastEntryTime.Load().(time.Time)

	ds.mu.RLock()
	watcherCount := int64(len(ds.watchers))
	details := make(map[string]any)

	// Add watcher details
	watchers := make([]map[string]any, 0, watcherCount)
	for _, w := range ds.watchers {
		info := w.getInfo()
		watchers = append(watchers, map[string]any{
			"path":         info.Path,
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
		Type:           "directory",
		TotalEntries:   ds.totalEntries.Load(),
		DroppedEntries: ds.droppedEntries.Load(),
		StartTime:      ds.startTime,
		LastEntryTime:  lastEntry,
		Details:        details,
	}
}

func (ds *DirectorySource) publish(entry core.LogEntry) {
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
				"component", "directory_source")
		}
	}
}

func (ds *DirectorySource) monitorLoop() {
	defer ds.wg.Done()

	ds.checkTargets()

	ticker := time.NewTicker(ds.checkInterval)
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

func (ds *DirectorySource) checkTargets() {
	files, err := ds.scanDirectory()
	if err != nil {
		ds.logger.Warn("msg", "Failed to scan directory",
			"component", "directory_source",
			"path", ds.path,
			"pattern", ds.pattern,
			"error", err)
		return
	}

	for _, file := range files {
		ds.ensureWatcher(file)
	}

	ds.cleanupWatchers()
}

func (ds *DirectorySource) scanDirectory() ([]string, error) {
	entries, err := os.ReadDir(ds.path)
	if err != nil {
		return nil, err
	}

	// Convert glob pattern to regex
	regexPattern := globToRegex(ds.pattern)
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
			files = append(files, filepath.Join(ds.path, name))
		}
	}

	return files, nil
}

func (ds *DirectorySource) ensureWatcher(path string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, exists := ds.watchers[path]; exists {
		return
	}

	w := newFileWatcher(path, ds.publish, ds.logger)
	ds.watchers[path] = w

	ds.logger.Debug("msg", "Created file watcher",
		"component", "directory_source",
		"path", path)

	ds.wg.Add(1)
	go func() {
		defer ds.wg.Done()
		if err := w.watch(ds.ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				ds.logger.Debug("msg", "Watcher cancelled",
					"component", "directory_source",
					"path", path)
			} else {
				ds.logger.Error("msg", "Watcher failed",
					"component", "directory_source",
					"path", path,
					"error", err)
			}
		}

		ds.mu.Lock()
		delete(ds.watchers, path)
		ds.mu.Unlock()
	}()
}

func (ds *DirectorySource) cleanupWatchers() {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	for path, w := range ds.watchers {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			w.stop()
			delete(ds.watchers, path)
			ds.logger.Debug("msg", "Cleaned up watcher for non-existent file",
				"component", "directory_source",
				"path", path)
		}
	}
}

func globToRegex(glob string) string {
	regex := regexp.QuoteMeta(glob)
	regex = strings.ReplaceAll(regex, `\*`, `.*`)
	regex = strings.ReplaceAll(regex, `\?`, `.`)
	return "^" + regex + "$"
}

func (ds *DirectorySource) SetAuth(auth *config.AuthConfig) {
	// Authentication does not apply to directory source
}