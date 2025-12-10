package file

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
	"logwisp/src/internal/plugin"
	"logwisp/src/internal/session"
	"logwisp/src/internal/source"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
)

// init registers the component in plugin factory
func init() {
	if err := plugin.RegisterSource("file", NewFileSourcePlugin); err != nil {
		panic(fmt.Sprintf("failed to register file source: %v", err))
	}
}

// FileSource monitors log files and tails them
type FileSource struct {
	// Plugin identity and session management
	id      string
	proxy   *session.Proxy
	session *session.Session

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

// NewFileSourcePlugin creates a file source through plugin factory
func NewFileSourcePlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (source.Source, error) {
	// Step 1: Create empty config struct with defaults
	opts := &config.FileSourceOptions{
		Directory:       "",    // Required field - no default
		Pattern:         "*",   // Default pattern
		CheckIntervalMS: 100,   // Default check interval
		Recursive:       false, // Default recursive
	}

	// Step 2: Use lconfig to scan map into struct (overriding defaults)
	if err := lconfig.ScanMap(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Step 3: Validate required fields
	if opts.Directory == "" {
		return nil, fmt.Errorf("directory is mandatory")
	}

	if opts.CheckIntervalMS < 10 {
		return nil, fmt.Errorf("check_interval_ms must be at least 10ms")
	}

	// Step 4: Create and return plugin instance
	fs := &FileSource{
		id:          id,
		proxy:       proxy,
		config:      opts,
		subscribers: make([]chan core.LogEntry, 0),
		watchers:    make(map[string]*fileWatcher),
		logger:      logger,
	}
	fs.lastEntryTime.Store(time.Time{})

	fs.session = proxy.CreateSession(
		fmt.Sprintf("file:///%s/%s", opts.Directory, opts.Pattern),
		map[string]any{
			"instance_id": id,
			"type":        "file",
			"directory":   opts.Directory,
			"pattern":     opts.Pattern,
		},
	)

	fs.logger.Info("msg", "File source initialized",
		"component", "file_source",
		"instance_id", id,
		"directory", opts.Directory,
		"pattern", opts.Pattern)

	return fs, nil
}

// Capabilities returns supported capabilities
func (fs *FileSource) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware, // Tracks sessions per file
		core.CapMultiSession, // Multiple file sessions
	}
}

// Subscribe returns a channel for receiving log entries
func (fs *FileSource) Subscribe() <-chan core.LogEntry {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	ch := make(chan core.LogEntry, 1000)
	fs.subscribers = append(fs.subscribers, ch)
	return ch
}

// Start begins the file monitoring loop
func (fs *FileSource) Start() error {
	fs.ctx, fs.cancel = context.WithCancel(context.Background())
	fs.startTime = time.Now()
	fs.wg.Add(1)
	go fs.monitorLoop()

	fs.logger.Info("msg", "File source started",
		"component", "File_source",
		"path", fs.config.Directory,
		"pattern", fs.config.Pattern,
		"check_interval_ms", fs.config.CheckIntervalMS)
	return nil
}

// Stop gracefully shuts down the file source and all file watchers
func (fs *FileSource) Stop() {
	if fs.cancel != nil {
		fs.cancel()
	}
	fs.wg.Wait()

	fs.proxy.RemoveSession(fs.id)

	fs.mu.Lock()
	for _, w := range fs.watchers {
		w.stop()
	}
	for _, ch := range fs.subscribers {
		close(ch)
	}
	fs.mu.Unlock()

	fs.logger.Info("msg", "File source stopped",
		"component", "file_source",
		"instance_id", fs.id,
		"path", fs.config.Directory)
}

// GetStats returns the source's statistics, including active watchers.
func (fs *FileSource) GetStats() source.SourceStats {
	lastEntry, _ := fs.lastEntryTime.Load().(time.Time)

	fs.mu.RLock()
	watcherCount := int64(len(fs.watchers))
	details := make(map[string]any)

	// Add watcher details
	watchers := make([]map[string]any, 0, watcherCount)
	for _, w := range fs.watchers {
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
	fs.mu.RUnlock()

	return source.SourceStats{
		ID:             fs.id,
		Type:           "file",
		TotalEntries:   fs.totalEntries.Load(),
		DroppedEntries: fs.droppedEntries.Load(),
		StartTime:      fs.startTime,
		LastEntryTime:  lastEntry,
		Details:        details,
	}
}

// monitorLoop periodically scans path for new or changed files.
func (fs *FileSource) monitorLoop() {
	defer fs.wg.Done()

	fs.checkTargets()

	ticker := time.NewTicker(time.Duration(fs.config.CheckIntervalMS) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-fs.ctx.Done():
			return
		case <-ticker.C:
			fs.checkTargets()
		}
	}
}

// checkTargets finds matching files and ensures watchers are running for them.
func (fs *FileSource) checkTargets() {
	files, err := fs.scanFile()
	if err != nil {
		fs.logger.Warn("msg", "Failed to scan file",
			"component", "file_source",
			"path", fs.config.Directory,
			"pattern", fs.config.Pattern,
			"error", err)
		return
	}

	for _, file := range files {
		fs.ensureWatcher(file)
	}

	fs.cleanupWatchers()
}

// ensureWatcher creates and starts a new file watcher if one doesn't exist for the given path.
func (fs *FileSource) ensureWatcher(path string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, exists := fs.watchers[path]; exists {
		return
	}

	w := newFileWatcher(path, fs.publish, fs.logger)
	fs.watchers[path] = w

	fs.logger.Debug("msg", "Created file watcher",
		"component", "file_source",
		"path", path)

	fs.wg.Add(1)
	go func() {
		defer fs.wg.Done()
		if err := w.watch(fs.ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				fs.logger.Debug("msg", "Watcher cancelled",
					"component", "file_source",
					"path", path)
			} else {
				fs.logger.Error("msg", "Watcher failed",
					"component", "file_source",
					"path", path,
					"error", err)
			}
		}

		fs.mu.Lock()
		delete(fs.watchers, path)
		fs.mu.Unlock()
	}()
}

// cleanupWatchers stops and removes watchers for files that no longer exist.
func (fs *FileSource) cleanupWatchers() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	for path, w := range fs.watchers {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			w.stop()
			delete(fs.watchers, path)
			fs.logger.Debug("msg", "Cleaned up watcher for non-existent file",
				"component", "file_source",
				"path", path)
		}
	}
}

// publish sends a log entry to all subscribers.
func (fs *FileSource) publish(entry core.LogEntry) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	fs.totalEntries.Add(1)
	fs.lastEntryTime.Store(entry.Time)

	for _, ch := range fs.subscribers {
		select {
		case ch <- entry:
		default:
			fs.droppedEntries.Add(1)
			fs.logger.Debug("msg", "Dropped log entry - subscriber buffer full",
				"component", "file_source")
		}
	}
}

// scanFile finds all files in the configured path that match the pattern.
func (fs *FileSource) scanFile() ([]string, error) {
	entries, err := os.ReadDir(fs.config.Directory)
	if err != nil {
		return nil, err
	}

	// Convert glob pattern to regex
	regexPattern := globToRegex(fs.config.Pattern)
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
			files = append(files, filepath.Join(fs.config.Directory, name))
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