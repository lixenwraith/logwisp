// FILE: src/internal/source/file_watcher.go
package source

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lixenwraith/log"
)

// WatcherInfo contains information about a file watcher
type WatcherInfo struct {
	Path         string
	Size         int64
	Position     int64
	ModTime      time.Time
	EntriesRead  uint64
	LastReadTime time.Time
	Rotations    int
}

type fileWatcher struct {
	path         string
	callback     func(LogEntry)
	position     int64
	size         int64
	inode        uint64
	modTime      time.Time
	mu           sync.Mutex
	stopped      bool
	rotationSeq  int
	entriesRead  atomic.Uint64
	lastReadTime atomic.Value // time.Time
	logger       *log.Logger
}

func newFileWatcher(path string, callback func(LogEntry), logger *log.Logger) *fileWatcher {
	w := &fileWatcher{
		path:     path,
		callback: callback,
		position: -1,
		logger:   logger,
	}
	w.lastReadTime.Store(time.Time{})
	return w
}

func (w *fileWatcher) watch(ctx context.Context) error {
	if err := w.seekToEnd(); err != nil {
		return fmt.Errorf("seekToEnd failed: %w", err)
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if w.isStopped() {
				return fmt.Errorf("watcher stopped")
			}
			if err := w.checkFile(); err != nil {
				// Log error but continue watching
				w.logger.Warn("msg", "checkFile error", "error", err)
			}
		}
	}
}

// FILE: src/internal/source/file_watcher.go
func (w *fileWatcher) seekToEnd() error {
	file, err := os.Open(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			w.mu.Lock()
			w.position = 0
			w.size = 0
			w.modTime = time.Now()
			w.inode = 0
			w.mu.Unlock()
			return nil
		}
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Keep existing position (including 0)
	// First time initialization seeks to the end of the file
	if w.position == -1 {
		pos, err := file.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}
		w.position = pos
	}

	w.size = info.Size()
	w.modTime = info.ModTime()
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		w.inode = stat.Ino
	}

	return nil
}

func (w *fileWatcher) checkFile() error {
	file, err := os.Open(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, keep watching
			return nil
		}
		w.logger.Error("msg", "Failed to open file for checking",
			"component", "file_watcher",
			"path", w.path,
			"error", err)
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		w.logger.Error("msg", "Failed to stat file",
			"component", "file_watcher",
			"path", w.path,
			"error", err)
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

	// Handle first time seeing a file that didn't exist before
	if oldInode == 0 && currentInode != 0 {
		// File just appeared, don't treat as rotation
		w.mu.Lock()
		w.inode = currentInode
		w.size = currentSize
		w.modTime = currentModTime
		// Position stays at 0 for new files
		w.mu.Unlock()
		// Don't return here - continue to read content
	}

	// Check for rotation
	rotated := false
	rotationReason := ""
	startPos := oldPos

	// Rotation detection
	if currentSize < oldSize {
		// File was truncated
		rotated = true
		rotationReason = "size decrease"
	} else if currentModTime.Before(oldModTime) && currentSize <= oldSize {
		// Modification time went backwards (logrotate behavior)
		rotated = true
		rotationReason = "modification time reset"
	} else if oldPos > currentSize+1024 {
		// Our position is way beyond file size
		rotated = true
		rotationReason = "position beyond file size"
	} else if oldInode != 0 && currentInode != 0 && currentInode != oldInode {
		// Inode changed - distinguish between rotation and atomic save
		if currentSize == 0 {
			// Empty file with new inode = likely rotation
			rotated = true
			rotationReason = "inode change with empty file"
		} else if currentSize < oldPos {
			// New file is smaller than our position = rotation
			rotated = true
			rotationReason = "inode change with size less than position"
		} else {
			// Inode changed but file has content and size >= position
			// This is likely an atomic save by an editor
			// Update inode but keep position
			w.mu.Lock()
			w.inode = currentInode
			w.mu.Unlock()

			w.logger.Debug("msg", "Atomic file update detected",
				"component", "file_watcher",
				"path", w.path,
				"old_inode", oldInode,
				"new_inode", currentInode,
				"position", oldPos,
				"size", currentSize)
		}
	}

	if rotated {
		startPos = 0
		w.mu.Lock()
		w.rotationSeq++
		seq := w.rotationSeq
		w.inode = currentInode
		w.position = 0 // Reset position on rotation
		w.mu.Unlock()

		w.callback(LogEntry{
			Time:    time.Now(),
			Source:  filepath.Base(w.path),
			Level:   "INFO",
			Message: fmt.Sprintf("Log rotation detected (#%d): %s", seq, rotationReason),
		})

		w.logger.Info("msg", "Log rotation detected",
			"component", "file_watcher",
			"path", w.path,
			"sequence", seq,
			"reason", rotationReason)
	}

	// Only read if there's new content
	if currentSize > startPos {
		if _, err := file.Seek(startPos, io.SeekStart); err != nil {
			return err
		}

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}

			rawSize := len(line)
			entry := w.parseLine(line)
			entry.RawSize = rawSize

			w.callback(entry)
			w.entriesRead.Add(1)
			w.lastReadTime.Store(time.Now())
		}

		if err := scanner.Err(); err != nil {
			w.logger.Error("msg", "Scanner error while reading file",
				"component", "file_watcher",
				"path", w.path,
				"position", startPos,
				"error", err)
			return err
		}

		// Update position after successful read
		currentPos, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			// Log error but don't fail - best effort position tracking
			w.logger.Warn("msg", "Failed to get file position", "error", err)
			// Use size as fallback position
			currentPos = currentSize
		}

		w.mu.Lock()
		w.position = currentPos
		w.size = currentSize
		w.modTime = currentModTime
		if !rotated && currentInode != 0 {
			w.inode = currentInode
		}
		w.mu.Unlock()

		return scanner.Err()
	}

	// Update metadata even if no new content
	w.mu.Lock()
	w.size = currentSize
	w.modTime = currentModTime
	if currentInode != 0 {
		w.inode = currentInode
	}
	w.mu.Unlock()

	return nil
}

func (w *fileWatcher) parseLine(line string) LogEntry {
	var jsonLog struct {
		Time    string          `json:"time"`
		Level   string          `json:"level"`
		Message string          `json:"msg"`
		Fields  json.RawMessage `json:"fields"`
	}

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

	level := extractLogLevel(line)

	return LogEntry{
		Time:    time.Now(),
		Source:  filepath.Base(w.path),
		Level:   level,
		Message: line,
	}
}

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

func (w *fileWatcher) getInfo() WatcherInfo {
	w.mu.Lock()
	info := WatcherInfo{
		Path:        w.path,
		Size:        w.size,
		Position:    w.position,
		ModTime:     w.modTime,
		EntriesRead: w.entriesRead.Load(),
		Rotations:   w.rotationSeq,
	}
	w.mu.Unlock()

	if lastRead, ok := w.lastReadTime.Load().(time.Time); ok {
		info.LastReadTime = lastRead
	}

	return info
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