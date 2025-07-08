// FILE: src/internal/monitor/file_watcher.go
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
	"sync/atomic"
	"syscall"
	"time"
)

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
}

func newFileWatcher(path string, callback func(LogEntry)) *fileWatcher {
	w := &fileWatcher{
		path:     path,
		callback: callback,
		position: -1,
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
				fmt.Printf("[WARN] checkFile error for %s: %v\n", w.path, err)
			}
		}
	}
}

func (w *fileWatcher) seekToEnd() error {
	file, err := os.Open(w.path)
	if err != nil {
		// For non-existent files, initialize position to 0
		// This allows watching files that don't exist yet
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
	// Only seek to end if position was never set (-1)
	// This preserves position = 0 for new files while allowing
	// directory-discovered files to start reading from current position
	if w.position == -1 {
		pos, err := file.Seek(0, io.SeekEnd)
		if err != nil {
			w.mu.Unlock()
			return err
		}
		w.position = pos
	}

	w.size = info.Size()
	w.modTime = info.ModTime()
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		w.inode = stat.Ino
	}
	w.mu.Unlock()

	return nil
}

func (w *fileWatcher) checkFile() error {
	file, err := os.Open(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, keep watching
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
		// Keep position at 0 to read from beginning if this is a new file
		// or seek to end if we want to skip existing content
		if oldSize == 0 && w.position == 0 {
			// First time seeing this file, seek to end to skip existing content
			w.position = currentSize
		}
		w.mu.Unlock()
		return nil
	}

	// Check for rotation
	rotated := false
	rotationReason := ""

	if oldInode != 0 && currentInode != 0 && currentInode != oldInode {
		rotated = true
		rotationReason = "inode change"
	} else if currentSize < oldSize {
		rotated = true
		rotationReason = "size decrease"
	} else if currentModTime.Before(oldModTime) && currentSize <= oldSize {
		rotated = true
		rotationReason = "modification time reset"
	} else if oldPos > currentSize+1024 {
		rotated = true
		rotationReason = "position beyond file size"
	}

	startPos := oldPos
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

			entry := w.parseLine(line)
			w.callback(entry)
			w.entriesRead.Add(1)
			w.lastReadTime.Store(time.Now())
		}

		// Update position after successful read
		currentPos, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			// Log error but don't fail - position tracking is best effort
			fmt.Printf("[WARN] Failed to get file position for %s: %v\n", w.path, err)
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

func globToRegex(glob string) string {
	regex := regexp.QuoteMeta(glob)
	regex = strings.ReplaceAll(regex, `\*`, `.*`)
	regex = strings.ReplaceAll(regex, `\?`, `.`)
	return "^" + regex + "$"
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