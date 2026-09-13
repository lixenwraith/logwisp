package file

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"logwisp/internal/core"
	"logwisp/internal/source"

	"github.com/lixenwraith/log"
)

// WatcherInfo contains snapshot information about a file watcher's state
type WatcherInfo struct {
	Directory    string
	Size         int64
	Position     int64
	ModTime      time.Time
	EntriesRead  uint64
	LastReadTime time.Time
	Rotations    int64
}

// fileWatcher tails a single file, handles rotations, and sends new lines to a callback
type fileWatcher struct {
	directory    string
	callback     func(core.LogEntry)
	raw          bool
	position     int64
	size         int64
	inode        uint64
	modTime      time.Time
	mu           sync.Mutex
	stopped      bool
	rotationSeq  int64
	entriesRead  atomic.Uint64
	lastReadTime atomic.Value // time.Time
	logger       *log.Logger
}

// newFileWatcher creates a new watcher for a specific file path.
// A start position of 0 reads an existing file whole; -1 seeks to its end.
func newFileWatcher(directory string, raw, fromStart bool, callback func(core.LogEntry), logger *log.Logger) *fileWatcher {
	position := int64(-1)
	if fromStart {
		position = 0
	}
	w := &fileWatcher{
		directory: directory,
		callback:  callback,
		raw:       raw,
		position:  position,
		logger:    logger,
	}
	w.lastReadTime.Store(time.Time{})
	return w
}

// watch starts the main monitoring loop for the file
func (w *fileWatcher) watch(ctx context.Context) error {
	if err := w.initPosition(); err != nil {
		return fmt.Errorf("initPosition failed: %w", err)
	}

	ticker := time.NewTicker(core.FileWatcherPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if w.isStopped() {
				return nil
			}
			if err := w.checkFile(); err != nil {
				// Log error but continue watching
				w.logger.Warn("msg", "checkFile error", "error", err)
			}
		}
	}
}

// stop signals the watcher to terminate its loop
func (w *fileWatcher) stop() {
	w.mu.Lock()
	w.stopped = true
	w.mu.Unlock()
}

// getInfo returns a snapshot of the watcher's current statistics
func (w *fileWatcher) getInfo() WatcherInfo {
	w.mu.Lock()
	info := WatcherInfo{
		Directory:   w.directory,
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

// checkFile examines the file for changes, rotations, or new content
func (w *fileWatcher) checkFile() error {
	file, err := os.Open(w.directory)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, keep watching
			return nil
		}
		w.logger.Error("msg", "Failed to open file for checking",
			"component", "file_watcher",
			"directory", w.directory,
			"error", err)
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		w.logger.Error("msg", "Failed to stat file",
			"component", "file_watcher",
			"directory", w.directory,
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
				"directory", w.directory,
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

		w.callback(core.LogEntry{
			Time:    time.Now(),
			Source:  filepath.Base(w.directory),
			Level:   "INFO",
			Message: fmt.Sprintf("Log rotation detected (#%d): %s", seq, rotationReason),
		})

		w.logger.Info("msg", "Log rotation detected",
			"component", "file_watcher",
			"directory", w.directory,
			"sequence", seq,
			"reason", rotationReason)
	}

	// Read if there's new content OR if we need to continue from position
	if currentSize > startPos {
		if _, err := file.Seek(startPos, io.SeekStart); err != nil {
			return err
		}

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), core.MaxLogEntryBytes)

		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}

			rawSize := int64(len(line))
			entry := w.parseLine(line)
			entry.RawSize = rawSize

			w.callback(entry)
			w.entriesRead.Add(1)
			w.lastReadTime.Store(time.Now())
		}

		if err := scanner.Err(); err != nil {
			w.logger.Error("msg", "Scanner error while reading file",
				"component", "file_watcher",
				"directory", w.directory,
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

// initPosition records the file's metadata and, unless the watcher was created
// to read from the start, sets the initial read position to the end
func (w *fileWatcher) initPosition() error {
	file, err := os.Open(w.directory)
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

// isStopped checks if the watcher has been instructed to stop
func (w *fileWatcher) isStopped() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stopped
}

// parseLine converts a line into an entry, as JSON when nothing would be lost
func (w *fileWatcher) parseLine(line string) core.LogEntry {
	if w.raw {
		// Newline restored: sinks write the payload as it stands
		return core.LogEntry{
			Time:    time.Now(),
			Source:  filepath.Base(w.directory),
			Level:   source.ExtractLogLevel(line),
			Message: line + "\n",
		}
	}

	if entry, ok := w.parseJSON(line); ok {
		return entry
	}

	return core.LogEntry{
		Time:    time.Now(),
		Source:  filepath.Base(w.directory),
		Level:   source.ExtractLogLevel(line),
		Message: line,
	}
}

// parseJSON decodes a line into the entry envelope. A top-level key LogEntry
// cannot carry refuses the whole line, so a richer record reaches the pipeline
// as text rather than silently reduced to the four keys kept here.
func (w *fileWatcher) parseJSON(line string) (core.LogEntry, bool) {
	if len(line) == 0 || line[0] != '{' {
		return core.LogEntry{}, false
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &obj); err != nil || len(obj) == 0 {
		return core.LogEntry{}, false
	}

	entry := core.LogEntry{Time: time.Now(), Source: filepath.Base(w.directory)}
	for key, val := range obj {
		var err error
		switch key {
		case "time":
			var ts string
			if json.Unmarshal(val, &ts) == nil {
				if t, terr := time.Parse(time.RFC3339Nano, ts); terr == nil {
					entry.Time = t
				}
			}
		case "level":
			err = json.Unmarshal(val, &entry.Level)
		case "msg":
			err = json.Unmarshal(val, &entry.Message)
		case "fields":
			entry.Fields = val
		default:
			return core.LogEntry{}, false
		}
		if err != nil {
			return core.LogEntry{}, false
		}
	}

	return entry, true
}
