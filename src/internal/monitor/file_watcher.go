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

type fileWatcher struct {
	path        string
	callback    func(LogEntry)
	position    int64
	size        int64
	inode       uint64
	modTime     time.Time
	mu          sync.Mutex
	stopped     bool
	rotationSeq int
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

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		w.inode = stat.Ino
	}
	w.mu.Unlock()

	return nil
}

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

	rotated := false
	rotationReason := ""

	if oldInode != 0 && currentInode != 0 && currentInode != oldInode {
		rotated = true
		rotationReason = "inode change"
	}

	if !rotated && currentSize < oldSize {
		rotated = true
		rotationReason = "size decrease"
	}

	if !rotated && currentModTime.Before(oldModTime) && currentSize <= oldSize {
		rotated = true
		rotationReason = "modification time reset"
	}

	if !rotated && oldPos > currentSize+1024 {
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

		w.callback(LogEntry{
			Time:    time.Now(),
			Source:  filepath.Base(w.path),
			Level:   "INFO",
			Message: fmt.Sprintf("Log rotation detected (#%d): %s", seq, rotationReason),
		})
	}

	if _, err := file.Seek(newPos, io.SeekStart); err != nil {
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
	}

	if currentPos, err := file.Seek(0, io.SeekCurrent); err == nil {
		w.mu.Lock()
		w.position = currentPos
		w.size = currentSize
		w.modTime = currentModTime
		w.mu.Unlock()
	}

	return scanner.Err()
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