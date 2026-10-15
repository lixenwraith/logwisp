package file

import (
	"bufio"
	"bytes"
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

	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/source"

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

// markBytes is how much of a file's start, and of the line read last, is kept
// to know the file again when an edit or a rotation swaps its inode or size
const markBytes = 256

// findWithin is how much of a rewritten file's end is searched for the line
// read last: what a save may append after it, and the most read to find it
const findWithin = 64 << 10

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
	prevInode    uint64
	prevPosition int64
	entriesRead  atomic.Uint64
	lastReadTime atomic.Value // time.Time
	logger       *log.Logger
	failed       string // the last check's error, "" for none; watch's
	head, tail   []byte // the file's first bytes and its line before position (lastLine); watch's
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

// watch follows the file until ctx ends or stop: it finds where to start,
// again each check until the file opens, then reads what the file gains
func (w *fileWatcher) watch(ctx context.Context) error {
	ticker := time.NewTicker(core.FileWatcherPollInterval)
	defer ticker.Stop()

	check := w.initPosition
	for {
		err := check()
		if err == nil {
			check = w.checkFile
		}
		w.note(err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if w.isStopped() {
				return nil
			}
		}
	}
}

// note logs a check's failure as it starts or changes, not every check; the
// watcher goes on
func (w *fileWatcher) note(err error) {
	if changed(&w.failed, err) && err != nil {
		w.logger.Warn("msg", "Cannot read file", "component", "file_watcher", "path", w.directory, "error", err)
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

// checkFile reads what the file has gained, whatever its inode or size. Where
// an edit rewrote it, reading resumes after the line read last, found near its
// end, or where that line is gone and the file starts as before, at its end, so
// an edit replays nothing; a file starting anew, a rotation, reads from its
// start. One emptied or cut within its start waits for what is written next.
func (w *fileWatcher) checkFile() error {
	file, err := os.Open(w.directory)
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
	size, ino := info.Size(), inodeOf(info)

	w.mu.Lock()
	pos := w.position
	same := size == w.size && ino == w.inode && info.ModTime().Equal(w.modTime)
	if ino != w.inode && w.inode != 0 {
		// Retained for the source: a rotation's renamed file is about to be
		// discovered under its archive name, and only this says how much of it was read.
		w.prevInode, w.prevPosition = w.inode, w.position
	}
	w.inode, w.size, w.modTime = ino, size, info.ModTime()
	w.mu.Unlock()
	if same && pos >= size {
		return nil
	}

	head, err := readAt(file, 0, min(size, markBytes))
	if err != nil {
		return err
	}
	n := min(len(head), len(w.head))
	sameStart := bytes.Equal(head[:n], w.head[:n])
	switch {
	case sameStart && size < int64(len(w.head)):
		return nil
	case w.follows(file, pos, size):
	default:
		at, found := w.find(file, size)
		if !found && !sameStart {
			pos = 0
			w.rotated()
			break
		}
		w.logger.Info("msg", "File rewritten; resuming after the last line read, or at its end",
			"component", "file_watcher", "path", w.directory, "position", pos, "resumed_at", at, "size", size)
		pos = at
	}
	w.head = head

	if _, err := file.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), core.MaxLogEntryBytes)
	scanner.Split(scanLinesCapped)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry := w.parseLine(line)
		entry.RawSize = int64(len(line))

		w.callback(entry)
		w.entriesRead.Add(1)
		w.lastReadTime.Store(time.Now())
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	end, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		w.logger.Warn("msg", "Failed to get file position", "error", err)
		end = max(pos, size)
	}
	if w.tail, err = lastLine(file, end); err != nil {
		return err
	}
	w.mu.Lock()
	w.position = end
	w.mu.Unlock()
	return nil
}

// rotated counts a rotation and says so, in lw's log and to the pipeline
func (w *fileWatcher) rotated() {
	w.mu.Lock()
	w.rotationSeq++
	seq := w.rotationSeq
	w.mu.Unlock()

	w.callback(core.LogEntry{
		Time:    time.Now(),
		Source:  filepath.Base(w.directory),
		Level:   "INFO",
		Message: fmt.Sprintf("Log rotation detected (#%d): the file starts anew", seq),
	})
	w.logger.Info("msg", "Log rotation detected",
		"component", "file_watcher",
		"directory", w.directory,
		"sequence", seq)
}

// follows reports whether the line before pos is still the one read last
func (w *fileWatcher) follows(file *os.File, pos, size int64) bool {
	if pos > size {
		return false
	}
	got, err := readAt(file, pos-int64(len(w.tail)), int64(len(w.tail)))
	return err == nil && bytes.Equal(got, w.tail)
}

// find is where reading resumes in a file an edit rewrote: after the line
// read last, which stays near the end whatever was deleted or added before it,
// or, not found, at the end
func (w *fileWatcher) find(file *os.File, size int64) (int64, bool) {
	if len(w.tail) == 0 {
		return size, false
	}
	lo := max(0, size-findWithin)
	buf, err := readAt(file, lo, size-lo)
	if i := bytes.LastIndex(buf, w.tail); err == nil && i >= 0 {
		return lo + int64(i+len(w.tail)), true
	}
	return size, false
}

// lastLine is the line that ends at end, with the newline before it, so that
// it is found only whole: markBytes at most, a longer line's end
func lastLine(file *os.File, end int64) ([]byte, error) {
	buf, err := readAt(file, end-min(end, markBytes), min(end, markBytes))
	if i := bytes.LastIndexByte(buf[:max(0, len(buf)-1)], '\n'); i >= 0 {
		buf = buf[i:]
	}
	return buf, err
}

// readAt reads n bytes at off, fewer where the file ends first
func readAt(file *os.File, off, n int64) ([]byte, error) {
	buf := make([]byte, n)
	got, err := file.ReadAt(buf, off)
	if err == io.EOF {
		err = nil
	}
	return buf[:got], err
}

// inodeOf is the file's inode, 0 where the platform gives none
func inodeOf(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}

// scanLinesCapped is bufio.ScanLines, except that a line longer than
// core.MaxLogEntryBytes continues in the next one, as on the console source:
// the scanner would otherwise stop at it and every poll re-read the lines before.
func scanLinesCapped(data []byte, atEOF bool) (int, []byte, error) {
	advance, token, err := bufio.ScanLines(data, atEOF)
	if advance == 0 && token == nil && err == nil && len(data) >= core.MaxLogEntryBytes {
		return core.MaxLogEntryBytes, data[:core.MaxLogEntryBytes], nil
	}
	return advance, token, err
}

// initPosition records the file's metadata and its marks and, unless the
// watcher was created to read from the start, sets the read position to the end.
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
	w.inode = inodeOf(info)
	if w.head, err = readAt(file, 0, min(w.size, markBytes)); err != nil {
		return err
	}
	w.tail, err = lastLine(file, w.position)
	return err
}

// readTo reports how far this watcher read the given inode: the file it tails
// now, or the one a rotation renamed out from under it.
func (w *fileWatcher) readTo(inode uint64) (int64, bool) {
	if inode == 0 {
		return 0, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	switch inode {
	case w.inode:
		return w.position, true
	case w.prevInode:
		return w.prevPosition, true
	}
	return 0, false
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
		return core.LogEntry{
			Time:    time.Now(),
			Source:  filepath.Base(w.directory),
			Level:   source.ExtractLogLevel(line),
			Message: line,
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
