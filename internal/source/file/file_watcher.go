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

// The lines read last that are kept, to find the place again in a file an edit
// rewrote, newest first, are tailLines and tailBytes at most; findWithin is how
// much of its end is searched, what a save may append after them
const (
	tailLines  = 8
	tailBytes  = 1 << 10
	findWithin = 64 << 10
)

// settleChecks is how many checks a file whose line read last is missing may go
// on changing, a slow rewrite still being written, before lw decides
const settleChecks = 20

// holeProbe is how much at each end of a rotated file's bytes before the
// position must be NUL to take them for a hole (see pastHole)
const holeProbe = 4 << 10

// fileWatcher tails a single file, handles rotations, and sends new lines to a callback
type fileWatcher struct {
	directory    string
	callback     func(core.LogEntry)
	raw          bool
	position     int64
	size         int64
	inode        uint64 // the file position is in, set once a check has judged it
	modTime      time.Time
	mu           sync.Mutex
	stopped      bool
	rotationSeq  int64
	prevInode    uint64
	prevPosition int64
	entriesRead  atomic.Uint64
	lastReadTime atomic.Value // time.Time
	logger       *log.Logger
	failed       string      // the last check's error, "" for none; watch's
	tail         []byte      // the lines before position (lastLines); watch's
	seen         os.FileInfo // the file as the last check found it; watch's
	holds        int         // checks waited for the file to settle; watch's
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
// an edit rewrote it, reading resumes after the newest line read that it still
// holds; with none the place is lost, a rotation, read from the start. While the
// line read last is missing and the file still changes, it is held, up to
// settleChecks, so that a slow rewrite is judged once written.
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
	size, same := info.Size(), w.seen != nil && os.SameFile(info, w.seen) && info.Size() == w.seen.Size() && info.ModTime().Equal(w.seen.ModTime())
	w.seen = info

	w.mu.Lock()
	pos := w.position
	w.size, w.modTime = size, info.ModTime()
	w.mu.Unlock()
	if same && pos >= size && w.holds == 0 {
		return nil
	}

	rotated := false
	if !w.follows(file, pos, size) {
		at, which := w.find(file, size)
		switch {
		case which != 0 && !same && w.holds < settleChecks:
			w.holds++
			return nil
		case which < 0:
			rotated, at = true, pastHole(file, pos, size)
		default:
			w.logger.Info("msg", "File rewritten; resuming after the newest line read it still holds",
				"component", "file_watcher", "path", w.directory, "position", pos, "resumed_at", at, "size", size)
		}
		pos = at
	}
	w.mu.Lock()
	if rotated {
		// Retained for the source: the renamed file is about to be discovered
		// under its archive name, and only this says how much of it was read.
		w.prevInode, w.prevPosition = w.inode, w.position
	}
	w.inode, w.position = inodeOf(info), pos
	w.mu.Unlock()
	w.holds = 0
	if rotated {
		w.rotated()
	}

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
	if w.tail, err = lastLines(file, end); err != nil {
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

// follows reports whether the lines before pos are still those read last
func (w *fileWatcher) follows(file *os.File, pos, size int64) bool {
	if pos > size {
		return false
	}
	got, err := readAt(file, pos-int64(len(w.tail)), int64(len(w.tail)))
	return err == nil && bytes.Equal(got, w.tail)
}

// find is where reading resumes in a file an edit rewrote: after the newest of
// the lines read last that its last findWithin bytes still hold. which counts
// back from the newest, -1 where none is
func (w *fileWatcher) find(file *os.File, size int64) (at int64, which int) {
	lo := max(0, size-findWithin)
	buf, err := readAt(file, lo, size-lo)
	if err != nil {
		return 0, -1
	}
	for end := len(w.tail); end > 0; which++ {
		start := bytes.LastIndexByte(w.tail[:end-1], '\n')
		line := w.tail[max(0, start):end]
		if len(bytes.TrimSpace(line)) > 0 {
			if i := bytes.LastIndex(buf, line); i >= 0 {
				return lo + int64(i+len(line)), which
			}
		}
		end = start + 1
	}
	return 0, -1
}

// pastHole is where a rotated file is read from: its start, or its first data
// past the position when the bytes before it are NUL, the hole copytruncate
// leaves under a writer that does not append and goes on at its offset
func pastHole(file *os.File, pos, size int64) int64 {
	at := min(pos, size)
	for _, from := range []int64{0, max(0, at-holeProbe)} {
		if b, err := readAt(file, from, min(at-from, holeProbe)); err != nil || len(b) == 0 || len(bytes.Trim(b, "\x00")) > 0 {
			return 0
		}
	}
	buf := make([]byte, holeProbe)
	for at < size {
		n, err := file.ReadAt(buf[:min(int64(len(buf)), size-at)], at)
		if i := bytes.IndexFunc(buf[:n], func(r rune) bool { return r != 0 }); i >= 0 {
			return at + int64(i)
		}
		if at += int64(n); err != nil {
			break
		}
	}
	return at
}

// lastLines are the lines that end at end, tailLines and tailBytes at most,
// each with the newline before it so that it is found only whole
func lastLines(file *os.File, end int64) ([]byte, error) {
	n := min(end, tailBytes)
	buf, err := readAt(file, end-n, n)
	cut := 0
	if end > n { // the first line is cut: from the newline after it
		cut = max(0, bytes.IndexByte(buf[:max(0, len(buf)-1)], '\n'))
	}
	for i, lines := len(buf)-2, 0; i > cut; i-- {
		if buf[i] == '\n' {
			if lines++; lines == tailLines {
				cut = i
				break
			}
		}
	}
	return buf[cut:], err
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

	w.size = info.Size()
	w.modTime = info.ModTime()
	w.inode = inodeOf(info)
	w.seen = info
	if w.position == -1 || w.position > w.size { // a resumed position past the end is not this file's
		w.position = w.size
	}
	w.tail, err = lastLines(file, w.position)
	return err
}

// readTo reports how far this watcher read the given inode: the file it tails
// now, as last judged (not one a held check has yet to), or the one a rotation
// renamed out from under it.
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
