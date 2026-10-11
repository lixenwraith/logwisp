// Package logline reads a log line of any shape (vif records, LogWisp's json,
// lw's own log, pino, zap, slog, logfmt, docker, journald, ECS, GCP, plain
// text) into one set of roles, and names the runes a terminal would act on. It
// links no terminal code, so a viewer, a sink and the configuration page can
// share it.
package logline

import (
	"bytes"
	"encoding/hex"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lixenwraith/logwisp/internal/core"
)

// Line is what a log line says, wherever its writer put it
type Line struct {
	Time    time.Time // zero when the line names none readable: the entry's time stands in
	Stamp   string    // the time as the line wrote it
	Level   string    // a core.Levels level, or a value outside their order as written (PROC)
	Tag     string    // who wrote it: sub, source, logger and the like, else the entry's source
	Message string
	Fields  []Field // what no role took, in the writer's order
	Layout  string  // where the roles were found, so a reader can check the guess
}

// Field is a value no role took. Key is its dotted path, "" for a positional
// value; Value is a string's text or any other value as its JSON.
type Field struct {
	Key, Value string
}

const (
	roleTime = iota
	roleLevel
	roleTag
	roleMsg
)

// roles are the keys each role is read from, the first present wins: a dotted
// key is a path into nested objects or a flat key spelled with dots. trace is
// the last tag, so it names LogWisp json's source but not vif's call chain.
var roles = [...][]string{
	roleTime:  {"time", "ts", "timestamp", "@timestamp", "t", "datetime", "__REALTIME_TIMESTAMP", "@t"},
	roleLevel: {"level", "lvl", "severity", "log.level", "levelname", "loglevel", "PRIORITY", "@l"},
	roleTag:   {"sub", "source", "logger", "component", "name", "_SYSTEMD_UNIT", "trace"},
	roleMsg:   {"msg", "message", "MESSAGE", "@m", "@mt", "log", "text", "event"},
}

// envelopes hold a record's payload one level down; the first of them present
// is opened, and without a message of its own the record takes the envelope's
// first discriminator, or an array's first string (vif: fields.msg|type|ev)
var (
	envelopes      = []string{"fields", "data", "attrs", "payload"}
	discriminators = []string{"msg", "type", "ev", "message"}
)

// nestMax bounds the depth flattened into dotted paths, and so their length
const nestMax = 8

// member is one leaf of a record; no role takes the envelope's
type member struct {
	key, val string
	kind     byte
	env      bool
	used     bool
}

// Read finds e's roles in its message, a JSON record (also one inside such a
// record's message) or text, and in its fields; a role the line does not name
// is the entry's.
func Read(e core.LogEntry) Line {
	l, at, ok := record(strings.TrimSpace(e.Message), "")
	if ok {
		if in, _, ok := record(strings.TrimSpace(l.Message), at); ok {
			l = merge(l, in)
		}
	} else {
		l = text(e.Message)
	}
	if f := strings.TrimSpace(string(e.Fields)); f != "" {
		_, kind, _ := scanValue(f, 0)
		ms, msg, at := envelope(nil, "fields", f, kind)
		if l.Message == "" && msg >= 0 {
			ms[msg].used = true
			l.Message, l.Layout = unquote(ms[msg].val, kStr), "entry, message in "+at
		}
		l.Fields = appendFields(l.Fields, ms)
	}
	if l.Level == "" {
		l.Level = level("", e.Level)
	}
	if l.Tag == "" {
		l.Tag = e.Source
	}
	l.Message = strings.TrimRight(l.Message, "\r\n")
	return l
}

// record reads s as a JSON object; in names where s sat as another record's
// message, at where s's own message is. The members before a malformed part
// count, so a clipped line still shows its roles; ok is false without any.
func record(s, in string) (l Line, at string, ok bool) {
	var top []member
	whole := eachField(s, 0, func(k, v string, kind byte) bool {
		top = append(top, member{key: k, val: v, kind: kind})
		return true
	})
	if len(top) == 0 {
		return Line{}, "", false
	}
	env := -1
	for _, name := range envelopes {
		for i := range top {
			if env < 0 && top[i].key == name && (top[i].kind == kObj || top[i].kind == kArr) {
				env = i
			}
		}
	}
	var ms []member
	msg, envAt := -1, ""
	for i, m := range top {
		if i == env {
			ms, msg, envAt = envelope(ms, m.key, m.val, m.kind)
		} else {
			ms = leaves(ms, m.key, m.val, m.kind, false, 0)
		}
	}

	if at = l.take(ms); at == "" && msg >= 0 {
		ms[msg].used = true
		l.Message, at = unquote(ms[msg].val, kStr), envAt
	}
	l.Fields = appendFields(nil, ms)

	l.Layout = "json"
	if in != "" {
		l.Layout += " in " + in
	}
	if !whole {
		l.Layout += ", cut short"
	}
	l.Layout += messageIn(at)
	return l, at, true
}

// text reads a line that is no JSON record: a leading RFC3339 stamp, then a
// word naming a level; the rest is the message, or a record's roles when it
// is logfmt pairs, a level or a message among them (slog's text handler)
func text(s string) Line {
	l, layout := Line{Message: s}, ""
	if stamp, rest, ok := strings.Cut(s, " "); ok {
		if at, ok := readStamp(stamp); ok {
			l.Time, l.Stamp, l.Message, layout = at, stamp, strings.TrimLeft(rest, " "), ", stamped"
			word, rest, _ := strings.Cut(l.Message, " ")
			if lv, i, j := core.LevelWord(word, ""); lv != "" && i == 0 && j == len(word) {
				l.Level, l.Message, layout = lv, strings.TrimLeft(rest, " "), layout+", level word"
			}
		}
	}
	var ms []member
	named := false
	pairs := eachPair(l.Message, func(k, v string) {
		ms = append(ms, member{key: k, val: v, kind: kText})
		named = named || slices.Contains(roles[roleLevel], k) || slices.Contains(roles[roleMsg], k)
	})
	if !pairs || !named {
		l.Layout = "text" + layout
		return l
	}
	l.Message = ""
	at := l.take(ms)
	l.Fields = appendFields(nil, ms)
	l.Layout = "logfmt" + layout + messageIn(at)
	return l
}

// take sets the roles ms names and returns the message's key, "" for none; a
// stamp or level read off the line's start stays, the member a field
func (l *Line) take(ms []member) (at string) {
	if l.Stamp == "" {
		if m := find(ms, roleTime); m != nil {
			l.Stamp = unquote(m.val, m.kind)
			l.Time, _ = readTime(l.Stamp)
		}
	}
	if l.Level == "" {
		if m := find(ms, roleLevel); m != nil {
			l.Level = level(m.key, unquote(m.val, m.kind))
		}
	}
	if m := find(ms, roleTag); m != nil {
		l.Tag = unquote(m.val, m.kind)
	}
	if m := find(ms, roleMsg); m != nil {
		l.Message, at = unquote(m.val, m.kind), m.key
	}
	return at
}

func messageIn(at string) string {
	if at == "" {
		return ", no message"
	}
	return ", message in " + at
}

// envelope appends the leaves of envelope name's value v; msg indexes its
// message in ms and at says where it was, -1 and "" when it holds none
func envelope(ms []member, name, v string, kind byte) (_ []member, msg int, at string) {
	msg, rank, slot := -1, len(discriminators), -1
	note := func(key string, kind byte, i int) {
		for r := 0; r < rank && kind == kStr; r++ {
			if discriminators[r] == key {
				msg, rank, slot = len(ms), r, i
			}
		}
	}
	switch kind {
	case kObj:
		eachField(v, 0, func(k, fv string, fk byte) bool {
			note(k, fk, -1)
			ms = leaves(ms, k, fv, fk, true, 1)
			return true
		})
	case kArr:
		// lw's own log writes key/value pairs; LogWisp json, the message alone
		n, pairs := 0, true
		eachItem(v, 0, func(_ string, k byte) {
			pairs = pairs && (n%2 == 1 || k == kStr)
			n++
		})
		pairs = pairs && n > 0 && n%2 == 0
		i, key := 0, ""
		eachItem(v, 0, func(iv string, ik byte) {
			switch {
			case pairs && i%2 == 0:
				key = unquote(iv, ik)
			case pairs:
				note(key, ik, i)
				ms = leaves(ms, key, iv, ik, true, 1)
			default:
				if i == 0 && ik == kStr {
					msg, slot = len(ms), 0
				}
				ms = leaves(ms, "", iv, ik, true, 1)
			}
			i++
		})
	default:
		ms = leaves(ms, name, v, kind, true, 0)
	}
	switch {
	case msg < 0:
	case slot < 0:
		at = name + "." + ms[msg].key
	default:
		at = name + "[" + strconv.Itoa(slot) + "]"
	}
	return ms, msg, at
}

// leaves appends v under key, an object as one leaf per member at its dotted
// path, so roles and readers see nested keys as if written flat
func leaves(ms []member, key, v string, kind byte, env bool, depth int) []member {
	if kind == kObj && depth < nestMax {
		n := len(ms)
		if eachField(v, 0, func(k, fv string, fk byte) bool {
			if key != "" {
				k = key + "." + k
			}
			ms = leaves(ms, k, fv, fk, env, depth+1)
			return true
		}) && len(ms) > n {
			return ms
		}
		ms = ms[:n]
	}
	return append(ms, member{key: key, val: v, kind: kind, env: env})
}

// find takes the leaf holding role r, outside the envelope and holding a
// string or a number: a null, a flag or a list names no role
func find(ms []member, r int) *member {
	for _, key := range roles[r] {
		for i := range ms {
			m := &ms[i]
			if m.key == key && !m.env && !m.used && (m.kind == kStr || m.kind == kNum || m.kind == kText) {
				m.used = true
				return m
			}
		}
	}
	return nil
}

func appendFields(fs []Field, ms []member) []Field {
	for _, m := range ms {
		if !m.used {
			fs = append(fs, Field{m.key, unquote(m.val, m.kind)})
		}
	}
	return fs
}

// merge lays a record found in out's message over out: its roles win, out's
// fill the ones it does not name, and out's fields come first
func merge(out, in Line) Line {
	if in.Time.IsZero() {
		in.Time, in.Stamp = out.Time, out.Stamp
	}
	if in.Level == "" {
		in.Level = out.Level
	}
	if in.Tag == "" {
		in.Tag = out.Tag
	}
	in.Fields = append(out.Fields, in.Fields...)
	return in
}

// level reads a level value: a name in any case, or a number on its key's
// scale (journald's syslog PRIORITY, pino's tens, else slog's and
// lixenwraith/log's); any other value is kept as written, outside the order
func level(key, v string) string {
	if n, ok := parseInt64(v); ok {
		switch {
		case key == "PRIORITY":
			return [...]string{"ERROR", "ERROR", "ERROR", "ERROR", "WARN", "INFO", "INFO", "DEBUG"}[min(max(n, 0), 7)]
		case n >= 10:
			return [...]string{"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "ERROR"}[min(n/10-1, 5)]
		case n <= -8:
			return "TRACE"
		case n < 0:
			return "DEBUG"
		case n < 4:
			return "INFO"
		case n < 8:
			return "WARN"
		}
		return "ERROR"
	}
	for _, l := range core.Levels {
		for _, names := range [2][]string{l.Names, l.Keyed} {
			for _, name := range names {
				if strings.EqualFold(v, name) {
					return l.Level
				}
			}
		}
	}
	return v
}

// readStamp reads an RFC3339 stamp, one without a zone as UTC
func readStamp(s string) (time.Time, bool) {
	at, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		at, err = time.Parse("2006-01-02T15:04:05.999999999", s)
	}
	return at, err == nil
}

// readTime reads an RFC3339 stamp, or a number since 1970 in seconds,
// milliseconds or microseconds, told apart by its magnitude
func readTime(s string) (time.Time, bool) {
	if at, ok := readStamp(s); ok {
		return at, true
	}
	whole, frac, _ := strings.Cut(s, ".")
	n, ok := parseInt64(whole)
	if !ok || n < 0 {
		return time.Time{}, false
	}
	unit := int64(1e3)
	switch {
	case n < 1e11:
		unit = 1e9
	case n < 1e14:
		unit = 1e6
	}
	if n > math.MaxInt64/unit {
		return time.Time{}, false
	}
	ns := n * unit
	for i := 0; i < len(frac); i++ {
		if frac[i] < '0' || frac[i] > '9' {
			return time.Time{}, false
		}
		unit /= 10
		ns += int64(frac[i]-'0') * unit
	}
	return time.Unix(0, ns), true
}

// EscapeControls writes what a terminal would act on or reorder (Control) as
// <hex>, keeping the final newline: a log line cannot drive the terminal.
// Other invisible characters stay: emoji and Indic scripts need ZWJ.
func EscapeControls(p []byte) []byte {
	body, newline := bytes.CutSuffix(p, []byte{'\n'})
	if printableASCII(body) {
		return p
	}
	out := make([]byte, 0, len(p)+16)
	for len(body) > 0 {
		r, n := utf8.DecodeRune(body)
		if !Control(r, n) {
			out = append(out, body[:n]...)
		} else {
			out = append(out, '<')
			out = hex.AppendEncode(out, body[:n])
			out = append(out, '>')
		}
		body = body[n:]
	}
	if newline {
		out = append(out, '\n')
	}
	return out
}

// Control reports whether a terminal would act on the rune r, decoded from
// size bytes, or reorder text by it: C0 and C1 controls but tab, DEL, bidi
// controls, line separators and invalid UTF-8
func Control(r rune, size int) bool {
	switch {
	case r == utf8.RuneError && size == 1:
		return true
	case r < 0x20:
		return r != '\t'
	case r >= 0x7f && r <= 0x9f, r == 0x061c, r == 0x200e, r == 0x200f,
		r >= 0x2028 && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

func printableASCII(b []byte) bool {
	for _, c := range b {
		if (c < 0x20 || c > 0x7e) && c != '\t' {
			return false
		}
	}
	return true
}
