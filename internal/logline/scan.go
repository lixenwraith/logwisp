package logline

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/lixenwraith/logwisp/internal/core"
)

// JSON token kinds, and kText for a logfmt value, unquoted already
const (
	kNone byte = 0
	kStr  byte = 's'
	kNum  byte = 'n'
	kBool byte = 'b'
	kNull byte = 'z'
	kObj  byte = 'o'
	kArr  byte = 'a'
	kText byte = 't'
)

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	return i
}

func isNumByte(c byte) bool {
	return c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' || (c >= '0' && c <= '9')
}

// scanString returns the index past the closing quote; i indexes the opener.
func scanString(s string, i int) (int, bool) {
	for i++; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i + 1, true
		}
	}
	return i, false
}

// scanValue returns the end index and kind of the value starting at i.
func scanValue(s string, i int) (int, byte, bool) {
	if i >= len(s) {
		return i, kNone, false
	}
	switch c := s[i]; c {
	case '"':
		e, ok := scanString(s, i)
		return e, kStr, ok

	case '{', '[':
		opener, closer, kind := byte('{'), byte('}'), kObj
		if c == '[' {
			opener, closer, kind = '[', ']', kArr
		}
		depth := 0
		for i < len(s) {
			ch := s[i]
			if ch == '"' {
				e, ok := scanString(s, i)
				if !ok {
					return e, kind, false
				}
				i = e
				continue
			}
			if ch == opener {
				depth++
			} else if ch == closer {
				depth--
				if depth == 0 {
					return i + 1, kind, true
				}
			}
			i++
		}
		return i, kind, false

	case 't', 'f', 'n':
		kind := kBool
		if c == 'n' {
			kind = kNull
		}
		for i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
			i++
		}
		return i, kind, true

	default:
		e := i
		for e < len(s) && isNumByte(s[e]) {
			e++
		}
		return e, kNum, e > i
	}
}

// eachField calls fn for each member of the object at i, which must index '{',
// until fn returns false; it reports whether the object is well formed.
func eachField(s string, i int, fn func(key, val string, kind byte) bool) bool {
	if i >= len(s) || s[i] != '{' {
		return false
	}
	i = skipSpace(s, i+1)
	if i < len(s) && s[i] == '}' {
		return true
	}
	for i < len(s) {
		if s[i] != '"' {
			return false
		}
		ke, ok := scanString(s, i)
		if !ok {
			return false
		}
		key := s[i+1 : ke-1]

		i = skipSpace(s, ke)
		if i >= len(s) || s[i] != ':' {
			return false
		}
		i = skipSpace(s, i+1)

		vs := i
		ve, kind, ok := scanValue(s, i)
		if !ok {
			return false
		}
		if !fn(key, s[vs:ve], kind) {
			return true
		}

		i = skipSpace(s, ve)
		if i >= len(s) {
			return false
		}
		switch s[i] {
		case ',':
			i = skipSpace(s, i+1)
		case '}':
			return true
		default:
			return false
		}
	}
	return false
}

// eachItem calls fn for each element of the array at i, which must index '[';
// it reports whether the array is well formed.
func eachItem(s string, i int, fn func(val string, kind byte)) bool {
	if i >= len(s) || s[i] != '[' {
		return false
	}
	i = skipSpace(s, i+1)
	if i < len(s) && s[i] == ']' {
		return true
	}
	for i < len(s) {
		ve, kind, ok := scanValue(s, i)
		if !ok {
			return false
		}
		fn(s[i:ve], kind)
		i = skipSpace(s, ve)
		if i >= len(s) {
			return false
		}
		switch s[i] {
		case ',':
			i = skipSpace(s, i+1)
		case ']':
			return true
		default:
			return false
		}
	}
	return false
}

// eachPair calls fn for each pair of a logfmt line, key=value with the value
// bare or quoted as Go quotes it; it reports whether s is such pairs alone.
func eachPair(s string, fn func(key, val string)) bool {
	bare := func(i int) int {
		for i < len(s) && s[i] > ' ' && s[i] != '=' && s[i] != '"' {
			i++
		}
		return i
	}
	for i := skipSpace(s, 0); i < len(s); i = skipSpace(s, i) {
		k := i
		if i = bare(k); i == k || i == len(s) || s[i] != '=' {
			return false
		}
		key, v := s[k:i], i+1
		i = bare(v)
		val := s[v:i]
		if i == v && i < len(s) && s[i] == '"' {
			var ok bool
			var err error
			if i, ok = scanString(s, v); !ok {
				return false
			}
			if val, err = strconv.Unquote(s[v:i]); err != nil {
				return false
			}
		}
		if i < len(s) && s[i] > ' ' {
			return false
		}
		fn(key, val)
	}
	return true
}

// unquote returns the content of a string token, decoding only when it holds
// an escape; any other token, a logfmt value too, is returned as it is.
func unquote(tok string, kind byte) string {
	if kind != kStr || len(tok) < 2 {
		return tok
	}
	in := tok[1 : len(tok)-1]
	for i := 0; i < len(in); i++ {
		if in[i] == '\\' {
			var s string
			if json.Unmarshal([]byte(tok), &s) == nil {
				return s
			}
			break
		}
	}
	return in
}

// parseInt64 parses a complete decimal integer token without allocating.
func parseInt64(s string) (int64, bool) {
	if len(s) == 0 {
		return 0, false
	}
	i, neg := 0, false
	if s[0] == '-' || s[0] == '+' {
		neg = s[0] == '-'
		i++
	}
	if i >= len(s) {
		return 0, false
	}
	var v int64
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v*10 + int64(s[i]-'0')
		if v < 0 {
			return 0, false
		}
	}
	if neg {
		v = -v
	}
	return v, true
}

// Mark is a part of a written line a console paints apart from its text;
// Level names a MarkLevel's level, a core.Levels one or as written
type Mark struct {
	Kind, Start, End int
	Level            string
}

// Mark kinds
const (
	MarkTime  = iota + 1 // a time stamp
	MarkLevel            // the line's level
	MarkTag              // who wrote the line
	MarkKey              // a field's name
	MarkPunct            // what frames a field: JSON's punctuation, logfmt's '='
)

// stampRE is the stamp (group 1) a line starts with, a word of its own: a
// date, a time of day or both, as RFC 3339, log4j, Go's log and most loggers
// write them, or syslog's (group 2)
var stampRE = regexp.MustCompile(`^(\[?(?:\d{4}[-/]\d{2}[-/]\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?|\d{2}:\d{2}:\d{2}(?:[.,]\d+)?|(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ \d]\d \d{2}:\d{2}:\d{2})\]?)(?:\s|$)`)

// syslogTagRE is the host and program[pid] after a syslog stamp, to the colon
var syslogTagRE = regexp.MustCompile(`^\S+ [\w./-]+(?:\[\d+\])?:`)

// Marks calls fn, in order, with the parts of s, e's line as a sink writes it,
// that name a role. A text line: a leading stamp and level word, then e's
// source label as txt writes it or syslog's host and program, else the first
// word naming e's level. A JSON object or key=value pairs: keys, punctuation
// and the values of time, level and tag keys.
func Marks(s string, e core.LogEntry, fn func(Mark)) {
	i, at := 0, Mark{Kind: MarkLevel, Start: -1}
	stamp := stampRE.FindStringSubmatchIndex(s)
	if stamp != nil {
		i = stamp[3]
		fn(Mark{Kind: MarkTime, End: i})
	}
	j := skipSpace(s, i)
	if w := wordEnd(s, j); w > j {
		if lv, a, b := core.LevelWord(s[j:w], ""); lv != "" && a == 0 && b == w-j {
			fn(Mark{MarkLevel, j, w, lv})
			i, j = w, skipSpace(s, w)
		} else if lv, _, _ := core.LevelWord(e.Level, ""); lv != "" && s[skipSpace(s, 0)] != '{' {
			if _, a, b := core.LevelWord(s[i:], lv); a < b {
				at = Mark{MarkLevel, i + a, i + b, lv}
			}
		}
	}
	switch rest, tag := s[j:], e.Label(); {
	case j > 0 && tag != "" && strings.HasPrefix(rest, tag) && wordEnd(rest, len(tag)) == len(tag):
		i = j + len(tag)
		fn(Mark{Kind: MarkTag, Start: j, End: i})
	case stamp != nil && stamp[4] >= 0 && syslogTagRE.MatchString(rest):
		i = j + len(syslogTagRE.FindString(rest)) - 1
		fn(Mark{Kind: MarkTag, Start: j, End: i})
	}

	// the level word, when the line has no level of its own at its start,
	// is marked in the word or plain value holding it
	word := func(start, end int) {
		if at.Start >= start && at.Start < end {
			fn(at)
		}
	}
	for i = skipSpace(s, i); i < len(s); i = skipSpace(s, i) {
		if s[i] == '{' {
			end, ok := walk(s, i, 0, nil)
			if ok {
				walk(s, i, 0, fn)
			} else {
				word(i, end) // text read as JSON to where it failed is not read again
			}
			i = end
			continue
		}
		k := i
		if s[k] == '"' {
			k++ // a key opening txt's quoted message
		}
		ke := keyEnd(s, k)
		if ke == k || ke == len(s) || s[ke] != '=' {
			k, i = i, wordEnd(s, i+1) // past a control byte, which skipSpace leaves
			word(k, i)
			continue
		}
		fn(Mark{Kind: MarkKey, Start: k, End: ke})
		fn(Mark{Kind: MarkPunct, Start: ke, End: ke + 1})
		v := ke + 1
		if i = v; i < len(s) && s[i] == '"' {
			i, _ = scanString(s, i)
		}
		if i = wordEnd(s, i); i > v && !role(s, s[k:ke], v, i, kText, fn) {
			word(v, i)
		}
	}
}

func wordEnd(s string, i int) int {
	for i < len(s) && s[i] > ' ' {
		i++
	}
	return i
}

// keyEnd is the end of the key at i: a letter, '_' or '@', then those,
// digits, '.' and '-'; i for none
func keyEnd(s string, i int) int {
	for k := i; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '@' || i > k && (c >= '0' && c <= '9' || c == '.' || c == '-')) {
			break
		}
	}
	return i
}

// roleMarks are the roles whose values are marked, by their mark
var roleMarks = [...]struct{ role, kind int }{{roleTime, MarkTime}, {roleLevel, MarkLevel}, {roleTag, MarkTag}}

// role marks the value s[v:ve] when key names a role, kind its token kind
func role(s, key string, v, ve int, kind byte, fn func(Mark)) bool {
	for _, r := range roleMarks {
		if slices.Contains(roles[r.role], key) {
			m := Mark{Kind: r.kind, Start: v, End: ve}
			if r.kind == MarkLevel {
				m.Level = level(key, unquote(s[v:ve], kind))
			}
			fn(m)
			return true
		}
	}
	return false
}

// walk marks the JSON value at i, which nil fn only checks; it returns the
// index past it and whether it is well formed. Keys at depth 0 name roles.
func walk(s string, i, depth int, fn func(Mark)) (int, bool) {
	mark := func(kind, a, b int) {
		if fn != nil {
			fn(Mark{Kind: kind, Start: a, End: b})
		}
	}
	if i >= len(s) || s[i] != '{' && s[i] != '[' || depth >= nestMax {
		e, _, ok := scanValue(s, i)
		return e, ok
	}
	closer := byte('}')
	if s[i] == '[' {
		closer = ']'
	}
	mark(MarkPunct, i, i+1)
	if i = skipSpace(s, i+1); i < len(s) && s[i] == closer {
		mark(MarkPunct, i, i+1)
		return i + 1, true
	}
	for i < len(s) {
		key := ""
		if closer == '}' {
			if s[i] != '"' {
				return i, false
			}
			ke, ok := scanString(s, i)
			if !ok {
				return ke, false
			}
			mark(MarkKey, i, ke)
			if depth == 0 {
				key = s[i+1 : ke-1]
			}
			if i = skipSpace(s, ke); i == len(s) || s[i] != ':' {
				return i, false
			}
			mark(MarkPunct, i, i+1)
			i = skipSpace(s, i+1)
		}
		v := i
		e, ok := walk(s, i, depth+1, fn)
		if !ok {
			return e, false
		}
		if key != "" && fn != nil && (s[v] == '"' || isNumByte(s[v])) {
			kind := kNum
			if s[v] == '"' {
				kind = kStr
			}
			role(s, key, v, e, kind, fn)
		}
		if i = skipSpace(s, e); i == len(s) {
			return i, false
		}
		switch s[i] {
		case ',':
			mark(MarkPunct, i, i+1)
			i = skipSpace(s, i+1)
		case closer:
			mark(MarkPunct, i, i+1)
			return i + 1, true
		default:
			return i, false
		}
	}
	return i, false
}
