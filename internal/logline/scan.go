package logline

import "encoding/json"

// JSON token kinds
const (
	kNone byte = 0
	kStr  byte = 's'
	kNum  byte = 'n'
	kBool byte = 'b'
	kNull byte = 'z'
	kObj  byte = 'o'
	kArr  byte = 'a'
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

// unquote returns the content of a string token, decoding only when it holds
// an escape; any other token is returned as its JSON.
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
