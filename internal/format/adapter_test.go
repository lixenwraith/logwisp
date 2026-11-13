package format

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
)

// Every payload is one record ending in exactly one newline, whatever the
// type and whether or not the message carried its own.
func TestEveryRecordEndsInOneNewline(t *testing.T) {
	entries := []core.LogEntry{
		{Message: "plain"},
		{Message: "carried\n"},
		{Fields: []byte(`{"k":1}`)},
		{Message: "with", Fields: []byte(`{"k":1}`)},
	}
	for _, typ := range []string{"raw", "txt", "json"} {
		f, err := NewFormatter(&config.FormatConfig{Type: typ})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			e.Time = time.Now()
			out, _ := f.Format(e)
			if !bytes.HasSuffix(out, []byte("\n")) || bytes.HasSuffix(out, []byte("\n\n")) {
				t.Errorf("%s %+v: %q", typ, e, out)
			}
		}
	}
}

// An entry's level is written as the level its word names in core.Levels, in
// any case; no level, or another word, is written as INFO
func TestLevelIsWrittenAsTheLevelItsWordNames(t *testing.T) {
	f, err := NewFormatter(&config.FormatConfig{Type: "json"})
	if err != nil {
		t.Fatal(err)
	}
	for level, want := range map[string]string{"TRACE": "TRACE", "debug": "DEBUG", "": "INFO", "warning": "WARN",
		"fatal": "ERROR", "crit": "ERROR", "chatty": "INFO"} {
		out, _ := f.Format(core.LogEntry{Time: time.Now(), Level: level, Message: "m"})
		if !bytes.Contains(out, []byte(`"level":"`+want+`"`)) {
			t.Errorf("level %q: %s", level, out)
		}
	}
}

// A pipeline's sources share its formatter and format at once: each record is
// its own entry's, whole, however the calls interleave
func TestSourcesFormatAtOnce(t *testing.T) {
	f, err := NewFormatter(&config.FormatConfig{Type: "txt"})
	if err != nil {
		t.Fatal(err)
	}
	entry := func(g, i int) core.LogEntry {
		return core.LogEntry{Time: time.Unix(int64(i), 0), Source: "s", Level: "INFO",
			Message: strings.Repeat(strconv.Itoa(g), 1+i%300)}
	}
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 2000 {
				got, _ := f.Format(entry(g, i))
				if want, _ := f.Format(entry(g, i)); !bytes.Equal(got, want) || !bytes.Contains(got, []byte(entry(g, i).Message+"\n")) {
					t.Errorf("source %d entry %d: %q", g, i, got)
					return
				}
			}
		})
	}
	wg.Wait()
}

// Fields over 64 KiB are written as their JSON text, not decoded: a peer's
// dense fields cost what a message of their size does
func TestLargeFieldsAreWrittenAsText(t *testing.T) {
	fields := []byte(`{"k":[` + strings.Repeat(`{},`, maxDecodedFields/3) + `{}]}`)
	for _, typ := range []string{"txt", "json"} {
		f, err := NewFormatter(&config.FormatConfig{Type: typ})
		if err != nil {
			t.Fatal(err)
		}
		e := core.LogEntry{Time: time.Now(), Message: "m", Fields: fields}
		out, _ := f.Format(e)
		if !bytes.Contains(out, []byte(`{\"k\":[{},{},`)) {
			t.Errorf("%s: %.200s", typ, out)
		}
		if allocs := testing.AllocsPerRun(5, func() { f.Format(e) }); allocs > 10 {
			t.Errorf("%s: %v allocations for %d bytes of fields", typ, allocs, len(fields))
		}
	}
}

// A fields number keeps its digits: an integer past 2^53 is not rounded, and
// one past a float64's range does not drop the fields. Shorter numbers, which
// a float64 holds, are written as before.
func TestFieldsNumbersKeepTheirDigits(t *testing.T) {
	fields := []byte(`{"trace":1234567890123456789,"ratio":0.1234567890123456789,"big":1e400,"n":42,"pi":3.14,"s":"1e5"}`)
	for typ, want := range map[string][]string{
		"json": {`"trace":1234567890123456789`, `"ratio":0.1234567890123456789`, `"big":1e400`, `"n":42`, `"pi":3.14`, `"s":"1e5"`},
		"txt":  {`trace:1234567890123456789`, `ratio:0.1234567890123456789`, `big:1e400`, `n:42`, `pi:3.14`, `s:1e5`},
	} {
		f, err := NewFormatter(&config.FormatConfig{Type: typ})
		if err != nil {
			t.Fatal(err)
		}
		out, _ := f.Format(core.LogEntry{Time: time.Now(), Message: "m", Fields: fields})
		for _, w := range want {
			if !bytes.Contains(out, []byte(w)) {
				t.Errorf("%s: no %s in %s", typ, w, out)
			}
		}
	}
	for in, exact := range map[string]bool{`{"a":123456789012345}`: false, `{"a":1234567890123456}`: true, `{"a":1.5,"b":true}`: false,
		`{"a":2E3}`: true, `{"a":"12345678901234567","e":"1e5"}`: false, `{"a":"\\"}`: false, `{"a":[1.000000000000001]}`: true} {
		if exactNumbers([]byte(in)) != exact {
			t.Errorf("%s: exact %v, want %v", in, !exact, exact)
		}
	}
}
