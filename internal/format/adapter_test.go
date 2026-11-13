package format

import (
	"bytes"
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
