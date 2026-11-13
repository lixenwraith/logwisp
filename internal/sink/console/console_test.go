package console

import (
	"io"
	"testing"

	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/terminal/inline"
)

// Each mark is painted in its kind's style, a level in its level's, one
// without a style (PROC) left plain; the text between marks stays as written.
func TestPaintStylesEachMarkAndKeepsTheText(t *testing.T) {
	p := inline.New(io.Discard)
	p.SetColor(true)
	grey, red, magenta, cyan := "\x1b[0;90m", "\x1b[0;1;31m", "\x1b[0;35m", "\x1b[0;36m"
	end := "\x1b[0m"
	for _, c := range []struct {
		in    string
		entry core.LogEntry
		want  string
	}{
		{"2026-11-05T07:51:43Z ERROR app \"disk full\" dev=sda\n", core.LogEntry{Level: "ERROR", Source: "app"},
			grey + "2026-11-05T07:51:43Z" + end + " " + red + "ERROR" + end + " " + magenta + "app" + end + " \"disk full\" " + cyan + "dev" + end + grey + "=" + end + "sda\n"},
		{"{\"level\":\"PROC\"}\n", core.LogEntry{Level: "PROC"},
			grey + "{" + end + cyan + "\"level\"" + end + grey + ":" + end + "\"PROC\"" + grey + "}" + end + "\n"},
	} {
		if got := string(newPalette(p).paint(nil, []byte(c.in), c.entry)); got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}
