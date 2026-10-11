package console

import (
	"io"
	"testing"

	"github.com/lixenwraith/terminal/inline"
)

// The entry's level, under any of its names, is painted where its line first
// names it as a whole word, in any case; other words and levels stay plain.
func TestPaintLevelColorsTheFirstWholeName(t *testing.T) {
	p := inline.New(io.Discard)
	p.SetColor(true)
	red, yellow := "\x1b[0;1;31m", "\x1b[0;33m"
	for _, c := range []struct{ in, level, want string }{
		{"2026 ERROR boom ERROR\n", "ERROR", "2026 " + red + "ERROR\x1b[0m boom ERROR\n"},
		{"[warning] disk\n", "WARN", "[" + yellow + "warning\x1b[0m] disk\n"},
		{"INFO: WARN disk\n", "warning", "INFO: " + yellow + "WARN\x1b[0m disk\n"},
		{"terror_x ERR:1\n", "ERROR", "terror_x " + red + "ERR\x1b[0m:1\n"},
		{"INFOS informal\n", "INFO", "INFOS informal\n"},
		{"ERROR without level\n", "", "ERROR without level\n"},
	} {
		if got := string(paintLevel(p, []byte(c.in), c.level)); got != c.want {
			t.Errorf("%q %s: got %q, want %q", c.in, c.level, got, c.want)
		}
	}
}
