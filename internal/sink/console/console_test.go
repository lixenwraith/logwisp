package console

import (
	"io"
	"testing"

	"github.com/lixenwraith/terminal/inline"
)

// Everything a terminal would act on is escaped; tabs and the final newline,
// which it only lays out, are kept.
func TestEscapeControlsKeepsOnlyLayout(t *testing.T) {
	for in, want := range map[string]string{
		"plain\ttext\n":                    "plain\ttext\n",
		"a\x1b[2Jb\n":                      "a<1b>[2Jb\n",
		"bell\x07 del\x7f\n":               "bell<07> del<7f>\n",
		"inner\nnewline\n":                 "inner<0a>newline\n",
		"c1 \u009b31m\n":                   "c1 <c29b>31m\n",
		"bidi \u202eevil\n":                "bidi <e280ae>evil\n",
		"isolate \u2066x\u2069\n":          "isolate <e281a6>x<e281a9>\n",
		"line\u2028sep\n":                  "line<e280a8>sep\n",
		"zwj \U0001f468\u200d\U0001f469\n": "zwj \U0001f468\u200d\U0001f469\n",
		"bad \xff utf8":                    "bad <ff> utf8",
		"ünïcødé and \ufffd kept\n":        "ünïcødé and \ufffd kept\n",
	} {
		if got := string(escapeControls([]byte(in))); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// The entry's level is painted where its line first names it as a whole
// word, in any case, longest name first; other words and levels stay plain.
func TestPaintLevelColorsTheFirstWholeName(t *testing.T) {
	p := inline.New(io.Discard)
	p.SetColor(true)
	red, yellow := "\x1b[0;1;31m", "\x1b[0;33m"
	for _, c := range []struct{ in, level, want string }{
		{"2026 ERROR boom ERROR\n", "ERROR", "2026 " + red + "ERROR\x1b[0m boom ERROR\n"},
		{"[warning] disk\n", "WARN", "[" + yellow + "warning\x1b[0m] disk\n"},
		{"terror_x ERR:1\n", "ERROR", "terror_x " + red + "ERR\x1b[0m:1\n"},
		{"INFOS informal\n", "INFO", "INFOS informal\n"},
		{"ERROR without level\n", "", "ERROR without level\n"},
	} {
		if got := string(paintLevel(p, []byte(c.in), c.level)); got != c.want {
			t.Errorf("%q %s: got %q, want %q", c.in, c.level, got, c.want)
		}
	}
}
