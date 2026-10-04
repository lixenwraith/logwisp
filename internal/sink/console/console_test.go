package console

import "testing"

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
