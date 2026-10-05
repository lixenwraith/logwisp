package core

import "testing"

// A line's level is its first whole word, in any case, naming a level, not the
// most severe one named; a wanted level skips the names of the others.
func TestLevelIsTheFirstWordNamingOne(t *testing.T) {
	for _, c := range []struct {
		text, want, level string
		start, end        int
	}{
		{"warning disk full", "", "WARN", 0, 7},
		{"DBG x", "", "DEBUG", 0, 3},
		{"2026-10-05 [Info] retry after error", "", "INFO", 12, 16},
		{`{"level":"fatal","msg":"x"}`, "", "ERROR", 10, 15},
		{"terror informal x_ERR", "", "", 0, 0},
		{"INFO then ERR", "ERROR", "ERROR", 10, 13},
	} {
		level, start, end := LevelWord(c.text, c.want)
		if level != c.level || start != c.start || end != c.end {
			t.Errorf("%q want %q: got %q [%d:%d], want %q [%d:%d]", c.text, c.want, level, start, end, c.level, c.start, c.end)
		}
	}
}
