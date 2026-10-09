package tui

import (
	"os"
	"strings"
	"unicode"

	"github.com/lixenwraith/color"
	"github.com/lixenwraith/terminal"
	ui "github.com/lixenwraith/terminal/tui"
)

// look is a color tier's styles: the widgets' theme and each column's tint
type look struct {
	ui.Theme
	Source, Flow, Sink ui.Style
}

// The site's dark tokens; true color and 256 colors paint its background
var (
	siteBg     = color.RGB{R: 0x14, G: 0x17, B: 0x1d}
	sitePanel  = color.RGB{R: 0x1c, G: 0x20, B: 0x28}
	siteFg     = color.RGB{R: 0xe3, G: 0xe7, B: 0xef}
	siteMuted  = color.RGB{R: 0x9a, G: 0xa3, B: 0xb5}
	siteAccent = color.RGB{R: 0x6e, G: 0xa0, B: 0xff}
)

var siteLook = look{
	Theme: ui.Theme{
		Text:     ui.Style{Fg: siteFg, Bg: siteBg},
		Muted:    ui.Style{Fg: siteMuted},
		Accent:   ui.Style{Fg: siteAccent, Attr: terminal.AttrBold},
		Selected: ui.Style{Bg: color.RGB{R: 0x26, G: 0x2c, B: 0x38}},
		Input:    ui.Style{Bg: sitePanel},
		Cursor:   ui.Style{Fg: siteBg, Bg: siteFg},
		Error:    ui.Style{Fg: color.RGB{R: 0xff, G: 0x6b, B: 0x6b}},
		Border:   ui.Style{Fg: color.RGB{R: 0x5a, G: 0x63, B: 0x75}},
	},
	Source: ui.Style{Fg: color.RGB{R: 0x56, G: 0xc8, B: 0xd8}},
	Flow:   ui.Style{Fg: color.RGB{R: 0xb1, G: 0x8c, B: 0xff}},
	Sink:   ui.Style{Fg: color.RGB{R: 0x6f, G: 0xcf, B: 0x8f}},
}

// ansi is a palette index the terminal shows in its own shade
func ansi(i uint8) ui.Style { return ui.Style{Fg: color.RGB{R: i}, Attr: terminal.AttrFg256} }

// looks holds one look per color tier: 16 colors and none keep the
// terminal's background
var looks = map[terminal.ColorMode]look{
	terminal.ColorModeTrueColor: siteLook,
	terminal.ColorMode256:       siteLook,
	terminal.ColorMode16: {Theme: ui.Theme16,
		Source: ansi(color.ANSICyan), Flow: ansi(color.ANSIMagenta), Sink: ansi(color.ANSIGreen)},
	terminal.ColorModeNone: {Theme: ui.MonoTheme,
		Source: ui.MonoTheme.Text, Flow: ui.MonoTheme.Text, Sink: ui.MonoTheme.Text},
}

// font is the marks one character set draws: the widgets' and the canvas's
type font struct {
	ui.Glyphs
	wire        []rune // a wire cell by its arms: up 1, right 2, down 4, left 8
	box         []rune // the flow box: top left, top right, bottom left, bottom right, across, down
	arrow, down rune   // into the flow box and a sink; between stacked parts
	bar, barOn  rune   // a node, and the chosen node
	dot, rule   rune   // before a column's title; the inspector's rule
	valid       string
	invalid     string
	enter       string
	space       string
	folds       map[rune]rune // runes its terminal lacks, by the rune drawn instead
	ascii       bool          // past ASCII, any other rune draws as '?'
}

// fold is r as the font's terminal shows it: the library truncates with '…'
// and the inspector's titles join with '·'
func (f font) fold(r rune) rune {
	if to, ok := f.folds[r]; ok {
		return to
	}
	if f.ascii && r > unicode.MaxASCII {
		return '?'
	}
	return r
}

// fonts: Unicode, a text console's CP437, and ASCII outside UTF-8
var (
	unicodeFont = font{Glyphs: ui.GlyphsUnicode, wire: []rune(" │─└││┌├─┘─┴┐┤┬┼"), box: []rune("╭╮╰╯╌╎"),
		arrow: '►', down: '▼', bar: '▌', barOn: '█', dot: '●', rule: '─', valid: "✓", invalid: "✗", enter: "⏎", space: "␣"}
	cp437Font = font{Glyphs: ui.GlyphsCP437, wire: []rune(" │─└││┌├─┘─┴┐┤┬┼"), box: []rune("┌┐└┘─│"),
		arrow: '►', down: '▼', bar: '▌', barOn: '█', dot: '•', rule: '─', valid: "√", invalid: "x", enter: "enter", space: "space",
		folds: map[rune]rune{'…': '.'}}
	asciiFont = font{Glyphs: ui.GlyphsASCII, wire: []rune(" |-+||++-+-+++++"), box: []rune("++++-|"),
		arrow: '>', down: 'v', bar: '|', barOn: '#', dot: '*', rule: '-', valid: "ok", invalid: "x", enter: "enter", space: "space",
		folds: map[rune]rune{'…': '.', '·': '-'}, ascii: true}
)

// fontFor picks ASCII outside a UTF-8 locale, CP437 on a text console (the
// terminals with 16 colors), Unicode elsewhere
func fontFor(detected terminal.ColorMode) font {
	locale := ""
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if locale = os.Getenv(name); locale != "" {
			break
		}
	}
	switch l := strings.ToLower(locale); {
	case l != "" && !strings.Contains(l, "utf-8") && !strings.Contains(l, "utf8"):
		return asciiFont
	case detected == terminal.ColorMode16:
		return cp437Font
	}
	return unicodeFont
}
