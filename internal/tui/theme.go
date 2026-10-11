package tui

import (
	"os"
	"strings"
	"unicode"

	"github.com/lixenwraith/color"
	"github.com/lixenwraith/terminal"
	ui "github.com/lixenwraith/terminal/tui"
)

// look is a color tier's styles: the widgets' theme, each column's tint, and
// the live view's levels by name, any other drawn as text
type look struct {
	ui.Theme
	Source, Flow, Sink ui.Style
	Levels             map[string]ui.Style
}

// The website's dark tokens; true color and 256 colors paint its background
var (
	siteBg = color.RGB{R: 0x11, G: 0x11, B: 0x1b} // --dark-bg
	siteFg = color.RGB{R: 0xff, G: 0xff, B: 0xff} // --text-color
)

var siteLook = look{
	Theme: ui.Theme{
		Text:     ui.Style{Fg: siteFg, Bg: siteBg},
		Muted:    ui.Style{Fg: color.RGB{R: 0x94, G: 0xa3, B: 0xb8}},                          // --muted-color
		Accent:   ui.Style{Fg: color.RGB{R: 0x8e, G: 0xa2, B: 0xff}, Attr: terminal.AttrBold}, // --accent-color
		Selected: ui.Style{Bg: color.RGB{R: 0x1d, G: 0x1c, B: 0x3e}},                          // --card-background-color
		Input:    ui.Style{Bg: color.RGB{R: 0x1a, G: 0x1b, B: 0x26}},                          // --dark-surface
		Cursor:   ui.Style{Fg: siteBg, Bg: siteFg},
		Error:    ui.Style{Fg: color.RGB{R: 0xf8, G: 0x71, B: 0x71}}, // --danger-color
		Border:   ui.Style{Fg: color.RGB{R: 0x7c, G: 0x7c, B: 0x82}}, // the diagram's --wire
	},
	Source: ui.Style{Fg: color.RGB{R: 0x22, G: 0xd3, B: 0xee}}, // --hue-cyan
	Flow:   ui.Style{Fg: color.RGB{R: 0xa7, G: 0x8b, B: 0xfa}}, // --hue-violet
	Sink:   ui.Style{Fg: color.RGB{R: 0x34, G: 0xd3, B: 0x99}}, // --hue-green
	Levels: map[string]ui.Style{
		"TRACE": {Fg: color.RGB{R: 0x94, G: 0xa3, B: 0xb8}},                          // --hue-slate
		"DEBUG": {Fg: color.RGB{R: 0x60, G: 0xa5, B: 0xfa}},                          // --hue-blue
		"INFO":  {Fg: color.RGB{R: 0x34, G: 0xd3, B: 0x99}},                          // --ok-color
		"WARN":  {Fg: color.RGB{R: 0xfb, G: 0xbf, B: 0x24}},                          // --warn-color
		"ERROR": {Fg: color.RGB{R: 0xf8, G: 0x71, B: 0x71}, Attr: terminal.AttrBold}, // --danger-color
	},
}

// console16 is the 16-color look, a text console's, where bold is bright:
// text is palette white rather than bold, which On would spread to every role
// drawn on it; muted the console's own grey; the cursor row a blue bar under
// which every role stays readable
var console16 = ui.Theme{
	Text:     ui.Style{Fg: color.RGB{R: color.ANSIBrightWhite}, Attr: terminal.AttrFg256 | terminal.AttrBgDefault},
	Muted:    ui.Style{Attr: terminal.AttrFgDefault},
	Accent:   ansi(color.ANSIBrightYellow),
	Selected: ui.Style{Bg: color.RGB{R: color.ANSIBlue}, Attr: terminal.AttrBg256},
	Input:    ui.Theme16.Input,
	Cursor:   ui.Theme16.Cursor,
	Error:    ui.Theme16.Error,
	Border:   ui.Style{Attr: terminal.AttrFgDefault},
}

// ansi is a palette index the terminal shows in its own shade
func ansi(i uint8) ui.Style { return ui.Style{Fg: color.RGB{R: i}, Attr: terminal.AttrFg256} }

// looks holds one look per color tier: 16 colors and none keep the
// terminal's background. Levels in 16 colors are picked by hand, as the
// quantizer turns the site's pastels grey; without color, bold and dim only
// add to the level's name.
var looks = map[terminal.ColorMode]look{
	terminal.ColorModeTrueColor: siteLook,
	terminal.ColorMode256:       siteLook,
	terminal.ColorMode16: {Theme: console16,
		Source: ansi(color.ANSICyan), Flow: ansi(color.ANSIBrightMagenta), Sink: ansi(color.ANSIGreen),
		Levels: map[string]ui.Style{"TRACE": console16.Muted, "DEBUG": ansi(color.ANSICyan), "INFO": ansi(color.ANSIGreen),
			"WARN": ansi(color.ANSIBrightYellow), "ERROR": ansi(color.ANSIBrightRed)}},
	terminal.ColorModeNone: {Theme: ui.MonoTheme,
		Source: ui.MonoTheme.Text, Flow: ui.MonoTheme.Text, Sink: ui.MonoTheme.Text,
		Levels: map[string]ui.Style{"TRACE": ui.MonoTheme.Muted, "DEBUG": ui.MonoTheme.Muted, "INFO": ui.MonoTheme.Text,
			"WARN": ui.MonoTheme.Accent, "ERROR": ui.MonoTheme.Accent}},
}

// font is the marks one character set draws: the widgets' and the canvas's;
// Glyphs.Line draws frames, rules and wires
type font struct {
	ui.Glyphs
	box         ui.LineType // the flow box
	arrow, down rune        // into the flow box and a sink; between stacked parts
	bar, barOn  rune        // a node, and the chosen node
	dot         rune        // before a column's title
	newline     rune        // a line break in a row of the live view
	odd         rune        // in the live view, a rune a cell cannot show
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
	unicodeFont = font{Glyphs: ui.GlyphsUnicode, box: ui.LineDashed,
		arrow: '►', down: '▼', bar: '▌', barOn: '█', dot: '●', newline: '↵', odd: '\uFFFD', valid: "✓", invalid: "✗", enter: "⏎", space: "␣"}
	cp437Font = font{Glyphs: ui.GlyphsCP437, box: ui.LineSingle,
		arrow: '►', down: '▼', bar: '▌', barOn: '█', dot: '•', newline: '¶', odd: '?', valid: "√", invalid: "x", enter: "enter", space: "space",
		folds: map[rune]rune{'…': '.'}}
	asciiFont = font{Glyphs: ui.GlyphsASCII, box: ui.LineASCII,
		arrow: '>', down: 'v', bar: '|', barOn: '#', dot: '*', newline: '|', odd: '?', valid: "ok", invalid: "x", enter: "enter", space: "space",
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
