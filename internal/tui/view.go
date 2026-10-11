package tui

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/logline"

	"github.com/lixenwraith/terminal"
	ui "github.com/lixenwraith/terminal/tui"
)

const (
	splitMin     = 40       // the shortest screen with the diagram over the live view
	ringBytes    = 32 << 20 // what the view's rows may hold
	drainBytes   = 1 << 20  // what a tick reads from the taps; the rest waits for the next
	drainEvery   = 100 * time.Millisecond
	detailBeside = 160 // the narrowest view with the detail beside its rows
	rowBytes     = 400 // a row's own fields, counted beside its text
	fieldBytes   = 32  // a field's two string headers
)

// passed ranks the verdict of an entry no stage dropped: past every stage
const passed = 1 << 30

// stages are the flow's stages in the order entries pass them
var stages = func() (out []string) {
	for _, s := range config.FlowStages() {
		out = append(out, s.Key)
	}
	return out
}()

// rank orders a verdict along the flow: the stage that dropped the entry, a
// filter by its index, or passed
func rank(stage string, index int) int {
	if stage == "" {
		return passed
	}
	return slices.Index(stages, stage)<<16 | min(max(index, 0), 1<<16-1)
}

// row is an entry the view holds, read once through logline on arrival into
// text of its own, or a rule across the rows where a run ended
type row struct {
	logline.Line // Level as written when outside core.Levels (PROC)
	seq          uint64
	at           time.Time
	level        int    // in core.Levels, -1 for none or one outside them
	fields       string // Fields as k=v, as the list shows them
	pipe, source string // pipe is "" for lw's own log and rules
	stage        string
	index, rank  int
	payload      []byte
	size         int    // what it holds: its text, payload and rowBytes
	mark         string // a rule's text
}

// view is the live view: rows bounded by what they hold, and the seqs of
// those the filters pass, oldest first. The screen's goroutine alone uses it.
type view struct {
	rows    []row
	bytes   int
	next    uint64
	shown   []uint64
	cursor  int // in shown
	scroll  int
	paused  bool // the cursor keeps its row; else it is on the newest
	detail  bool
	dscroll int
	tagW    int
	listH   int
	mode    int
	floor   int  // 0 shows every row, n those of core.Levels[n-1] and above
	own     bool // the point is lw's own log until the canvas cursor moves
	pat     pattern
	prompt  *ui.TextFieldState // the pattern being typed
	built   query              // what shown holds
}

// query is what picks the rows shown
type query struct {
	at          point
	mode, floor int
	pattern     string
}

// verdicts are what the view shows at its point: all that reaches it, what
// passed it, what it dropped
var verdicts = [...]string{"all", "passed", "dropped"}

const (
	modeAll = iota
	modePassed
	modeDropped
)

// point is where on a pipeline the view looks, as the canvas cursor picks
// it: the verdicts reaching it rank from reach, those it drops from lo to
// hi; a source's and the heartbeat's take only their own entries. own is
// lw's own log alone, which s picks. all says what mode all shows.
type point struct {
	pipe, name, all string
	one, own        bool
	source          string
	reach           int
	lo, hi          int
}

// lwShown is the lowest level of lw's own log a pipeline's point shows, so
// its startup records do not bury the entries
var lwShown = slices.IndexFunc(core.Levels, func(l core.Level) bool { return l.Level == "WARN" })

// shows reports whether the point in mode shows r: lw's own log shows from
// warn up at every point and whole at its own, which names no pipeline; a
// heartbeat only at the sinks' and its own
func (p point) shows(r *row, mode int) bool {
	switch {
	case r.pipe == "":
		return p.own || r.level >= lwShown
	case r.pipe != p.pipe || p.one && r.source != p.source, r.source == "" && p.reach != passed:
		return false
	case mode == modeDropped:
		return p.lo <= r.rank && r.rank <= p.hi
	case mode == modePassed:
		return r.rank > p.hi
	}
	return r.rank >= p.reach
}

// needsDrops reports whether the point in mode shows entries the flow
// dropped, which the tap then takes too
func (p point) needsDrops(mode int) bool {
	switch mode {
	case modeDropped:
		return p.lo <= p.hi
	case modePassed:
		return p.hi+1 < passed
	}
	return p.reach < passed
}

// point is where the canvas cursor looks: a source, a flow stage or the
// filter the inspector is on, the heartbeat, or the sinks
func (a *app) point() point {
	p := point{name: "sinks", all: "all they got", reach: passed, hi: passed - 1}
	switch {
	case a.view.own:
		return point{name: "lw's own log", own: true, reach: passed, lo: passed, hi: passed - 1}
	case len(a.comp.Pipelines) == 0:
		return p
	}
	p.pipe = a.pipeline().Name
	n, ok := a.node()
	if l := a.lines(); a.inspect && ok && n.Role == "filters" && len(l) > 0 {
		if m := l[min(a.insp.cursor, len(l)-1)].node; m.Index < len(a.pipeline().Flow.Filters) {
			r := rank("filters", m.Index)
			return point{pipe: p.pipe, name: fmt.Sprintf("filter %d", m.Index+1), all: "all that reaches it", reach: r, lo: r, hi: r}
		}
	}
	switch {
	case !ok || n.Role == "sink":
	case n.Role == "source":
		p.name, p.all, p.one, p.source, p.reach = "source "+n.ID, "all it reads", true, n.ID, 0
	case n.Role == "heartbeat":
		p.name, p.all, p.one, p.lo, p.hi = "heartbeat", "all it sends", true, 1, 0
	default:
		p.name, p.all, p.reach, p.lo, p.hi = n.Role, "all that reaches it", rank(n.Role, 0), rank(n.Role, 0), rank(n.Role, 1<<16-1)
	}
	return p
}

// take adds a tapped record as a row and returns what the row holds
func (v *view) take(t core.Tapped) int {
	e := t.Event.Entry
	r := row{Line: logline.Read(e), pipe: t.Pipeline, source: t.Source,
		stage: t.Stage, index: t.Index, rank: rank(t.Stage, t.Index), payload: t.Event.Payload}
	r.at = r.Time
	for _, at := range []time.Time{e.Time, t.Event.Time, time.Now()} {
		if r.at.IsZero() {
			r.at = at
		}
	}
	r.level = slices.IndexFunc(core.Levels, func(l core.Level) bool { return l.Level == r.Level })
	var b strings.Builder
	for _, f := range r.Fields {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		if f.Key != "" {
			b.WriteString(f.Key + "=")
		}
		b.WriteString(f.Value)
	}
	r.fields = b.String()
	r.size = rowBytes + r.own() + len(r.fields) + len(r.payload)
	v.tagW = max(v.tagW, ui.RuneLen(r.Tag))
	v.add(r)
	return r.size
}

// own copies the line's text, which logline cuts from the entry's, so a row
// pins no entry and its size is what it holds; it returns those bytes
func (r *row) own() int {
	l := &r.Line
	for _, s := range []*string{&l.Stamp, &l.Level, &l.Tag, &l.Message, &l.Layout} {
		*s = strings.Clone(*s)
	}
	n := len(l.Stamp) + len(l.Level) + len(l.Tag) + len(l.Message) + len(l.Layout)
	fields := make([]logline.Field, len(l.Fields))
	for i, f := range l.Fields {
		fields[i] = logline.Field{Key: strings.Clone(f.Key), Value: strings.Clone(f.Value)}
		n += fieldBytes + len(f.Key) + len(f.Value)
	}
	l.Fields = fields
	return n
}

// dropped reports whether the flow dropped the row
func (r *row) dropped() bool { return r.stage != "" }

// mark draws a rule across the rows, which every filter shows
func (v *view) mark(text string) { v.add(row{mark: text, level: -1, size: rowBytes}) }

// add appends r, then evicts the oldest rows past ringBytes; the cursor
// keeps its row, or takes the oldest kept when its own went
func (v *view) add(r row) {
	r.seq = v.next
	v.next++
	v.rows = append(v.rows, r)
	v.bytes += r.size
	if v.passes(&v.rows[len(v.rows)-1]) {
		v.shown = append(v.shown, r.seq)
	}
	for v.bytes > ringBytes && len(v.rows) > 1 {
		old := v.rows[0].seq
		v.bytes -= v.rows[0].size
		v.rows[0] = row{} // the array keeps no evicted text
		v.rows = v.rows[1:]
		if len(v.shown) > 0 && v.shown[0] == old {
			v.shown = v.shown[1:]
			v.cursor, v.scroll = max(0, v.cursor-1), max(0, v.scroll-1)
		}
	}
}

// passes reports whether the query shown was built for shows r; a rule shows
// always
func (v *view) passes(r *row) bool {
	q := v.built
	switch {
	case r.mark != "":
		return true
	case !q.at.shows(r, q.mode), q.floor > 0 && r.level < q.floor-1:
		return false
	}
	return v.pat.match(r.Message) || v.pat.match(r.fields) || v.pat.match(r.Tag)
}

// sync rebuilds the rows shown when the point or a filter changed, and has
// the tap take drops while they show. A paused cursor stays on its row, and
// that on its screen row; so does a following one when a filter changed, which
// pauses it unless its row is still the newest.
func (v *view) sync(at point, tap *core.Tap) {
	if tap != nil {
		tap.All.Store(at.needsDrops(v.mode))
	}
	q, was := query{at, v.mode, v.floor, v.pat.src}, v.built
	if q == was {
		return
	}
	v.built = q
	f := v.focused()
	line := v.cursor - v.scroll
	v.shown = v.shown[:0]
	for i := range v.rows {
		if v.passes(&v.rows[i]) {
			v.shown = append(v.shown, v.rows[i].seq)
		}
	}
	if f != nil && (v.paused || q.pattern != was.pattern || q.floor != was.floor) {
		v.cursor, _ = slices.BinarySearch(v.shown, f.seq)
		v.scroll = v.cursor - line
		v.paused = v.paused || v.cursor < len(v.shown)-1
	}
	v.settle()
}

// settle puts the cursor on the newest row while following, and in range
func (v *view) settle() {
	if !v.paused {
		v.cursor = len(v.shown) - 1
	}
	v.cursor = max(0, min(v.cursor, len(v.shown)-1))
}

// move moves the cursor d rows: off the newest pauses, onto it follows
func (v *view) move(d int) {
	v.settle()
	v.cursor = max(0, min(v.cursor+d, len(v.shown)-1))
	v.paused, v.dscroll = v.cursor < len(v.shown)-1, 0
}

// focused is the cursor's row, nil while none shows
func (v *view) focused() *row {
	if len(v.shown) == 0 {
		return nil
	}
	v.settle()
	return &v.rows[v.shown[v.cursor]-v.rows[0].seq]
}

// focusedEntry is the cursor's row when it is an entry, nil on a rule or none
func (v *view) focusedEntry() *row {
	if w := v.focused(); w != nil && w.mark == "" {
		return w
	}
	return nil
}

func (v *view) clear() {
	v.rows, v.shown, v.bytes, v.cursor, v.scroll, v.paused = nil, nil, 0, 0, 0, false
}

// drain reads taps into the view until they are empty or it read budget
// bytes; what is left waits for the next tick
func (a *app) drain(budget int, taps ...*core.Tap) {
	for budget > 0 {
		took := false
		for _, t := range taps {
			if t == nil {
				continue
			}
			select {
			case rec := <-t.Records():
				budget -= a.view.take(rec)
				took = true
			default:
			}
		}
		if !took {
			return
		}
	}
}

// viewKey takes the keys of the live view; the composer's stay inert but for
// quitting, help, running, printing and the pipelines
func (a *app) viewKey(ev terminal.Event) {
	v := &a.view
	if v.prompt != nil {
		a.promptKey(ev)
		return
	}
	switch {
	case ev.Type != terminal.EventKey:
	case is(ev, terminal.KeyUp, "k"):
		v.move(-1)
	case is(ev, terminal.KeyDown, "j"):
		v.move(1)
	case is(ev, terminal.KeyPageUp, ""):
		v.move(-ui.PageDelta(v.listH))
	case is(ev, terminal.KeyPageDown, ""):
		v.move(ui.PageDelta(v.listH))
	case is(ev, terminal.KeyHome, "g"):
		v.move(-len(v.shown))
	case is(ev, terminal.KeyEnd, "Gf"):
		v.paused = false
	case is(ev, terminal.KeyEnter, ""):
		v.detail, v.dscroll = !v.detail, 0
	case is(ev, terminal.KeyNone, "J"):
		v.dscroll++
	case is(ev, terminal.KeyNone, "K"):
		v.dscroll = max(0, v.dscroll-1)
	case is(ev, terminal.KeyNone, "/"):
		v.prompt = ui.NewTextFieldState(v.pat.src)
	case is(ev, terminal.KeyNone, "012345"):
		v.floor = int(ev.Rune - '0')
	case is(ev, terminal.KeyNone, "v"):
		v.mode = (v.mode + 1) % len(verdicts)
	case is(ev, terminal.KeyNone, "s"):
		a.dialog = a.pointMenu()
	case is(ev, terminal.KeyNone, "c"):
		v.clear()
	case is(ev, terminal.KeyNone, "i") && v.focusedEntry() != nil:
		a.dialog = &entry{row: *v.focusedEntry()}
	case is(ev, terminal.KeyNone, "e"):
		a.editDrop(v.focusedEntry())
	case is(ev, terminal.KeyEscape, "") && v.detail:
		v.detail = false
	case is(ev, terminal.KeyEscape, "t"):
		a.viewing = false
	case is(ev, terminal.KeyCtrlC, "q?ro[]"):
		a.globalKey(ev)
	}
}

// promptKey types the pattern; Enter shows the rows matching it, all when it
// is empty
func (a *app) promptKey(ev terminal.Event) {
	v := &a.view
	switch {
	case ev.Type == terminal.EventPaste:
		v.prompt.Paste(ev.Text)
	case ev.Type != terminal.EventKey:
	case is(ev, terminal.KeyEscape, ""):
		v.prompt = nil
	case is(ev, terminal.KeyEnter, ""):
		p, err := newPattern(v.prompt.Value())
		if v.prompt = nil; err != nil {
			a.status = "pattern: " + err.Error()
			return
		}
		v.pat = p
	default:
		v.prompt.HandleKey(ev.Key, ev.Rune, ev.Modifiers)
	}
}

// editDrop opens the inspector on the stage that dropped w
func (a *app) editDrop(w *row) {
	pi := -1
	if w != nil {
		pi = a.pipeIndex(w.pipe)
	}
	switch {
	case w == nil || pi < 0:
		a.note = "e edits the stage that dropped an entry"
		return
	case !w.dropped():
		a.note = "it passed every stage"
		return
	}
	n := compose.Node{Role: w.stage}
	if w.stage == "filters" {
		n.Index = w.index
	}
	a.pi, a.viewing = pi, false
	a.choose(n)
	a.inspectAt(func(l line) bool { return l.node == n })
}

// pipeIndex is the pipeline named name, -1 when none is
func (a *app) pipeIndex(name string) int {
	return slices.IndexFunc(a.comp.Pipelines, func(p config.PipelineConfig) bool { return p.Name == name })
}

// pointMenu picks where the view looks, moving the canvas cursor there, or
// lw's own log while it reaches the screen: s
func (a *app) pointMenu() dialog {
	type at struct {
		pi, col int
		n       compose.Node
		own     bool
	}
	var options []ui.Option
	var ats []at
	for pi, p := range a.comp.Pipelines {
		add := func(name, hint string, col int, n compose.Node) {
			if len(a.comp.Pipelines) > 1 {
				name = p.Name + " · " + name
			}
			options = append(options, ui.Option{Name: name, Hint: hint})
			ats = append(ats, at{pi: pi, col: col, n: n})
		}
		for _, s := range p.PluginSources {
			add("source "+s.ID, "its entries", sourcesCol, compose.Node{Role: "source", ID: s.ID})
		}
		for _, s := range stages {
			hint := "what reaches it, passes it, or it drops"
			if s == "heartbeat" {
				hint = "its heartbeats"
			}
			add(s, hint, flowCol, compose.Node{Role: s})
		}
		add("sinks", "what the sinks got", sinksCol, compose.Node{})
	}
	if a.live.state.Log != nil {
		options = append(options, ui.Option{Name: "lw's own log", Hint: "its records alone, debug too"})
		ats = append(ats, at{own: true})
	}
	return &chooser{title: "Look at", list: ui.NewOptionListState(options), pick: func(a *app, i int) {
		t := ats[i]
		if a.view.own = t.own; t.own {
			return
		}
		a.pi, a.col, a.row, a.inspect, a.bar = t.pi, t.col, [3]int{}, false, false
		if t.n.Role != "" {
			a.choose(t.n)
		}
	}}
}

// drawView draws the live view: a rule naming its point and filters, the
// rows, and the focused row's detail beside them from 160 columns, else
// under them
func (a *app) drawView(r ui.Region) {
	v, th := &a.view, a.th
	v.settle()
	at := v.built.at
	title, more, dimmed, rest := at.name, "", "", ""
	switch {
	case at.own:
	case v.mode == modeAll:
		title, more = title+" · all", strings.TrimPrefix(at.all, "all")
		if at.needsDrops(modeAll) {
			dimmed = ", dropped dimmed"
		}
	default:
		title += " · " + verdicts[v.mode]
	}
	if len(a.comp.Pipelines) > 1 && at.pipe != "" {
		title = at.pipe + " · " + title
	}
	if v.floor > 0 {
		rest += " · " + core.Levels[v.floor-1].Level + " up"
	}
	if v.pat.src != "" {
		rest += " · /" + v.pat.src
	}
	hint := fmt.Sprintf("following · %d rows", len(v.shown))
	if v.paused {
		hint = fmt.Sprintf("paused · %d newer", len(v.shown)-1-v.cursor)
	}
	// The hint keeps its room, the rule padding title and hint by 8 cells: the
	// title gives up saying the dropped are dimmed, then what all holds, then
	// its end
	room, text := r.W-ui.RuneLen(hint)-8, title+more+dimmed+rest
	for _, shorter := range []string{title + more + rest, title + rest} {
		if ui.RuneLen(text) > room {
			text = shorter
		}
	}
	r.Rule(0, a.font.flat(text, room), hint, th)
	if a.viewing {
		r.TextStyled(0, 0, string(th.Glyphs.Focus), th.Accent)
	}
	list := r.Sub(0, 1, r.W, r.H-1)
	if !v.detail {
		a.drawRows(list)
		return
	}
	if r.W >= detailBeside {
		w := r.W * 62 / 100
		a.drawRows(list.Sub(0, 0, w, list.H))
		a.drawDetail(list.Sub(w+1, 0, list.W-w-1, list.H))
		return
	}
	h := list.H - list.H*2/5
	a.drawRows(list.Sub(0, 0, list.W, h))
	a.drawDetail(list.Sub(0, h, list.W, list.H-h))
}

func (a *app) drawRows(r ui.Region) {
	v := &a.view
	v.listH = r.H
	if len(v.shown) == 0 {
		r.TextStyled(2, 0, "nothing here yet", a.th.Muted)
		return
	}
	v.settle()
	v.scroll = ui.AdjustScroll(v.cursor, ui.ClampScroll(v.scroll, r.H, len(v.shown)), r.H, len(v.shown))
	tw, lw, gw := v.widths(r.W)
	first := v.rows[0].seq
	for y := 0; y < r.H && v.scroll+y < len(v.shown); y++ {
		i := v.scroll + y
		a.drawRow(r.Sub(0, y, r.W, 1), &v.rows[v.shown[i]-first], tw, lw, gw, i == v.cursor)
	}
}

// widths are a row's time, level and tag columns w wide; each drops as w
// narrows, so none overlaps the message
func (v *view) widths(w int) (tw, lw, gw int) {
	switch {
	case w >= 60:
		tw = 12
	case w >= 40:
		tw = 8
	}
	switch {
	case w >= 100:
		lw = 5
	case w >= 24:
		lw = 1
	}
	if w >= 50 {
		gw = max(6, min(16, v.tagW))
	}
	return tw, lw, gw
}

// drawRow draws a row: the cursor's pointer, its time, level and tag, then
// its message and, muted, its fields; all muted when the flow dropped it and
// the view shows all. On the cursor row each role keeps its color on the
// bar, but for a reverse bar, which ui.Style.On draws in one style.
func (a *app) drawRow(r ui.Region, w *row, tw, lw, gw int, cursor bool) {
	th, f := a.th, a.font
	dim := a.view.mode == modeAll && w.dropped()
	on := func(s ui.Style) ui.Style {
		if dim {
			s = th.Muted
		}
		if cursor {
			s = s.On(th.Selected)
		}
		return s
	}
	if cursor {
		r.FillStyle(th.Text.On(th.Selected))
		r.TextStyled(0, 0, string(th.Glyphs.Pointer), th.Accent.On(th.Selected))
	}
	if w.mark != "" {
		dash := "─"
		if f.ascii {
			dash = "-"
		}
		text := dash + dash + " " + w.mark + " "
		r.TextStyled(2, 0, text+strings.Repeat(dash, max(0, r.W-2-ui.RuneLen(text))), on(th.Border))
		return
	}
	x := 1
	if tw > 0 {
		r.TextStyled(x, 0, w.at.Local().Format("15:04:05.000")[:tw], on(th.Muted))
		x += tw + 1
	}
	if lw > 0 {
		style, ok := a.look.Levels[w.Level]
		if !ok {
			style = th.Text
		}
		r.TextStyled(x, 0, f.flat(w.Level, lw), on(style))
		x += lw + 1
	}
	if gw > 0 {
		r.TextStyled(x, 0, f.flat(w.Tag, gw), on(a.look.Source))
		x += gw + 1
	}
	msg := f.flat(w.Message, r.W-x)
	r.TextStyled(x, 0, msg, on(th.Text))
	if x += ui.RuneLen(msg) + 2; x < r.W {
		r.TextStyled(x, 0, f.flat(w.fields, r.W-x), on(th.Muted))
	}
}

// dline is a line of the detail: a key, muted, beside its text
type dline struct {
	key, text string
	style     ui.Style
}

// drawDetail draws the focused entry whole, scrolled by J and K
func (a *app) drawDetail(r ui.Region) {
	v := &a.view
	w := v.focusedEntry()
	hint := "J K scroll"
	switch {
	case w != nil && w.dropped():
		hint = "i full screen  e edit its stage  " + hint
	case w != nil:
		hint = "i full screen  " + hint
	}
	r.Rule(0, "detail", hint, a.th)
	if w != nil {
		v.dscroll = a.drawLines(r.Sub(0, 1, r.W, r.H-1), a.details(w, r.W-2), v.dscroll)
	}
}

// drawLines draws detail lines from top, kept in range, which it returns
func (a *app) drawLines(r ui.Region, lines []dline, top int) int {
	top = max(0, min(top, len(lines)-r.H))
	for y := 0; y < r.H && top+y < len(lines); y++ {
		l := lines[top+y]
		r.TextStyled(1, y, l.key, a.th.Muted)
		r.TextStyled(2+ui.RuneLen(l.key), y, l.text, l.style)
	}
	return top
}

// details are a row's detail lines w wide: its time, level, origin and
// flow, the layout logline found, its message and fields, then its payload
// as the sinks receive it; what a cell cannot show is an escape
func (a *app) details(w *row, width int) []dline {
	th := a.th
	var out []dline
	put := func(key string, keyW int, value string, style ui.Style) {
		for i, s := range ui.WrapText(escape(value), max(1, width-keyW-1)) {
			if i > 0 {
				key = ""
			}
			out = append(out, dline{ui.PadRight(ui.Truncate(escape(key), keyW), keyW), s, style})
		}
	}
	put("time", 8, w.at.Local().Format("2006-01-02 15:04:05.000 MST"), th.Text)
	if w.Stamp != "" {
		put("written", 8, w.Stamp, th.Muted)
	}
	put("level", 8, w.Level, th.Text)
	put("from", 8, a.origin(w), th.Text)
	if w.pipe != "" {
		put("flow", 8, a.verdict(w), th.Text)
	}
	put("layout", 8, w.Layout, th.Muted)
	put("message", 8, w.Message, th.Text)
	keyW := 8
	for _, f := range w.Fields {
		keyW = max(keyW, ui.RuneLen(f.Key))
	}
	for _, f := range w.Fields {
		put(f.Key, min(keyW, width/3), f.Value, th.Text)
	}
	if w.payload != nil {
		out = append(out, dline{text: "as sinks receive it", style: th.Accent})
		put("", 0, strings.TrimSuffix(string(w.payload), "\n"), th.Text)
	}
	return out
}

// origin names where a row came from: lw's own log, or a pipeline's
// heartbeat or source, by the type it has now and its id when that is
// another, then the tag the line names when it is not the source's id
func (a *app) origin(w *row) string {
	switch {
	case w.pipe == "":
		return "lw's own log"
	case w.source == "":
		return "pipeline " + w.pipe + " · heartbeat"
	}
	from := "source " + w.source
	if pi := a.pipeIndex(w.pipe); pi >= 0 {
		for _, s := range a.comp.Pipelines[pi].PluginSources {
			switch {
			case s.ID != w.source:
			case s.ID == s.Type:
				from = s.Type + " source"
			default:
				from = s.Type + " source " + s.ID
			}
		}
	}
	if w.Tag != "" && w.Tag != w.source {
		from += " · " + w.Tag
	}
	return "pipeline " + w.pipe + " · " + from
}

// verdict says what the flow did with a row: passed, or the stage, and for a
// filter the patterns it has now, that dropped it
func (a *app) verdict(w *row) string {
	switch w.stage {
	case "":
		return "passed every stage"
	case "filters":
		text := fmt.Sprintf("dropped by filter %d", w.index+1)
		if pi := a.pipeIndex(w.pipe); pi >= 0 {
			if fs := a.comp.Pipelines[pi].Flow.Filters; w.index < len(fs) {
				text += " (" + string(fs[w.index].Type) + " " + strings.Join(fs[w.index].Patterns, " | ") + ")"
			}
		}
		return text
	}
	return "dropped by " + w.stage
}

// oneCell reports whether a cell shows the rune r, decoded from size bytes,
// as itself: not one a terminal acts on (logline.Control), and one taking a
// column of its own
func oneCell(r rune, size int) bool {
	if r >= ' ' && r < 0x7f {
		return true
	}
	return !logline.Control(r, size) && !unicode.In(r, unicode.Cc, unicode.Cf, unicode.Mn, unicode.Me, unicode.Mc, wideOrJoining)
}

// flat is s on one row of at most w cells: a line break as the font's mark,
// a tab as a space, what a cell cannot show as the font's placeholder, and
// '…' where it is cut
func (f font) flat(s string, w int) string {
	if w <= 0 {
		return ""
	}
	out := make([]rune, 0, min(w, len(s)))
	i := 0
	for i < len(s) && len(out) < w {
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		switch {
		case r == '\n':
			r = f.newline
		case r == '\t':
			r = ' '
		case !oneCell(r, n):
			r = f.odd
		}
		out = append(out, r)
	}
	if i < len(s) && w > 1 {
		out[w-1] = '…'
	}
	return string(out)
}

// escape writes each rune a cell cannot show as a \u escape and each invalid
// byte as a \x one; line breaks stay, for the detail to keep them
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '\n' || oneCell(r, n):
			b.WriteString(s[i : i+n])
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r > 0xffff:
			fmt.Fprintf(&b, `\U%08X`, r)
		default:
			fmt.Fprintf(&b, `\u%04X`, r)
		}
		i += n
	}
	return b.String()
}

// pattern is a smart-case match: all lower case ignores case. Without
// regexp metacharacters an ASCII pattern is a substring, found without
// allocating; any other is RE2.
type pattern struct {
	src, lit string
	fold     bool
	re       *regexp.Regexp
}

func newPattern(s string) (pattern, error) {
	p := pattern{src: s, lit: s, fold: s == strings.ToLower(s)}
	if regexp.QuoteMeta(s) == s && !strings.ContainsFunc(s, func(r rune) bool { return r > unicode.MaxASCII }) {
		return p, nil
	}
	expr := s
	if p.fold {
		expr = "(?i)" + s
	}
	re, err := regexp.Compile(expr)
	p.re = re
	return p, err
}

func (p pattern) match(s string) bool {
	switch {
	case p.re != nil:
		return p.re.MatchString(s)
	case p.fold:
		return foldContains(s, p.lit)
	}
	return strings.Contains(s, p.lit)
}

// foldContains reports whether s holds the lower-case ASCII needle, in any
// case
func foldContains(s, needle string) bool {
	for i := 0; i+len(needle) <= len(s); i++ {
		j := 0
		for j < len(needle) && lower(s[i+j]) == needle[j] {
			j++
		}
		if j == len(needle) {
			return true
		}
	}
	return false
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// wideOrJoining is what a terminal draws in two columns, East Asian wide and
// fullwidth and emoji presentation as of Unicode 17, and the letters a
// grapheme cluster joins to a neighbour (Hangul jamo, Prepend, SpacingMark and
// Extend ones); a range spans the unassigned code points between its runes
var wideOrJoining = &unicode.RangeTable{
	R16: []unicode.Range16{
		{0x0D4E, 0x0D4E, 1}, {0x0E33, 0x0E33, 1}, {0x0EB3, 0x0EB3, 1},
		{0x1100, 0x11FF, 1}, {0x231A, 0x231B, 1}, {0x2329, 0x232A, 1}, {0x23E9, 0x23EC, 1},
		{0x23F0, 0x23F0, 1}, {0x23F3, 0x23F3, 1}, {0x25FD, 0x25FE, 1}, {0x2614, 0x2615, 1},
		{0x2630, 0x2637, 1}, {0x2648, 0x2653, 1}, {0x267F, 0x267F, 1}, {0x268A, 0x268F, 1},
		{0x2693, 0x2693, 1}, {0x26A1, 0x26A1, 1}, {0x26AA, 0x26AB, 1}, {0x26BD, 0x26BE, 1},
		{0x26C4, 0x26C5, 1}, {0x26CE, 0x26CE, 1}, {0x26D4, 0x26D4, 1}, {0x26EA, 0x26EA, 1},
		{0x26F2, 0x26F3, 1}, {0x26F5, 0x26F5, 1}, {0x26FA, 0x26FA, 1}, {0x26FD, 0x26FD, 1},
		{0x2705, 0x2705, 1}, {0x270A, 0x270B, 1}, {0x2728, 0x2728, 1}, {0x274C, 0x274C, 1},
		{0x274E, 0x274E, 1}, {0x2753, 0x2755, 1}, {0x2757, 0x2757, 1}, {0x2795, 0x2797, 1},
		{0x27B0, 0x27B0, 1}, {0x27BF, 0x27BF, 1}, {0x2B1B, 0x2B1C, 1}, {0x2B50, 0x2B50, 1},
		{0x2B55, 0x2B55, 1}, {0x2E80, 0x303E, 1}, {0x3041, 0x3247, 1}, {0x3250, 0xA4C6, 1},
		{0xA960, 0xA97C, 1}, {0xAC00, 0xD7FF, 1}, {0xF900, 0xFAFF, 1}, {0xFE10, 0xFE19, 1},
		{0xFE30, 0xFE6B, 1}, {0xFF01, 0xFF60, 1}, {0xFF9E, 0xFF9F, 1}, {0xFFE0, 0xFFE6, 1},
	},
	R32: []unicode.Range32{
		{0x111C2, 0x111C3, 1}, {0x113D1, 0x113D1, 1}, {0x1193F, 0x1193F, 1}, {0x11941, 0x11941, 1},
		{0x11A84, 0x11A89, 1}, {0x11D46, 0x11D46, 1}, {0x11F02, 0x11F02, 1},
		{0x16FE0, 0x1B2FB, 1}, {0x1D300, 0x1D376, 1}, {0x1F004, 0x1F004, 1}, {0x1F0CF, 0x1F0CF, 1},
		{0x1F18E, 0x1F18E, 1}, {0x1F191, 0x1F19A, 1}, {0x1F1E6, 0x1F320, 1}, {0x1F32D, 0x1F335, 1},
		{0x1F337, 0x1F37C, 1}, {0x1F37E, 0x1F393, 1}, {0x1F3A0, 0x1F3CA, 1}, {0x1F3CF, 0x1F3D3, 1},
		{0x1F3E0, 0x1F3F0, 1}, {0x1F3F4, 0x1F3F4, 1}, {0x1F3F8, 0x1F43E, 1}, {0x1F440, 0x1F440, 1},
		{0x1F442, 0x1F4FC, 1}, {0x1F4FF, 0x1F53D, 1}, {0x1F54B, 0x1F54E, 1}, {0x1F550, 0x1F567, 1},
		{0x1F57A, 0x1F57A, 1}, {0x1F595, 0x1F596, 1}, {0x1F5A4, 0x1F5A4, 1}, {0x1F5FB, 0x1F64F, 1},
		{0x1F680, 0x1F6C5, 1}, {0x1F6CC, 0x1F6CC, 1}, {0x1F6D0, 0x1F6D2, 1}, {0x1F6D5, 0x1F6DF, 1},
		{0x1F6EB, 0x1F6EC, 1}, {0x1F6F4, 0x1F6FC, 1}, {0x1F7E0, 0x1F7F0, 1}, {0x1F90C, 0x1F93A, 1},
		{0x1F93C, 0x1F945, 1}, {0x1F947, 0x1F9FF, 1}, {0x1FA70, 0x1FAF8, 1}, {0x20000, 0x3FFFF, 1},
	},
}
