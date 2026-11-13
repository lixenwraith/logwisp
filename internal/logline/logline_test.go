package logline

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/core"
)

// arrived is a line as a source passes one it does not parse: whole, at its
// arrival, with the level its first level word names
func arrived(line string) core.LogEntry {
	level, _, _ := core.LevelWord(line, "")
	return core.LogEntry{Time: time.Unix(1, 0), Source: "app.log", Level: level, Message: line}
}

// Each writer's line yields its time, level, tag and message from where that
// writer puts them, the rest as fields in its order; the want is "layout |
// stamp=time | level | tag | message | fields". vif's, lw's and slog's lines
// are their writers' output (lw's key=value line as its log library writes one
// with FlagKV); the others follow their formats' documentation.
func TestReadFindsTheRolesWhereTheirWriterPutsThem(t *testing.T) {
	for _, c := range []struct {
		in   core.LogEntry
		want string
	}{
		// vif: the tag is sub, the message the first of fields.msg, type and ev
		{arrived(`{"time":"2026-10-10T19:09:54.251623265Z","level":"INFO","sub":"fsm","run":3,"tick":1200,"fields":{"msg":"transition","from":"idle","to":"run","elapsed":1500000}}`),
			`json, message in fields.msg | 2026-10-10T19:09:54.251623265Z=2026-10-10T19:09:54.251623265Z | INFO | fsm | "transition" | run="3" tick="1200" from="idle" to="run" elapsed="1500000"`},
		{arrived(`{"time":"2026-10-10T19:09:54.251635197Z","level":"WARN","sub":"fsm","run":3,"tick":1200,"trace":"main -> main","fields":{"msg":"slow tick","ms":73.25}}`),
			`json, message in fields.msg | 2026-10-10T19:09:54.251635197Z=2026-10-10T19:09:54.251635197Z | WARN | fsm | "slow tick" | run="3" tick="1200" trace="main -> main" ms="73.25"`},
		{arrived(`{"time":"2026-10-10T19:09:54.251635488Z","level":"INFO","sub":"journal","run":0,"tick":0,"fields":{"jseq":7,"domain":"player","ev":"EventX","payload":"x = 1\ny = 2\n"}}`),
			`json, message in fields.ev | 2026-10-10T19:09:54.251635488Z=2026-10-10T19:09:54.251635488Z | INFO | journal | "EventX" | run="0" tick="0" jseq="7" domain="player" payload="x = 1\ny = 2\n"`},
		{arrived(`{"time":"2026-08-29T21:15:23.33805528-04:00","level":"PROC","run":0,"tick":0,"frame":0,"fields":{"type":"proc","sequence":1,"processed_logs":0}}`),
			`json, message in fields.type | 2026-08-29T21:15:23.33805528-04:00=2026-08-30T01:15:23.33805528Z | PROC | app.log | "proc" | run="0" tick="0" frame="0" sequence="1" processed_logs="0"`},
		{arrived(`{"time":"2026-08-30T01:27:39.654615818Z","level":"INFO","sub":"anchor","run":0,"tick":0,"frame":0,"fields":{"schema":10,"jseq":0,"tick_ns":50000000}}`),
			`json, no message | 2026-08-30T01:27:39.654615818Z=2026-08-30T01:27:39.654615818Z | INFO | anchor | "" | run="0" tick="0" frame="0" schema="10" jseq="0" tick_ns="50000000"`},
		// LogWisp json: trace is the source, the message alone is fields[0], and a
		// record the console source read whole sits there, over the outer roles
		{arrived(`{"time":"2026-10-10T12:00:00Z","level":"WARN","trace":"app.log","message":"disk almost full","fields":{"disk":"/dev/sda1","nested":{"a":[1,2]},"pct":91}}`),
			`json, message in message | 2026-10-10T12:00:00Z=2026-10-10T12:00:00Z | WARN | app.log | "disk almost full" | disk="/dev/sda1" nested.a="[1,2]" pct="91"`},
		{arrived(`{"time":"2026-10-10T20:30:12.385839584Z","level":"INFO","trace":"app.log","fields":["TRACE deep detail"]}`),
			`json, message in fields[0] | 2026-10-10T20:30:12.385839584Z=2026-10-10T20:30:12.385839584Z | INFO | app.log | "TRACE deep detail" | `},
		{arrived(`{"time":"2026-10-10T20:43:03.350727184Z","level":"INFO","trace":"console","fields":["{\"time\":\"2026-10-10T12:00:00Z\",\"msg\":\"disk almost full\",\"fields\":{\"disk\":\"/dev/sda1\"}}"]}`),
			`json in fields[0], message in msg | 2026-10-10T12:00:00Z=2026-10-10T12:00:00Z | INFO | console | "disk almost full" | disk="/dev/sda1"`},
		{arrived(`{"time":"2026-10-10T20:43:38.342629146Z","level":"INFO","trace":"console","fields":["{\"msg\":\"no time here\",\"fields\":{\"k\":1}}"]}`),
			`json in fields[0], message in msg | 2026-10-10T20:43:38.342629146Z=2026-10-10T20:43:38.342629146Z | INFO | console | "no time here" | k="1"`},
		{arrived(`{"time":"2026-10-10T19:06:34.86389785Z","node":"edge-01","source":"app.log","level":"WARN","message":"disk almost full","fields":{"pct":91}}`),
			`json, message in message | 2026-10-10T19:06:34.86389785Z=2026-10-10T19:06:34.86389785Z | WARN | app.log | "disk almost full" | node="edge-01" pct="91"`},
		// lw's own log: key/value pairs, in the line or in what the file source kept
		{arrived(`{"time":"2026-10-10T20:29:33.279610845Z","level":"INFO","fields":["msg","Initializing pipeline","pipeline","cli"]}`),
			`json, message in fields[1] | 2026-10-10T20:29:33.279610845Z=2026-10-10T20:29:33.279610845Z | INFO | app.log | "Initializing pipeline" | pipeline="cli"`},
		{core.LogEntry{Source: "lw.log", Level: "INFO", Fields: json.RawMessage(`["msg","LogWisp starting","status_reporter",false]`)},
			`entry, message in fields[1] | =- | INFO | lw.log | "LogWisp starting" | status_reporter="false"`},
		{core.LogEntry{Source: "app.log", Level: "warning", Message: "disk almost full", Fields: json.RawMessage(`{"pct":91}`)},
			`text | =- | WARN | app.log | "disk almost full" | pct="91"`},
		// pino's tens, zap's seconds, slog's scale and groups
		{arrived(`{"level":30,"time":1728561600000,"pid":1,"hostname":"h","msg":"pino style"}`),
			`json, message in msg | 1728561600000=2024-10-10T12:00:00Z | INFO | app.log | "pino style" | pid="1" hostname="h"`},
		{arrived(`{"level":"info","ts":1728561600.123456,"caller":"main.go:12","msg":"zap style","n":1}`),
			`json, message in msg | 1728561600.123456=2024-10-10T12:00:00.123456Z | INFO | app.log | "zap style" | caller="main.go:12" n="1"`},
		{arrived(`{"time":"2026-10-10T20:30:23.451515887Z","level":"INFO","msg":"slog style","user":{"id":7,"name":"a"}}`),
			`json, message in msg | 2026-10-10T20:30:23.451515887Z=2026-10-10T20:30:23.451515887Z | INFO | app.log | "slog style" | user.id="7" user.name="a"`},
		{arrived(`{"time":"2026-10-10T20:39:59.809016667Z","level":-4,"msg":"slog level as a number","attempt":2}`),
			`json, message in msg | 2026-10-10T20:39:59.809016667Z=2026-10-10T20:39:59.809016667Z | DEBUG | app.log | "slog level as a number" | attempt="2"`},
		// logfmt, slog's text handler and go-kit's: key=value pairs, a value
		// quoted as Go quotes it
		{arrived(`time=2026-10-11T05:23:21.410Z level=WARN msg="disk almost full" pct=91 disk.dev=/dev/sda1 err="open \"x\": denied"`),
			`logfmt, message in msg | 2026-10-11T05:23:21.410Z=2026-10-11T05:23:21.41Z | WARN | app.log | "disk almost full" | pct="91" disk.dev="/dev/sda1" err="open \"x\": denied"`},
		{arrived(`level=info ts=2026-10-10T12:00:00.000Z caller=main.go:12 listen=:8080`),
			`logfmt, no message | 2026-10-10T12:00:00.000Z=2026-10-10T12:00:00Z | INFO | app.log | "" | caller="main.go:12" listen=":8080"`},
		// lw's own log as text: the level word after the stamp is the level, taken
		// off the message (the entry names none here); its pairs, once key=value,
		// are a record's
		{core.LogEntry{Source: "lw", Message: `2026-10-11T05:23:20.28585127Z INFO msg "Waiting for directory" component file_source instance_id file directory /home/me/.local/state/vif/log`},
			`text, stamped, level word | 2026-10-11T05:23:20.28585127Z=2026-10-11T05:23:20.28585127Z | INFO | lw | "msg \"Waiting for directory\" component file_source instance_id file directory /home/me/.local/state/vif/log" | `},
		{arrived(`2026-10-11T05:19:17.289770496Z INFO msg="Waiting for directory" component=file_source instance_id=file directory=/home/me/.local/state/vif/log`),
			`logfmt, stamped, level word, message in msg | 2026-10-11T05:19:17.289770496Z=2026-10-11T05:19:17.289770496Z | INFO | file_source | "Waiting for directory" | instance_id="file" directory="/home/me/.local/state/vif/log"`},
		// the line's start keeps its stamp and level word; pairs naming them are fields
		{arrived(`2026-10-11T05:00:00Z WARN msg="request done" t=3 level=debug`),
			`logfmt, stamped, level word, message in msg | 2026-10-11T05:00:00Z=2026-10-11T05:00:00Z | WARN | app.log | "request done" | t="3" level="debug"`},
		// an '=' in text is text: pairs alone, a level or message among them, count
		{arrived(`x=1 y=2 note="no level or message key"`),
			`text | =- |  | app.log | "x=1 y=2 note=\"no level or message key\"" | `},
		{arrived(`msg=not only pairs`),
			`text | =- |  | app.log | "msg=not only pairs" | `},
		{arrived(`level=INFO msg="clipped at an escape\`),
			`text | =- | INFO | app.log | "level=INFO msg=\"clipped at an escape\\" | `},
		{arrived(`2026-10-10T12:00:00Z DEBUG cache hit ratio=0.93`),
			`text, stamped, level word | 2026-10-10T12:00:00Z=2026-10-10T12:00:00Z | DEBUG | app.log | "cache hit ratio=0.93" | `},
		// docker's log ends in its newline; the level is the entry's
		{arrived(`{"log":"docker line ERROR x\n","stream":"stderr","time":"2026-10-10T12:00:00.1Z"}`),
			`json, message in log | 2026-10-10T12:00:00.1Z=2026-10-10T12:00:00.1Z | ERROR | app.log | "docker line ERROR x" | stream="stderr"`},
		// journald writes numbers as strings: microseconds, syslog priority
		{arrived(`{"__REALTIME_TIMESTAMP":"1728561600123456","PRIORITY":"3","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"journald"}`),
			`json, message in MESSAGE | 1728561600123456=2024-10-10T12:00:00.123456Z | ERROR | nginx.service | "journald" | `},
		{arrived(`{"@timestamp":"2026-10-10T12:00:00Z","log.level":"warn","message":"ecs flat"}`),
			`json, message in message | 2026-10-10T12:00:00Z=2026-10-10T12:00:00Z | WARN | app.log | "ecs flat" | `},
		{arrived(`{"@timestamp":"2026-10-10T12:00:00Z","log":{"level":"error"},"message":"ecs nested"}`),
			`json, message in message | 2026-10-10T12:00:00Z=2026-10-10T12:00:00Z | ERROR | app.log | "ecs nested" | `},
		{arrived(`{"severity":"CRITICAL","timestamp":"2026-10-10T12:00:00Z","message":"gcp"}`),
			`json, message in message | 2026-10-10T12:00:00Z=2026-10-10T12:00:00Z | ERROR | app.log | "gcp" | `},
		{arrived(`{"a":1,"b":"no known keys","source":null}`),
			`json, no message | =- |  | app.log | "" | a="1" b="no known keys" source="null"`},
		// a line the tap clipped keeps the roles before the cut
		{arrived(`{"time":"2026-10-10T12:00:00Z","level":"INFO","msg":"clipped","big":"aaaa`),
			`json, cut short, message in msg | 2026-10-10T12:00:00Z=2026-10-10T12:00:00Z | INFO | app.log | "clipped" | `},
		// nesting past nestMax, or under a key past pathMax, stays one value,
		// bounding the paths
		{arrived(`{"msg":"deep","a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":1}}}}}}}}}}`),
			`json, message in msg | =- |  | app.log | "deep" | a.b.c.d.e.f.g.h.i="{\"j\":1}"`},
		{arrived(`{"msg":"long","` + strings.Repeat("k", 65) + `":{"b":1}}`),
			`json, message in msg | =- |  | app.log | "long" | ` + strings.Repeat("k", 65) + `="{\"b\":1}"`},
		{arrived(`2026-10-10T12:00:00+02:00 ERROR db: connection refused`),
			`text, stamped, level word | 2026-10-10T12:00:00+02:00=2026-10-10T10:00:00Z | ERROR | app.log | "db: connection refused" | `},
		{arrived(`2026-10-10T12:00:00.5 a stamp without a zone is UTC`),
			`text, stamped | 2026-10-10T12:00:00.5=2026-10-10T12:00:00.5Z |  | app.log | "a stamp without a zone is UTC" | `},
		// a level word is a whole word: one in brackets stays in the message
		{arrived(`2026-10-10T12:00:00Z [WARN] disk almost full`),
			`text, stamped | 2026-10-10T12:00:00Z=2026-10-10T12:00:00Z | WARN | app.log | "[WARN] disk almost full" | `},
		// what only looks like a stamp is text: no day is invented
		{arrived(`2026-13-45T99:99:99Z ERROR x`),
			`text | =- | ERROR | app.log | "2026-13-45T99:99:99Z ERROR x" | `},
		{arrived(`2026-10-10T12:00:00Zjunk ERROR x`),
			`text | =- | ERROR | app.log | "2026-10-10T12:00:00Zjunk ERROR x" | `},
		{arrived(`{not json} WARNING disk`),
			`text | =- | WARN | app.log | "{not json} WARNING disk" | `},
	} {
		if got := show(Read(c.in)); got != c.want {
			t.Errorf("%s\n got: %s\nwant: %s", c.in.Message, got, c.want)
		}
	}
}

func show(l Line) string {
	at := "-"
	if !l.Time.IsZero() {
		at = l.Time.UTC().Format(time.RFC3339Nano)
	}
	var fs []string
	for _, f := range l.Fields {
		fs = append(fs, fmt.Sprintf("%s=%q", f.Key, f.Value))
	}
	return fmt.Sprintf("%s | %s=%s | %s | %s | %q | %s", l.Layout, l.Stamp, at, l.Level, l.Tag, l.Message, strings.Join(fs, " "))
}

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
		if got := string(EscapeControls([]byte(in))); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// marked writes each mark as its kind's letter (T time, L:level, G tag, K key,
// P punctuation) around the text it covers
func marked(s string, e core.LogEntry) string {
	var b strings.Builder
	at := 0
	Marks(s, e, func(m Mark) {
		b.WriteString(s[at:m.Start])
		kind := string(" TLGKP"[m.Kind])
		if m.Kind == MarkLevel {
			kind += ":" + m.Level
		}
		fmt.Fprintf(&b, "%s(%s)", kind, s[m.Start:m.End])
		at = m.End
	})
	return b.String() + s[at:]
}

// Each role is marked where the line writes it: the stamp and level word it
// starts with, then the source label as txt writes it or syslog's host and
// program, else the first word naming the entry's level; keys, punctuation and
// the time, level and tag values of a JSON object or key=value pairs.
func TestMarksNameEachRoleWhereTheLineWritesIt(t *testing.T) {
	for _, c := range []struct {
		in    string
		entry core.LogEntry
		want  string
	}{
		// txt: stamp, level, label; pairs in the quoted message, its first too
		{`2026-11-05T07:51:43.123Z INFO console "server started addr=0.0.0.0:8080 n=4"`, core.LogEntry{Level: "info", Source: "console"},
			`T(2026-11-05T07:51:43.123Z) L:INFO(INFO) G(console) "server started K(addr)P(=)0.0.0.0:8080 K(n)P(=)4"`},
		{`2026-11-05 07:51:44,001 WARN edge-01/app "time=07:51:44 level=warn msg=\"slow\""`, core.LogEntry{Level: "WARN", Node: "edge-01", Source: "app"},
			`T(2026-11-05 07:51:44,001) L:WARN(WARN) G(edge-01/app) "K(time)P(=)T(07:51:44) K(level)P(=)L:WARN(warn) K(msg)P(=)\"slow\""`},
		{`Nov  5 07:51:45 edge-01 sshd[2211]: error: auth failed`, core.LogEntry{Level: "ERROR", Source: "messages"},
			`T(Nov  5 07:51:45) G(edge-01 sshd[2211]): L:ERROR(error): auth failed`},
		// JSON: a level value reads as its writer's scale; nested keys name no role
		{`{"level":30,"ts":1762329103.88,"msg":"a","n":[1,{"logger":"x"}],"logger":"db"}`, core.LogEntry{Level: "INFO"},
			`P({)K("level")P(:)L:INFO(30)P(,)K("ts")P(:)T(1762329103.88)P(,)K("msg")P(:)"a"P(,)K("n")P(:)P([)1P(,)P({)K("logger")P(:)"x"P(})P(])P(,)K("logger")P(:)G("db")P(})`},
		// LogWisp json writes TRACE as INFO: the line's level is marked, not the trace key
		{`{"time":"2026-11-05T07:51:43Z","level":"INFO","trace":"console","fields":["TRACE x"]}`, core.LogEntry{Level: "TRACE", Source: "console"},
			`P({)K("time")P(:)T("2026-11-05T07:51:43Z")P(,)K("level")P(:)L:INFO("INFO")P(,)K("trace")P(:)G("console")P(,)K("fields")P(:)P([)"TRACE x"P(])P(})`},
		// without a level at its start, the first whole word naming the entry's
		{`[warning] disk`, core.LogEntry{Level: "WARN"}, `[L:WARN(warning)] disk`},
		{`INFO: WARN disk`, core.LogEntry{Level: "warning"}, `INFO: L:WARN(WARN) disk`},
		{`2026 ERROR boom ERROR`, core.LogEntry{Level: "ERROR"}, `2026 L:ERROR(ERROR) boom ERROR`},
		{`terror_x code=ERR:1`, core.LogEntry{Level: "ERROR"}, `terror_x K(code)P(=)L:ERROR(ERR):1`},
		{`INFOS informal`, core.LogEntry{Level: "INFO"}, `INFOS informal`},
		{`boom ERROR, entry without level`, core.LogEntry{}, `boom ERROR, entry without level`},
		// braces that are no JSON are text; a JSON object after text is marked
		{`2026/11/05 07:51:48 DEBUG Foo { a: 1 } done {"id":7}`, core.LogEntry{Level: "DEBUG"},
			`T(2026/11/05 07:51:48) L:DEBUG(DEBUG) Foo { a: 1 } done P({)K("id")P(:)7P(})`},
		// the label follows a stamp or level; a stamp is a word of its own
		{`[2026-11-05 07:51:44] app ready`, core.LogEntry{Source: "app"}, `T([2026-11-05 07:51:44]) G(app) ready`},
		{`app ready`, core.LogEntry{Source: "app"}, `app ready`},
		{`12:30 lunch x=1`, core.LogEntry{}, `12:30 lunch K(x)P(=)1`},
		{`2026-11-05T07:51:43Zjunk x`, core.LogEntry{}, `2026-11-05T07:51:43Zjunk x`},
	} {
		if got := marked(c.in, c.entry); got != c.want {
			t.Errorf("%s\n got: %s\nwant: %s", c.in, got, c.want)
		}
	}
}

// Marks of any line, its level any word, are in order, apart and in bounds,
// and come to an end: a line unescaped may hold control bytes
func FuzzMarksStayInOrderWithinTheLine(f *testing.F) {
	f.Add(`2026-11-05 07:51:44,001 WARN edge-01/app "time=07:51:44 level=warn msg=\"slow\""`, "WARN")
	f.Add("a \x01b \x1b[31mERROR\x1b[0m \x00", "ERROR")
	f.Add(`Nov  5 07:51:45 edge-01 sshd[2211]: error: auth failed`, "ERROR")
	f.Add(`{"level":30,"ts":1.5,"n":[1,{"k":"x"}],"logger":"db"} tail {"a":`, "INFO")
	f.Add(`[warning] k="unterminated \"`, "warning")
	f.Add(`level="x\`, "INFO")
	f.Add(`ts="x\`, "INFO")
	f.Fuzz(func(t *testing.T, s, level string) {
		at := 0
		Marks(s, core.LogEntry{Level: level, Source: "app"}, func(m Mark) {
			if m.Start < at || m.End <= m.Start || m.End > len(s) {
				t.Fatalf("%q: mark %+v after %d", s, m, at)
			}
			at = m.End
		})
	})
}
