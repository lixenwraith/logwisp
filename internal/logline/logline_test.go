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
// are their writers' output; the others follow their formats' documentation.
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
		// nesting past nestMax stays one value, bounding the paths
		{arrived(`{"msg":"deep","a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":1}}}}}}}}}}`),
			`json, message in msg | =- |  | app.log | "deep" | a.b.c.d.e.f.g.h.i="{\"j\":1}"`},
		{arrived(`2026-10-10T12:00:00+02:00 ERROR db: connection refused`),
			`text, stamped | 2026-10-10T12:00:00+02:00=2026-10-10T10:00:00Z | ERROR | app.log | "ERROR db: connection refused" | `},
		{arrived(`2026-10-10T12:00:00.5 INFO a stamp without a zone is UTC`),
			`text, stamped | 2026-10-10T12:00:00.5=2026-10-10T12:00:00.5Z | INFO | app.log | "INFO a stamp without a zone is UTC" | `},
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
