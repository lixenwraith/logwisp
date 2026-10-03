#!/usr/bin/env bash
# logwisp file pass-through test: a file source relays a record whose envelope
# is wider than time/level/msg/fields byte for byte (raw = true) and, parsed,
# with no key dropped. One-shot: both modes run the checks; no ports.
# Requires: bash 5+, coreutils (timeout). Linux dev host only.

set -u
. "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

RUN=$E2E_DIR/run/passthrough
e2e_init "$@"

section "Setup"
need
rm -rf "$RUN"
mkdir -p "$RUN/in" "$RUN/out-raw" "$RUN/out-parsed" "$CONF" "$LOG"

cat >"$RUN/in/wide.jsonl" <<'EOF'
{"time":"2026-09-08T21:35:44.178372768-04:00","level":"INFO","sub":"app","run":0,"tick":0,"frame":0,"fields":{"msg":"init begin","mode":"play"}}
{"time":"2026-09-08T21:35:44.178581366-04:00","level":"PROC","run":0,"tick":0,"frame":0,"fields":{"seq":1,"seed":1788917744178374836}}
plain text line, not JSON at all
EOF

conf() { # sink_dir raw
	cat <<EOF
quiet = true
status_reporter = false
[logging]
output = "stderr"
level = "error"
[[pipelines]]
name = "passthrough"
[pipelines.flow.format]
type = "raw"
sanitizer_policy = "raw"
[[pipelines.plugin_sources]]
id = "wide"
type = "file"
[pipelines.plugin_sources.config]
directory = "$RUN/in"
pattern = "*.jsonl"
raw = $2
from = "start"
[[pipelines.plugin_sinks]]
id = "out"
type = "file"
[pipelines.plugin_sinks.config]
directory = "$1"
name = "relay"
flush_interval_ms = 100
EOF
}
conf "$RUN/out-raw" true >"$CONF/raw.toml"
conf "$RUN/out-parsed" false >"$CONF/parsed.toml"
info "fixture $(short "$RUN/in/wide.jsonl"), configurations in $(short "$CONF")/"

section "Relay"
for c in raw parsed; do
	info "lw -c $(short "$CONF/$c.toml"), 5 s"
	timeout 5 "$BIN" -c "$CONF/$c.toml" >"$LOG/$c.out" 2>&1
done

section "Checks"
# 1. raw = true relays the file byte for byte
if diff -q "$RUN/in/wide.jsonl" "$RUN/out-raw/relay.log" >/dev/null; then
	check "raw = true: output identical to input" 1
else
	check "raw = true: output identical to input" 0
	diff "$RUN/in/wide.jsonl" "$RUN/out-raw/relay.log" | head -6 | sed 's/^/        /'
fi

# 2. the default parse keeps every key, JSON branch refused on the wide envelope
n=$(grep -c '"sub":"app"' "$RUN/out-parsed/relay.log")
check "defaults: wide envelope reaches the sink whole ($n line(s) carry sub)" $((n == 1))
n=$(grep -c '1788917744178374836' "$RUN/out-parsed/relay.log")
check "defaults: large integers are not re-encoded through float64 ($n)" $((n == 1))

summary
