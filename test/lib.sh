# Shared by the e2e scripts (test/*-test.sh): sourced after the script sets RUN,
# then e2e_init parses the common flags. Daemons log to $LOG/NAME.out only.
# Exit codes: 0 every check passed, 1 a check failed, 77 the script skipped.

E2E_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BIN=${LOGWISP_BIN:-${E2E_DIR%/*}/bin/lw}
AUTO=0 KEEP=0 FOLLOW=0
PIDS=() DAEMONS=() AT_EXIT=()
E2E_PASSED=0 E2E_FAILED=0 E2E_SKIPPED=0
# What --follow shows besides WARN and ERROR lines; a script may extend it
FOLLOW_KEYS='LogWisp started|hot reload completed|Login accepted|rejected|refused'
PKI_DAYS=45 # past the 30-day expiry warning, which would fill the daemon logs

# https://no-color.org; FORCE_COLOR=1 keeps colour through a pipe
if [[ ${FORCE_COLOR:-0} != 0 ]] || [[ -t 1 && -z ${NO_COLOR:-} ]]; then
	C_BOLD=$'\e[1m' C_DIM=$'\e[2m' C_RED=$'\e[31m' C_GREEN=$'\e[32m'
	C_YELLOW=$'\e[33m' C_CYAN=$'\e[36m' C_OFF=$'\e[0m'
else
	C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_CYAN='' C_OFF=''
fi
# Rules fit a narrower terminal; wider ones keep 64 columns
COLS=${COLUMNS:-$(stty size <&2 2>/dev/null | cut -d' ' -f2)}
[[ $COLS =~ ^[0-9]+$ ]] && ((COLS >= 20 && COLS < 64)) || COLS=64

usage() {
	sed -n '2,/^[^#]/s/^# \{0,1\}//p' "$0"
	cat <<EOF

Usage: $0 [--auto [--keep]] [--follow]
  (none)    start the daemons, print the guide, keep them up until Ctrl-C
  --auto    run the checks, then stop the daemons
  --keep    with --auto: leave them up when every check passes
  --follow  show the daemons' warnings, errors and key events as they log
Daemon logs: $(short "$RUN")/log/NAME.out. NO_COLOR=1 or FORCE_COLOR=1 sets
colour; LOGWISP_BIN names another lw binary.
EOF
}

e2e_init() { # "$@" of the script
	local a
	for a; do
		case $a in
		--auto) AUTO=1 ;;
		--keep) KEEP=1 ;;
		--follow) FOLLOW=1 ;;
		-h | --help) usage; exit 0 ;;
		*) printf '%s: unknown argument %s (see --help)\n' "${0##*/}" "$a" >&2; exit 2 ;;
		esac
	done
	CONF=$RUN/conf LOG=$RUN/log
	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	trap 'exit 129' HUP
	trap 'exit 141' PIPE
	printf '%s%s%s\n' "$C_BOLD" "${0##*/}$( ((AUTO)) && echo ' --auto')" "$C_OFF"
}

# --- output ---

rule() { local s='' n=$1; while ((n-- > 0)); do s+=${2:-─}; done; printf '%s' "$s"; } # N [CHAR]
short() { if [[ $1 == "$PWD"/* ]]; then printf '%s' "${1#"$PWD"/}"; else printf '%s' "$1"; fi; }
section() { printf '\n%s── %s %s%s\n' "$C_BOLD$C_CYAN" "$1" "$(rule $((COLS - 4 - ${#1})))" "$C_OFF"; }
info() { printf '  %s·%s %s\n' "$C_DIM" "$C_OFF" "$*"; }

pass() { E2E_PASSED=$((E2E_PASSED + 1)); printf '  %sPASS%s  %s\n' "$C_BOLD$C_GREEN" "$C_OFF" "$1"; }
fail() { E2E_FAILED=$((E2E_FAILED + 1)); printf '  %sFAIL%s  %s\n' "$C_BOLD$C_RED" "$C_OFF" "$1"; }
skip() { E2E_SKIPPED=$((E2E_SKIPPED + 1)); printf '  %sSKIP%s  %s\n' "$C_BOLD$C_YELLOW" "$C_OFF" "$1"; }
check() { if (($2)); then pass "$1"; else fail "$1"; fi; } # LABEL 1|0
is() { [[ $1 == "$2" ]] && echo 1 || echo 0; }           # ACTUAL EXPECTED
is_set() { [[ -n $1 ]] && echo 1 || echo 0; }

# guide TITLE, the body on stdin, between two rules and without a side border,
# so lines wrapped by a narrow terminal stay readable: "> " lines are commands,
# "  NNNNN " lines ports, lines ending in ":" headings.
guide() {
	local line
	printf '\n%s══ %s %s%s\n' "$C_BOLD" "$1" "$(rule $((COLS - 4 - ${#1})) ═)" "$C_OFF"
	while IFS= read -r line; do
		case $line in
		'> '*) line="  $C_CYAN${line#> }$C_OFF" ;;
		'  '[0-9][0-9][0-9][0-9][0-9]' '*) line="  $C_YELLOW${line:2:5}$C_OFF${line:7}" ;;
		*:) line="$C_BOLD$line$C_OFF" ;;
		esac
		printf '%s\n' "$line"
	done
	printf '%s%s%s\n' "$C_BOLD" "$(rule "$COLS" ═)" "$C_OFF"
}

# write_env NAME=VALUE...: $RUN/env, which the guide's commands source
write_env() {
	local kv
	{
		echo "# . $(short "$RUN")/env: what the guide of ${0##*/} refers to"
		echo 'export no_proxy="127.0.0.1,127.0.0.2,::1${no_proxy:+,$no_proxy}"; export NO_PROXY=$no_proxy'
		for kv; do printf 'export %s=%q\n' "${kv%%=*}" "${kv#*=}"; done
		# keeps a bearer token off argv: curl -H @<(bearer)
		echo "bearer() { printf 'Authorization: Bearer %s\\n' \"\$token\"; }"
	} >"$RUN/env"
}

# --- results ---

# abort MESSAGE [DAEMON]: a failure the checks cannot run past; shows the
# daemon's last warnings and errors
abort() {
	fail "$1"
	ABORTED=${2:-}
	[[ -z $ABORTED ]] || excerpt "$ABORTED" '^([^ ]+ (WARN|ERROR) |Error: )' 5
	summary
}

summary() {
	local name counts="$E2E_PASSED passed, $E2E_FAILED failed, $E2E_SKIPPED skipped"
	stop_follow
	if ((E2E_FAILED == 0 && KEEP)); then
		info "--keep: left running: pids ${PIDS[*]}${AT_EXIT[*]:+; later: ${AT_EXIT[*]}}"
		PIDS=() AT_EXIT=()
	fi
	stop_all
	if ((E2E_FAILED)); then
		for name in "${DAEMONS[@]}"; do
			[[ $name == "${ABORTED:-}" ]] || excerpt "$name" '^([^ ]+ ERROR |Error: )'
		done
	fi
	printf '%s%s%s\n' "$C_DIM" "$(rule "$COLS")" "$C_OFF"
	if ((E2E_FAILED)); then
		printf '%sRESULT: FAILURES%s (%s); logs in %s/\n' "$C_BOLD$C_RED" "$C_OFF" "$counts" "$(short "$LOG")"
		exit 1
	fi
	if ((E2E_SKIPPED)); then
		printf '%sRESULT: PASS%s (%s)\n' "$C_BOLD$C_GREEN" "$C_OFF" "$counts"
	else
		printf '%sRESULT: ALL PASS%s (%s)\n' "$C_BOLD$C_GREEN" "$C_OFF" "$counts"
	fi
	exit 0
}

skip_all() { # REASON: nothing in the script applies to this host
	skip "$1"
	printf '%s%s%s\n%sRESULT: SKIPPED%s\n' "$C_DIM" "$(rule "$COLS")" "$C_OFF" "$C_BOLD$C_YELLOW" "$C_OFF"
	exit 77
}

# --- processes ---

spawn() { # NAME COMMAND...: in the background, output to $LOG/NAME.out
	local name=$1
	shift
	"$@" >"$LOG/$name.out" 2>&1 &
	PIDS+=($!) DAEMONS+=("$name")
}
start_daemon() { spawn "$1" "$BIN" -c "$CONF/$2"; } # NAME CONF_FILE
daemons_up() { info "running: ${DAEMONS[*]} (logs: $(short "$LOG")/NAME.out)"; }
at_exit() { AT_EXIT+=("$1"); } # COMMAND, run at teardown

stop_all() { # TERM every process, KILL what outlives 10 s
	local pid deadline=$((SECONDS + 10))
	((${#PIDS[@]})) || return 0
	kill -TERM "${PIDS[@]}" 2>/dev/null
	for pid in "${PIDS[@]}"; do
		while kill -0 "$pid" 2>/dev/null && ((SECONDS < deadline)); do sleep 0.1; done
		kill -KILL "$pid" 2>/dev/null
	done
	info "stopped ${#PIDS[@]} process(es)"
	PIDS=()
}

cleanup() {
	local rc=$? c
	trap '' PIPE
	trap - EXIT
	stop_follow
	stop_all
	for c in "${AT_EXIT[@]}"; do eval "$c" >/dev/null 2>&1; done
	exit "$rc"
}

# follow_logs: with --follow, WARN, ERROR and FOLLOW_KEYS lines of every daemon
# started so far, as they are logged
follow_logs() {
	local name files=()
	((FOLLOW)) || return 0
	for name in "${DAEMONS[@]}"; do files+=("$LOG/$name.out"); done
	tail -v -n +1 -F "${files[@]}" 2>/dev/null > >(follow_filter) &
	FOLLOW_PID=$!
	info "following warnings, errors and key events of: ${DAEMONS[*]}"
}
follow_filter() { # tail -v output -> "NAME HH:MM:SS LEVEL message"; read, not awk, for line buffering
	local line name='' ts lvl rest c
	while IFS= read -r line; do
		case $line in '==> '*' <==')
			name=${line#==> } name=${name% <==} name=${name##*/} name=${name%.out}
			continue ;;
		esac
		read -r ts lvl rest <<<"$line"
		# lw's own startup failure, before its logger runs: "Error: ..."
		[[ $ts == Error: ]] && rest="$lvl $rest" lvl=ERROR ts=''
		case $lvl in
		ERROR) c=$C_RED ;;
		WARN) c=$C_YELLOW ;;
		*) [[ $line =~ $FOLLOW_KEYS ]] || continue; c=$C_CYAN ;;
		esac
		printf '  %s%-12s %s%s %s%-5s %s%s\n' "$C_DIM" "$name" "${ts:11:8}" "$C_OFF" "$c" "$lvl" "${rest#msg }" "$C_OFF"
	done
}
stop_follow() { [[ -z ${FOLLOW_PID:-} ]] || kill "$FOLLOW_PID" 2>/dev/null; FOLLOW_PID=''; }

# manual_hold: starts --follow; without --auto, keeps the daemons up until Ctrl-C
manual_hold() {
	follow_logs
	((AUTO)) && return 0
	info "manual mode: the daemons stay up until Ctrl-C (--auto runs the checks)"
	while :; do sleep 1; done
}

# --- network and files ---

# listening PORT [HOST]: a listener on PORT in HOST's address family. It reads
# the kernel's table: a probe connection would land in the daemon logs, as a
# failed TLS handshake or hello the checks count.
listening() {
	local table=/proc/net/tcp
	[[ ${2:-} == *:* ]] && table=/proc/net/tcp6
	awk -v port="$(printf ':%04X' "$1")" '$4 == "0A" && substr($2, length($2) - 4) == port { found = 1 }
		END { exit !found }' "$table" 2>/dev/null
}
wait_port() { # PORT [HOST]: up to 10 s
	local i
	for ((i = 0; i < 100; i++)); do
		listening "$@" && return 0
		sleep 0.1
	done
	return 1
}
wait_until() { # SECONDS COMMAND...
	local deadline=$((SECONDS + $1))
	shift
	until "$@"; do
		((SECONDS >= deadline)) && return 1
		sleep 0.2
	done
}
ports_free() { # PORT...: in either family, as a dual-stack [::] listener holds IPv4 too
	local p
	for p; do
		listening "$p" || listening "$p" :: && abort "port $p is already in use"
	done
	return 0
}
need() { # TOOL...: the binary and each tool, or abort
	[[ -x $BIN ]] || abort "no lw binary at $(short "$BIN"): make build"
	local t
	for t; do command -v "$t" >/dev/null || abort "$t not found"; done
}

# What a plain TCP sink client receives in SECONDS
tcp_read() { timeout "$2" bash -c "exec 3<>/dev/tcp/127.0.0.1/$1; cat <&3" 2>/dev/null || true; }
ingested() { cat "$OUT/$1"* 2>/dev/null; }                  # FILE_PREFIX: the relay's file sinks
has_entry() { ingested "$1" | grep -q -- "$2"; }            # FILE_PREFIX PATTERN
count() { grep -c -- "$2" "$LOG/$1.out" 2>/dev/null; }      # DAEMON PATTERN
logged() { local n; n=$(count "$1" "$2"); ((${n:-0} >= ${3:-1})); } # DAEMON PATTERN [MIN]
excerpt() { # DAEMON ERE [LINES]: its last matching WARN or ERROR lines
	{ echo "==> $1 <=="; grep -E "$2" "$LOG/$1.out" 2>/dev/null | tail -n "${3:-3}"; } | follow_filter
}

# --- credentials ---

pki_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
pki_ca() { # the test CA in $PKI
	mkdir -p "$PKI"
	pki_key "$PKI/ca.key"
	openssl req -x509 -new -key "$PKI/ca.key" -days "$PKI_DAYS" -out "$PKI/ca.crt" \
		-subj "/CN=LogWisp Test CA" 2>/dev/null || abort "PKI: cannot create the CA"
}
pki_leaf() { # NAME CN EKU [SAN]: $PKI/NAME.crt and NAME.key from the test CA
	local name=$1 ext="extendedKeyUsage=$3"
	[[ -n ${4:-} ]] && ext+=$'\n'"subjectAltName=$4"
	printf '%s\n' "$ext" >"$PKI/$name.ext"
	pki_key "$PKI/$name.key"
	openssl req -new -key "$PKI/$name.key" -out "$PKI/$name.csr" -subj "/CN=$2" 2>/dev/null
	openssl x509 -req -in "$PKI/$name.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial \
		-out "$PKI/$name.crt" -days "$PKI_DAYS" -extfile "$PKI/$name.ext" 2>/dev/null
	[[ -s $PKI/$name.crt ]] || abort "PKI: cannot issue $name"
}
add_users() { # CREDENTIALS USER...: through the CLI, passwords in $AUTH/USER.pass
	local u
	for u in "${@:2}"; do
		"$BIN" auth add-user -credentials "$1" -user "$u" -password-file "$AUTH/$u.pass" \
			>>"$LOG/auth-cli.out" 2>&1 || abort "lw auth add-user $u failed" auth-cli
	done
}
