#!/usr/bin/env bash
# logwisp pipe test: without a configuration file lw is a filter, stdin to
# stdout line for line, without loss, quiet on stderr, exiting 0 at the end of
# input. One-shot: both modes run the checks; no ports.
# Requires: bash 5+, coreutils (timeout, seq, head, cmp, od). Linux dev host only.

set -u
. "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

RUN=$E2E_DIR/run/pipe
e2e_init "$@"

section "Setup"
need
rm -rf "$RUN"
mkdir -p "$RUN/bare" "$RUN/withfile" "$LOG"
printf '[logging]\noutput = "stderr"\n' >"$RUN/withfile/logwisp.toml"
# lw DIR ARGS...: in DIR, with no user configuration or LOGWISP_ variable
lw() {
	(
		cd "$RUN/$1" || exit 1
		for v in $(compgen -e LOGWISP_); do unset "$v"; done
		HOME=$RUN timeout 30 "$BIN" "${@:2}"
	)
}
info "runs lw in $(short "$RUN")/bare (no file) and $(short "$RUN")/withfile"

section "Checks"
# 1. line for line, without loss, and nothing on stderr
seq 1 200000 >"$RUN/seq.txt"
lw bare <"$RUN/seq.txt" >"$RUN/seq.out" 2>"$LOG/seq.err"
rc=$?
check "200000 lines pass unchanged, exit $rc" $((rc == 0))
check "output identical to input" "$(cmp -s "$RUN/seq.txt" "$RUN/seq.out" && echo 1 || echo 0)"
check "nothing on stderr without a configuration file" "$( [[ -s $LOG/seq.err ]] && echo 0 || echo 1)"

# 2. sources are subscribed before they start: the first line is not lost
check "a single line arrives" "$(is "$(printf 'first\n' | lw bare)" first)"

# 3. terminators: CRLF stripped, blank lines skipped, last line unterminated
check "\\r\\n, blank and unterminated lines" "$(is "$(printf 'a\r\nb\n\nc' | lw bare | od -An -c | tr -s ' ')" " a \n b \n c \n")"

# 4. a line over the 1 MiB entry cap continues in the next entry, no byte lost
head -c 2500000 /dev/zero | tr '\0' x | lw bare >"$RUN/long.out"
check "2.5 MB line: entries of $(awk '{printf "%s ", length($0)}' "$RUN/long.out")" \
	"$(is "$(awk '{n += length($0)} END {print NR, n}' "$RUN/long.out")" "3 2500000")"

# 5. a slow reader slows lw down instead of losing lines
n=$(seq 1 50000 | lw bare | { sleep 1; wc -l; })
check "slow reader receives all 50000 lines ($n)" "$((n == 50000))"

# 6. a reader that leaves ends lw as it ends cat: SIGPIPE
seq 1 5000000 | lw bare | head -1 >/dev/null
rc=${PIPESTATUS[1]}
check "reader gone: lw exits on SIGPIPE ($rc)" "$((rc == 141))"

# 7. filters and formats compose with stdin and stdout
check "--filter keeps matching lines" "$(is "$(printf 'x INFO\ny ERROR\n' | lw bare --filter include,patterns=ERROR)" "y ERROR")"

# 8. control characters pass to a pipe unchanged and are escaped on request
check "control bytes reach a pipe unchanged" "$(is "$(printf 'a\033[31mb\n' | lw bare | od -An -tx1 | tr -d ' ')" 611b5b33316d620a)"
check "escape=always writes them as <hex>" "$(is "$(printf 'a\033[31mb\n' | lw bare --sink console,escape=always)" 'a<1b>[31mb')"

# 9. a configuration file makes lw a service: info on stderr, data on stdout
out=$(printf 'x\n' | lw withfile 2>"$LOG/withfile.err")
check "with a file: data still on stdout" "$(is "$out" x)"
check "with a file: info logging on stderr" "$(grep -q 'LogWisp starting' "$LOG/withfile.err" && echo 1 || echo 0)"

summary
