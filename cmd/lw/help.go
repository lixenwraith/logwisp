package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/lixenwraith/logwisp/internal/version"
)

// helpText lists every option lw takes; man lw is the full reference.
const helpText = `LogWisp %s - log collection, processing, and distribution

Usage:
  lw [options] [< input]        No file, no pipeline options: stdin to stdout,
                                line for line, like cat; exits at end of input
  lw -c|--config FILE [options] Run the file's pipelines
  lw -p|--preset SPEC [options] Run a preset's pipeline
  lw -t|--check [options]       Build every pipeline and plugin, report, exit
  lw --dump [options]           Print the effective configuration as TOML, exit
  lw -T|--tui [options]         Compose pipelines on screen, then run them or
                                print them as flags, variables or a file
  lw help | -h | --help
  lw -V | --version | --schema

Commands (lw COMMAND -h lists its subcommands):
%s
Options: a short option is its long one; a value follows as the next argument
or after '=' (-c FILE, --config=FILE), one that starts with '-' or a switch's
after '='; short options do not combine. lw takes options only.
  -c, --config FILE             Configuration file (default:
                                ~/.config/logwisp/logwisp.toml if it exists,
                                else ./logwisp.toml)
  -t, --check                   Build every pipeline and plugin, report, exit
      --dump                    Print the effective configuration, exit
  -T, --tui                     Compose the pipelines on a full-screen
                                terminal, starting from the ones lw would run
                                or a preset; then run them, or print them
  -q, --quiet                   Silence lw's own log and notices; pipeline
                                output still flows
      --color [WHEN]            Level names in color on console sinks: auto
                                (on a terminal; default), always (a bare
                                --color) or never
  -V, --version                 Print the version and exit
      --schema                  Print every setting, flag, plugin option and
                                preset as JSON, exit
  -h, --help                    Print this help and exit
      --                        End the options

Configuration keys are options by their TOML path, '_' and '.' kept; a BOOL
key alone means true:
      --status_reporter=BOOL    Log pipeline statistics every 30 s at debug
                                (default: true with a configuration file)
      --auto_reload=BOOL        Reload when the file changes (default: false)
  lw's own log:
      --logging.output=MODE     stderr (default), stdout, split (warn and
                                error to stderr, the rest to stdout), file,
                                all (split and file) or none
      --logging.level=LEVEL     debug|info|warn|error (default: info with a
                                configuration file, warn without)
      --logging.format=FORMAT   txt|json|raw (default: txt)
      --logging.sanitization=POLICY
                                raw (default: unchanged), txt (hex for '<'
                                and non-printables), json (escapes control
                                characters) or shell (strips; lossy)
      --logging.file.directory=DIR
                                Where file and all write (default: ./log);
                                lw's alone: the limits below delete any old
                                .log file in it
      --logging.file.name=NAME  File name base (default: logwisp)
      --logging.file.max_size_mb=N
                                Start a new file past N MB (default: 100)
      --logging.file.max_total_size_mb=N
                                Delete the oldest .log files there past N MB
                                in all (default: 1000)
      --logging.file.retention_hours=H
                                Delete .log files there older than H hours
                                (default: 168; 0 keeps them)
      --logging.console.target=TARGET
                                Accepted without effect: --logging.output
                                chooses the console

Pipelines (they replace the configuration file's pipelines):
  -p, --preset NAME[:KEY=VALUE,...]
                                Start a pipeline with a preset: pipe, tail,
                                serve, edge, aggregator; lw preset NAME -h
                                lists its keys, lw preset NAME prints it
      --pipeline NAME           Start a pipeline named NAME, which the
                                pipeline options after it configure; those
                                before any --pipeline make one named after
                                its --preset, or "cli" without one
      --source SPEC             TYPE[:KEY=VALUE,...], repeatable
      --sink SPEC               e.g. http:host=0.0.0.0,port=8080, repeatable
      --filter SPEC             include|exclude:patterns=RE, repeatable
      --format SPEC             json|txt|raw[:KEY=VALUE,...]
      --rate-limit SPEC         entries_per_second=N[,burst_entries=N,
                                policy=drop|pass]
      --heartbeat SPEC          interval_ms=N[,include_stats=true,...]
  A pipeline without --source reads stdin, one without --sink writes stdout.
  TYPE ends at the first ':'. Keys nest with '.' (tls.cert_file=...), a
  repeated key makes a list, and '\' escapes ',' '=' '\' in values.

Examples:
  lw < app.log > copy.log                         Copy, line for line
  tail -F app.log | lw --filter include:patterns=ERROR,patterns=WARN
  journalctl -f | lw --sink http:host=127.0.0.1,port=8080
                                Serve stdin live; browse http://127.0.0.1:8080/
  lw --source file:directory=/var/log/app,pattern='*.log' --format txt
  lw -p tail:path=/var/log/app                    Follow a directory's files
  lw --preset serve:path=/var/log/app,tls=self,users=users.toml
                                                  HTTPS stream, SCRAM logins
  lw --preset edge:path=/var/log/app,to=agg:9000,ca=ca.crt,user=edge-01,\
password_file=edge-01.pass                        Forward to an aggregator
  lw -p aggregator:user=pipe,format=raw           A temporary pipe's end: Enter
                                                  at the prompt draws a password
  cmd | lw -p edge:to=HOST:9000,pin=PIN,user=pipe
                                                  Its source, asked the password

Environment:
  LOGWISP_<KEY>                 A configuration key, '.' as '_', uppercase:
                                LOGWISP_LOGGING_LEVEL=debug
  LOGWISP_CONFIG_FILE           Configuration file path
  LOGWISP_CONFIG_DIR            Configuration directory
  LOGWISP_PIPELINE, LOGWISP_PRESET, LOGWISP_SOURCE[_N], LOGWISP_SINK[_N],
  LOGWISP_FILTER[_N], LOGWISP_FORMAT, LOGWISP_RATE_LIMIT, LOGWISP_HEARTBEAT
                                One pipeline, specs as the flags (_N adds
                                more); ignored when a pipeline flag is given
  NO_COLOR, TERM=dumb           Turn --color auto off

Signals:
  SIGINT, SIGTERM               Graceful shutdown
  SIGHUP, SIGUSR1               Reload configuration

Exit codes:
  0  Success, including the end of input
  1  Failure, including a configuration that does not load
  2  Usage error, or a named configuration file not found

The full reference, with every key, preset and command: man lw
`

func printHelp(w io.Writer) {
	var list strings.Builder
	for _, c := range commands {
		fmt.Fprintf(&list, "  lw %-26s %s\n", c.name+" COMMAND", c.summary)
	}
	fmt.Fprintf(w, helpText, version.Short(), list.String())
}
