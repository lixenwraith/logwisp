package main

import (
	"fmt"
	"strings"

	"github.com/lixenwraith/logwisp/internal/version"
)

// helpText is the CLI usage reference. Scalar flags map 1:1 to TOML config paths.
const helpText = `LogWisp %s - log collection, processing, and distribution

Usage:
  lw [options] [< input]        No file, no pipeline options: stdin to stdout,
                                line for line, like cat; exits at end of input
  lw -c|--config FILE [options] Run the file's pipelines
  lw -p|--preset SPEC [options] Run a preset's pipeline
  lw -t|--check [options]       Build every pipeline and plugin, report, exit
  lw --dump [options]           Print the effective configuration as TOML, exit
  lw help | -h | --help
  lw -V | --version

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
  -q, --quiet                   Silence lw's own log and notices; pipeline
                                output still flows
      --color [WHEN]            Level names in color on console sinks:
                                auto (a terminal, NO_COLOR unset; default),
                                always (bare --color) or never
  -V, --version                 Print the version and exit
  -h, --help                    Print this help and exit
      --                        End the options

Configuration keys are flags by their TOML path, '_' and '.' kept:
      --KEY=VALUE               e.g. --logging.level=debug
      --status_reporter=BOOL    Periodic status logging (default: true with
                                a configuration file)
      --auto_reload=BOOL        Reload when the file changes (default: false)
  Logging (lw's own log goes to stderr, at info with a configuration file and
  at warn without one):
      --logging.output=MODE     file|stdout|stderr|split|all|none
      --logging.level=LEVEL     debug|info|warn|error
      --logging.file.directory=DIR

Pipelines (replace the file's pipelines; see doc/cli.md):
  -p, --preset NAME[,KEY=VALUE...]
                                Start a pipeline with a preset: pipe, tail,
                                serve, edge, aggregator; lw preset NAME -h
                                lists its keys, lw preset NAME prints it
      --pipeline NAME           Start a pipeline; earlier specs go to "cli"
      --source SPEC             TYPE[,KEY=VALUE...], repeatable
      --sink SPEC               e.g. http,host=0.0.0.0,port=8080, repeatable
      --filter SPEC             include|exclude,patterns=RE, repeatable
      --format SPEC             json|txt|raw[,KEY=VALUE...]
      --rate-limit SPEC         rate=N[,burst=N,policy=drop|pass]
      --heartbeat SPEC          interval_ms=N[,include_stats=true,...]
  A pipeline without --source reads stdin, one without --sink writes stdout.
  Keys nest with '.' (tls.cert_file=...), a repeated key makes a list, and
  '\' escapes ',' '=' '\' in values.

Examples:
  lw < app.log > copy.log                         Copy, line for line
  tail -F app.log | lw --filter include,patterns=ERROR,patterns=WARN
  journalctl -f | lw --sink http,host=127.0.0.1,port=8080
                                Serve stdin live; browse http://127.0.0.1:8080/
  lw --source file,directory=/var/log/app,pattern='*.log' --format txt
  lw -p tail,path=/var/log/app                    Follow a directory's files
  lw --preset serve,path=/var/log/app,tls=self,users=users.toml
                                                  HTTPS stream, SCRAM logins
  lw --preset edge,path=/var/log/app,to=agg:9000,ca=ca.crt,user=edge-01,\
password_file=edge-01.pass                        Forward to an aggregator

Environment:
  LOGWISP_<PATH>                Config path, '.' -> '_', uppercase
                                e.g. LOGWISP_LOGGING_LEVEL=debug
  LOGWISP_CONFIG_FILE           Configuration file path
  LOGWISP_CONFIG_DIR            Configuration directory
  LOGWISP_PIPELINE, LOGWISP_PRESET, LOGWISP_SOURCE[_N], LOGWISP_SINK[_N],
  LOGWISP_FILTER[_N], LOGWISP_FORMAT, LOGWISP_RATE_LIMIT, LOGWISP_HEARTBEAT
                                One pipeline, specs as the flags (_N adds
                                more); ignored when a pipeline flag is given

Signals:
  SIGINT, SIGTERM               Graceful shutdown
  SIGHUP, SIGUSR1               Reload configuration

Exit codes:
  0  success, including the end of input
  1  general error, including a configuration that does not load
  2  usage error, or a named configuration file not found
`

func printHelp() {
	var list strings.Builder
	for _, c := range commands {
		fmt.Fprintf(&list, "  lw %-26s %s\n", c.name+" COMMAND", c.summary)
	}
	fmt.Printf(helpText, version.Short(), list.String())
}
