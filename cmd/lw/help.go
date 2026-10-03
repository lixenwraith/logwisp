package main

import (
	"fmt"
	"os"

	"github.com/lixenwraith/logwisp/internal/version"
)

// helpText is the CLI usage reference. Scalar flags map 1:1 to TOML config paths.
const helpText = `LogWisp %s - log collection, processing, and distribution

Usage:
  lw [options] [< input]        No file, no pipeline options: stdin to stdout,
                                line for line, like cat; exits at end of input
  lw -c <file> [options]        Run the file's pipelines
  lw --check [options]          Build every pipeline and plugin, report, exit
  lw help | -h | --help
  lw --version

Subcommands:
  lw auth <command>             SCRAM credentials files, bearer tokens and tcp
                                sink viewing; lw auth -h lists commands

Scalar configuration keys are settable as flags using their TOML paths:
  --<path>=<value>              e.g. --logging.level=debug

Common options:
  -c, --config <path>           Configuration file (default: ./logwisp.toml)
      --quiet                   Suppress console output
      --status_reporter=<bool>  Periodic status logging (default: true with
                                a configuration file)
      --auto_reload=<bool>      Config hot reload on file change (default: false)

Logging (lw's own log goes to stderr, at info with a configuration file and
at warn without one):
      --logging.output=<mode>   file|stdout|stderr|split|all|none
      --logging.level=<level>   debug|info|warn|error
      --logging.file.directory=<path>

Pipelines (replace the file's pipelines; see doc/cli.md):
      --pipeline <name>         Start a pipeline; earlier specs go to "cli"
      --source <spec>           TYPE[,key=value...], repeatable
      --sink <spec>             e.g. http,host=0.0.0.0,port=8080, repeatable
      --filter <spec>           include|exclude,patterns=RE, repeatable
      --format <spec>           json|txt|raw[,key=value...]
      --rate-limit <spec>       rate=N[,burst=N,policy=drop|pass]
      --heartbeat <spec>        interval_ms=N[,include_stats=true,...]
  A pipeline without --source reads stdin, one without --sink writes stdout.
  Keys nest with '.' (tls.cert_file=...), a repeated key makes a list, and
  '\' escapes ',' '=' '\' in values. -- ends option parsing.

Examples:
  lw < app.log > copy.log                         Copy, line for line
  tail -F app.log | lw --filter include,patterns=ERROR,patterns=WARN
  journalctl -f | lw --sink http,host=127.0.0.1,port=8080
                                                  Serve stdin as a live stream
  lw --source file,directory=/var/log/app,pattern='*.log' --format txt

Environment:
  LOGWISP_<PATH>                Config path, '.' -> '_', uppercase
                                e.g. LOGWISP_LOGGING_LEVEL=debug
  LOGWISP_CONFIG_FILE           Configuration file path
  LOGWISP_CONFIG_DIR            Configuration directory
  LOGWISP_PIPELINE, LOGWISP_SOURCE[_N], LOGWISP_SINK[_N], LOGWISP_FILTER[_N],
  LOGWISP_FORMAT, LOGWISP_RATE_LIMIT, LOGWISP_HEARTBEAT
                                One pipeline, specs as the flags (_N adds
                                more); ignored when a pipeline flag is given

Signals:
  SIGINT, SIGTERM               Graceful shutdown
  SIGHUP, SIGUSR1               Reload configuration

Exit codes:
  0  success, including the end of input
  1  general error
  2  configuration file not found
`

// handleHelp prints usage and exits if a help request is present in args
func handleHelp(args []string) {
	if len(args) > 0 && args[0] == "help" {
		printHelp()
	}
	for _, arg := range args {
		if arg == "--" {
			break // end of flags
		}
		if arg == "-h" || arg == "--help" {
			printHelp()
		}
	}
}

func printHelp() {
	fmt.Printf(helpText, version.Short())
	os.Exit(0)
}
