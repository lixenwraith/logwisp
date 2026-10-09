package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"

	shipped "github.com/lixenwraith/logwisp/config"
	"github.com/lixenwraith/logwisp/internal/config"

	"github.com/lixenwraith/toml"
)

// command is a group of subcommands, recognized only as lw's first argument
type command struct {
	name, summary, footer string
	subcommands           []subcommand
}

// subcommand is one `lw COMMAND NAME`: define registers its flags and
// returns the work, which runs once they are parsed and checked.
type subcommand struct {
	name, synopsis, summary string
	required                []string
	define                  func(fs *flag.FlagSet) func(stdout, stderr io.Writer) error
}

var commands = []command{
	{"auth", "SCRAM users, bearer tokens, tcp sink viewing",
		"Credential changes apply on SIGHUP.", authCommands},
	{"tls", "A CA and certificates for TLS and mTLS",
		"Files are never overwritten; keys are written mode 0600.", tlsCommands},
	{"preset", "Show the pipeline a preset makes, as TOML",
		"lw --preset NAME,key=value runs one; flags here are its keys.", presetCommands()},
	{"config", "Place the annotated default configuration",
		"Files are never overwritten; lw --dump prints the effective configuration.", configCommands},
}

// shorts are lw's one-letter flags, each its long flag in every command that
// defines that flag; lw's own command line takes the top ones
var shorts = map[string]struct {
	long string
	top  bool
}{
	"c": {"config", true}, "h": {"help", true}, "p": {"preset", true},
	"q": {"quiet", true}, "t": {"check", true}, "V": {"version", true},
	"u": {"user", false},
}

// switches are lw's own options that take no value and are no setting, so no
// file or environment variable turns one on
var switches = []string{"check", "dump", "version"}

// usageError is a command-line mistake: exit status 2 rather than 1
type usageError string

func (e usageError) Error() string { return string(e) }

// run runs a subcommand and returns the exit status: 0 success or help,
// 1 failure, 2 usage error.
func (c *command) run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || slices.Contains([]string{"-h", "-help", "--help", "help"}, args[0]) {
		c.usage(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	i := slices.IndexFunc(c.subcommands, func(s subcommand) bool { return s.name == args[0] })
	if i < 0 {
		fmt.Fprintf(stderr, "lw %s: unknown command %q\n\n", c.name, args[0])
		c.usage(stderr)
		return 2
	}
	s := c.subcommands[i]
	fs := flag.NewFlagSet("lw "+c.name+" "+s.name, flag.ContinueOnError)
	// flag names a long flag with one dash: its errors, and the usage, print below
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	usage := func() {
		fmt.Fprintf(stderr, "Usage: %s %s\n\n%s.\n\n", fs.Name(), s.synopsis, s.summary)
		printFlags(stderr, fs)
	}
	work := s.define(fs)
	for letter, short := range shorts {
		if f := fs.Lookup(short.long); f != nil {
			fs.Var(f.Value, letter, "") // no usage: printFlags shows it with its long flag
		}
	}
	err := fs.Parse(args[1:])
	switch {
	case errors.Is(err, flag.ErrHelp):
		usage()
		return 0
	case err != nil:
		err = usageError(longFlag.ReplaceAllString(err.Error(), "$1--$2"))
	default:
		err = checkArgs(fs, s.required)
	}
	if err == nil {
		err = work(stdout, stderr)
	}
	if err == nil {
		return 0
	}
	fmt.Fprintf(stderr, "%s: %v\n", fs.Name(), err)
	if _, ok := errors.AsType[usageError](err); ok {
		usage()
		return 2
	}
	return 1
}

// longFlag is a flag name of two or more letters in flag's errors
var longFlag = regexp.MustCompile(`(^|\s)-(\w[\w-]+)`)

func (c *command) usage(w io.Writer) {
	fmt.Fprintf(w, "Usage: lw %s COMMAND [flags]\n\n", c.name)
	for _, s := range c.subcommands {
		fmt.Fprintf(w, "  %-12s %s\n", s.name, s.summary)
	}
	fmt.Fprintf(w, "\nRun lw %s COMMAND -h for its flags. %s\n"+
		"Exit status: 0 success, 1 failure, 2 usage error.\n", c.name, c.footer)
}

// printFlags lists fs's flags as "  -u, --user NAME" or "      --credentials FILE"
func printFlags(w io.Writer, fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		if f.Usage == "" {
			return
		}
		head := "    "
		for letter, short := range shorts {
			if short.long == f.Name {
				head = "-" + letter + ", "
			}
		}
		arg, usage := flag.UnquoteUsage(f)
		// Only a bool flag has no argument; its "false" default goes unsaid
		if f.DefValue != "" && (arg != "" || f.DefValue != "false") {
			usage += " (default: " + f.DefValue + ")"
		}
		if arg == "string" {
			arg = "value"
		}
		if arg != "" {
			arg = " " + strings.ToUpper(arg)
		}
		fmt.Fprintf(w, "  %s--%s%s\n        %s\n", head, f.Name, arg, usage)
	})
}

func checkArgs(fs *flag.FlagSet, required []string) error {
	if fs.NArg() > 0 {
		return usageError(fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}
	for _, name := range required {
		if fs.Lookup(name).Value.String() == "" {
			return usageError("--" + name + " is required")
		}
	}
	return nil
}

// invocation is a parsed command line: a command with its arguments, a help
// request, or the switches given and what config.Load reads.
type invocation struct {
	command *command
	args    []string
	help    bool
	on      map[string]bool
	load    config.Args
}

// parseCommandLine reads lw's own flags, a short one as its long one; any
// other --flag is a setting, passed to lixenwraith/config as --path=value or a
// bare switch so it never guesses. A flag's value is the next argument unless
// that starts with '-'. Every error is a usage error; a help request wins.
func parseCommandLine(argv []string) (inv invocation, err error) {
	defer func() {
		if inv.help {
			err = nil
		}
	}()
	if len(argv) > 0 {
		if i := slices.IndexFunc(commands, func(c command) bool { return c.name == argv[0] }); i >= 0 {
			return invocation{command: &commands[i], args: argv[1:]}, nil
		}
	}
	specFlags, settings := config.SpecFlags(), config.Settings()
	unexpected := func(word string) error {
		return fmt.Errorf("unexpected argument %q: lw takes options only (a configuration file is -c FILE, a switch's value follows '=')", word)
	}
	next := func(i *int) string {
		if *i+1 < len(argv) && !strings.HasPrefix(argv[*i+1], "-") {
			*i++
			return argv[*i]
		}
		return ""
	}
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		name, value, inline := strings.Cut(arg, "=")
		typed := name
		if short, ok := shorts[strings.TrimPrefix(name, "-")]; ok && short.top && len(name) == 2 {
			arg, name = "--"+short.long+arg[len(name):], "--"+short.long
		}
		switch {
		case arg == "--":
			if i+1 < len(argv) {
				err = cmp.Or(err, unexpected(argv[i+1]))
			}
			return inv, err
		case arg == "--help" || i == 0 && arg == "help":
			inv.help = true
		case name == "--config":
			if !inline {
				value = next(&i)
			}
			if value == "" {
				err = cmp.Or(err, fmt.Errorf("%s requires a configuration file path", typed))
			}
			inv.load.File = value
		case strings.HasPrefix(name, "--") && slices.Contains(switches, name[2:]):
			if inline {
				err = cmp.Or(err, fmt.Errorf("%s takes no value", typed))
			}
			if inv.on == nil {
				inv.on = map[string]bool{}
			}
			inv.on[name[2:]] = true
		case arg == "--color":
			// Bare, it means always: config takes no bare flag for a string key
			inv.load.Overrides = append(inv.load.Overrides, "--color="+cmp.Or(next(&i), "always"))
		case strings.HasPrefix(name, "--") && slices.Contains(specFlags, name[2:]):
			if !inline {
				value = next(&i)
			}
			if value == "" {
				err = cmp.Or(err, fmt.Errorf("%s requires a value; one that starts with '-' follows '='", typed))
			}
			inv.load.Specs = append(inv.load.Specs, config.Spec{Flag: name[2:], Value: value})
		case len(name) > 1 && name[0] == '-' && unicode.IsLetter(rune(name[1])):
			// lw's only single-dash options are the shorts
			err = cmp.Or(err, fmt.Errorf("unknown option %s: long options take two dashes, and a value that starts with '-' follows '=' (lw --help lists them)", typed))
		case !strings.HasPrefix(name, "--"):
			err = cmp.Or(err, unexpected(arg))
		default:
			isSwitch, known := settings[name[2:]]
			if !known {
				err = cmp.Or(err, fmt.Errorf("unknown option %s (lw --help lists them)", typed))
			}
			if !inline && !isSwitch {
				if value = next(&i); value == "" && known {
					err = cmp.Or(err, fmt.Errorf("%s needs a value; one that starts with '-' follows '='", typed))
				}
				arg += "=" + value
			}
			inv.load.Overrides = append(inv.load.Overrides, arg)
		}
	}
	return inv, err
}

// presetCommands makes each preset a subcommand whose flags are its keys
func presetCommands() []subcommand {
	var subs []subcommand
	for _, p := range config.Presets() {
		s := subcommand{name: p.Name, summary: p.Summary}
		var synopsis []string
		for _, k := range p.Params {
			if k.Required {
				s.required = append(s.required, k.Name)
				synopsis = append(synopsis, "--"+k.Name+" VALUE")
			}
		}
		s.synopsis = strings.Join(append(synopsis, "[--KEY VALUE...]"), " ")
		s.define = func(fs *flag.FlagSet) func(stdout, stderr io.Writer) error {
			values := map[string]*string{}
			for _, k := range p.Params {
				values[k.Name] = fs.String(k.Name, k.Default, k.Help)
			}
			return func(stdout, _ io.Writer) error {
				set := map[string]string{}
				for name, v := range values {
					set[name] = *v
				}
				pipeline, err := config.ExpandPreset(p.Name, set)
				if err != nil {
					return usageError(err.Error())
				}
				data, err := toml.Marshal(map[string]any{"pipelines": []config.PipelineConfig{pipeline}})
				if err == nil {
					_, err = stdout.Write(data)
				}
				return err
			}
		}
		subs = append(subs, s)
	}
	return subs
}

var configCommands = []subcommand{
	{"init", "[--out FILE]",
		"Write the annotated default configuration, to edit and run",
		nil, defineConfigInit},
}

func defineConfigInit(flags *flag.FlagSet) func(stdout, stderr io.Writer) error {
	out := flags.String("out", "", "`file` to write (default: ~/.config/logwisp/logwisp.toml)")
	return func(_, stderr io.Writer) error {
		user, err := config.UserFile()
		path := cmp.Or(*out, user)
		if path == "" {
			return fmt.Errorf("no home directory for the default file (%v): name one with --out", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := writeNew(path, shipped.Sample, 0o644); errors.Is(err, fs.ErrExist) {
			if fi, err := os.Stat(path); err == nil && fi.IsDir() {
				return fmt.Errorf("%s is a directory: name the file, as in %s", path, filepath.Join(path, "logwisp.toml"))
			}
			return fmt.Errorf("%s exists; remove it to replace it", path)
		} else if err != nil {
			return err
		}
		// -c refuses a path that climbs out with ..; an absolute one loads anywhere
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if found, err := filepath.Abs(config.DefaultPath()); err == nil && found == path {
			fmt.Fprintf(stderr, "wrote %s; lw reads it without -c\n", path)
		} else {
			fmt.Fprintf(stderr, "wrote %s; run it with lw -c %s\n", path, path)
		}
		return nil
	}
}
