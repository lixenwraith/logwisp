package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

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
}

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
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s %s\n\n%s.\n\n", fs.Name(), s.synopsis, s.summary)
		fs.PrintDefaults()
	}
	work := s.define(fs)
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2 // already reported by flag, with the usage
	}
	err := checkArgs(fs, s.required)
	if err == nil {
		err = work(stdout, stderr)
	}
	if err == nil {
		return 0
	}
	fmt.Fprintf(stderr, "%s: %v\n", fs.Name(), err)
	if _, ok := errors.AsType[usageError](err); ok {
		fs.Usage()
		return 2
	}
	return 1
}

func (c *command) usage(w io.Writer) {
	fmt.Fprintf(w, "Usage: lw %s <command> [flags]\n\n", c.name)
	for _, s := range c.subcommands {
		fmt.Fprintf(w, "  %-12s %s\n", s.name, s.summary)
	}
	fmt.Fprintf(w, "\nRun lw %s <command> -h for its flags. %s\n"+
		"Exit status: 0 success, 1 failure, 2 usage error.\n", c.name, c.footer)
}

func checkArgs(fs *flag.FlagSet, required []string) error {
	if fs.NArg() > 0 {
		return usageError(fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}
	for _, name := range required {
		if fs.Lookup(name).Value.String() == "" {
			return usageError("-" + name + " is required")
		}
	}
	return nil
}

// invocation is a parsed command line: a command with its arguments, a help
// request, or what config.Load reads.
type invocation struct {
	command *command
	args    []string
	help    bool
	load    config.Args
}

// parseCommandLine reads lw's own flags; anything else is a --path=value
// setting for lixenwraith/config, which reports what it does not know. A
// pipeline flag takes the next argument unless it starts with '-'. A help
// request wins over a malformed flag.
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
		inv.help = argv[0] == "help"
	}
	specFlags := config.SpecFlags()
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
		switch {
		case arg == "--":
			inv.load.Overrides = append(inv.load.Overrides, argv[i:]...)
			return inv, err
		case arg == "-h" || arg == "--help":
			inv.help = true
		case name == "-c" || name == "--config":
			if !inline {
				value = next(&i)
			}
			if value == "" {
				err = cmp.Or(err, fmt.Errorf("%s requires a configuration file path", name))
			}
			inv.load.File = value
		case arg == "--color":
			// Bare, it means always: config takes no bare flag for a string key
			inv.load.Overrides = append(inv.load.Overrides, "--color="+cmp.Or(next(&i), "always"))
		case strings.HasPrefix(name, "--") && slices.Contains(specFlags, name[2:]):
			if !inline {
				value = next(&i)
			}
			inv.load.Specs = append(inv.load.Specs, config.Spec{Flag: name[2:], Value: value})
		default:
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
				synopsis = append(synopsis, "-"+k.Name+" VALUE")
			}
		}
		s.synopsis = strings.Join(append(synopsis, "[-KEY VALUE...]"), " ")
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
