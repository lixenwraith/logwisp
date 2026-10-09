package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	shipped "github.com/lixenwraith/logwisp/config"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/testutil"
	"github.com/lixenwraith/logwisp/internal/tlsx"
)

// lw's own flags: a short is its long flag, an unknown single-dash one fails,
// the last -c wins, a flag takes the next argument unless it starts with '-',
// a switch takes none, and a command is only the first argument. A setting
// reaches config as --path=value or a bare switch.
func TestCommandLineGrammar(t *testing.T) {
	for _, c := range []struct {
		argv []string
		want invocation
	}{
		{[]string{"-c", "a.toml", "--config=b.toml", "--quiet"}, invocation{load: config.Args{File: "b.toml", Overrides: []string{"--quiet"}}}},
		{[]string{"-c=a.toml", "--config", "b.toml"}, invocation{load: config.Args{File: "b.toml"}}},
		{[]string{"--source=null", "--sink", "http,port=1"},
			invocation{load: config.Args{Specs: []config.Spec{{Flag: "source", Value: "null"}, {Flag: "sink", Value: "http,port=1"}}}}},
		{[]string{"--preset", "tail,path=x", "--pipeline", "b"}, invocation{load: config.Args{Specs: []config.Spec{{Flag: "preset", Value: "tail,path=x"}, {Flag: "pipeline", Value: "b"}}}}},
		{[]string{"--color", "--color", "never", "--color=auto"}, invocation{load: config.Args{Overrides: []string{"--color=always", "--color=never", "--color=auto"}}}},
		{[]string{"--quiet", "--"}, invocation{load: config.Args{Overrides: []string{"--quiet"}}}},
		{[]string{"--quiet", "-h"}, invocation{help: true, load: config.Args{Overrides: []string{"--quiet"}}}},
		{[]string{"-c", "-h"}, invocation{help: true}},
		{[]string{"help"}, invocation{help: true}},
		{[]string{"tls", "ca", "-h"}, invocation{command: &commands[1], args: []string{"ca", "-h"}}},
		{[]string{"-q", "-t", "-V", "-p", "tail,path=x", "-c=a.toml", "--logging.level", "debug", "--logging.file.retention_hours=-1", "--dump"},
			invocation{on: map[string]bool{"check": true, "version": true, "dump": true},
				load: config.Args{File: "a.toml", Specs: []config.Spec{{Flag: "preset", Value: "tail,path=x"}},
					Overrides: []string{"--quiet", "--logging.level=debug", "--logging.file.retention_hours=-1"}}}},
	} {
		got, err := parseCommandLine(c.argv)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q:\n got %+v %v\nwant %+v", c.argv, got, err, c.want)
		}
	}
	for _, argv := range [][]string{{"-c"}, {"--config"}, {"--config="}, {"-c="}, {"-c", "--quiet"},
		{"-v"}, {"-qt"}, {"-u", "x"}, {"-config", "x"}, {"--logging.level"}, {"--logging.file.retention_hours", "-1"},
		{"--check=false"}, {"--version=true"}, {"--source"}, {"--sink=", "x"}, {"-p"}, {"--filter", "--sink", "x"}} {
		if _, err := parseCommandLine(argv); err == nil {
			t.Errorf("%q accepted", argv)
		}
	}
}

// lw takes no positional argument: a word no flag takes is named, not passed
// to config, whose bool would take it as its value
func TestAWordNoFlagTakesIsAnError(t *testing.T) {
	for _, c := range []struct {
		argv []string
		word string
	}{
		{[]string{"tail"}, "tail"}, {[]string{"-t", "x.toml"}, "x.toml"}, {[]string{"--quiet", "tls"}, "tls"},
		{[]string{"--status_reporter", "false"}, "false"}, {[]string{"--logging.level", "debug", "x"}, "x"},
		{[]string{"--color=never", "x"}, "x"}, {[]string{"--", "-c"}, "-c"}, {[]string{"-1"}, "-1"},
	} {
		_, err := parseCommandLine(c.argv)
		if err == nil || !strings.Contains(err.Error(), "unexpected argument "+strconv.Quote(c.word)) {
			t.Errorf("%q: %v", c.argv, err)
		}
	}
}

// An option lw does not know is an error, whatever follows it
func TestAnUnknownOptionIsAnError(t *testing.T) {
	for _, argv := range [][]string{{"--nosuch"}, {"--nosuch=1"}, {"--nosuch", "x"}, {"--check", "--nosuch"}} {
		_, err := parseCommandLine(argv)
		if err == nil || err.Error() != "unknown option --nosuch (lw --help lists them)" {
			t.Errorf("%q: %v", argv, err)
		}
	}
}

// flag writes a long flag with one dash; lw names it with two, then the usage
func TestFlagErrorsNameLongFlagsWithTwoDashes(t *testing.T) {
	for args, want := range map[string]string{
		"--user":   "lw auth add-user: flag needs an argument: --user\nUsage: ",
		"-u":       "lw auth add-user: flag needs an argument: -u\nUsage: ",
		"-nosuch":  "lw auth add-user: flag provided but not defined: --nosuch\nUsage: ",
		"--user=x": "lw auth add-user: --credentials is required\nUsage: ",
	} {
		code, _, stderr := runCommand(t, "auth", "add-user", args)
		if code != 2 || !strings.HasPrefix(stderr, want) || strings.Count(stderr, "Usage: ") != 1 {
			t.Errorf("lw auth add-user %s: exit %d:\n%s", args, code, stderr)
		}
	}
}

// Every subcommand's -h lists each flag once, GNU style, with its short form
// beside it: "  -u, --user NAME" or "      --credentials FILE"
func TestUsageListsEachFlagOnce(t *testing.T) {
	for _, c := range commands {
		for _, s := range c.subcommands {
			code, _, stderr := runCommand(t, c.name, s.name, "-h")
			fs := flag.NewFlagSet("", flag.ContinueOnError)
			s.define(fs)
			want := 0
			fs.VisitAll(func(f *flag.Flag) {
				if f.Usage == "" {
					return // an earlier name, unlisted
				}
				want++
				head := "      --" + f.Name
				for letter, short := range shorts {
					if short.long == f.Name {
						head = "  -" + letter + ", --" + f.Name
					}
				}
				if n := len(regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(head)+`( |$)`).FindAllString(stderr, -1)); n != 1 {
					t.Errorf("lw %s %s -h lists %q %d times:\n%s", c.name, s.name, head, n, stderr)
				}
			})
			if heads := regexp.MustCompile(`(?m)^  (-., |    )--`).FindAllString(stderr, -1); code != 0 || len(heads) != want {
				t.Errorf("lw %s %s -h: exit %d, %d flags listed, want %d", c.name, s.name, code, len(heads), want)
			}
		}
	}
}

// lw --help and its manual list every option lw takes, and only those, a short
// beside its long: lw's own, each configuration key, and the pipeline flags
func TestHelpAndManualListEveryOption(t *testing.T) {
	manual, err := os.ReadFile("../../doc/lw.1")
	if err != nil {
		t.Fatal(err)
	}
	var help bytes.Buffer
	printHelp(&help)
	options := options()
	// mdoc's Fl writes the first dash, and the others as \-
	fl := func(flag string) string { return regexp.QuoteMeta("Fl " + strings.ReplaceAll(flag[1:], "-", `\-`)) }
	for long, letter := range options {
		short, item := "    ", `^\.It (Fl \\-.*)?` // only long options before it
		if letter != "" {
			short, item = "-"+letter+", ", `^\.It `+fl("-"+letter)+` .*`
		}
		option := short + "--" + long
		if !regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(option) + `([^\w.-]|$)`).Match(help.Bytes()) {
			t.Errorf("lw --help does not list %s", strings.TrimSpace(option))
		}
		if !regexp.MustCompile(`(?m)` + item + fl("--"+long) + `([^\w.\\]|$)`).Match(manual) {
			t.Errorf("doc/lw.1 does not list %s", strings.TrimSpace(option))
		}
	}
	if heads := regexp.MustCompile(`(?m)^  (-., |    )--\w`).FindAll(help.Bytes(), -1); len(heads) != len(options) {
		t.Errorf("lw --help lists %d options, want %d", len(heads), len(options))
	}
}

// --dump prints a file that lw -c reads back to the same configuration, its
// console sinks still taking the top-level color
func TestDumpReadsBack(t *testing.T) {
	testLogger(t)
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.toml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--color", "--preset", "serve,listen=127.0.0.1:15841,tls=self,hosts=a.example,hosts=b.example",
		"--filter", `exclude,patterns=password=\S{8\,64}`, "--sink", "console", "--logging.level=debug"}
	cfg := loadTestConfig(t, empty, args...)
	var dump bytes.Buffer
	if code := dumpConfig(loadTestConfig(t, empty, args...), &dump); code != 0 {
		t.Fatalf("dump exit %d", code)
	}
	path := filepath.Join(dir, "dump.toml")
	if err := os.WriteFile(path, dump.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	again := loadTestConfig(t, path)
	if !reflect.DeepEqual(again.Pipelines, cfg.Pipelines) || again.Color != "always" || again.Logging.Level != "debug" ||
		strings.Count(dump.String(), "color = ") != 1 {
		t.Fatalf("dump does not read back:\n%s\n got %+v\nwant %+v", dump.String(), again.Pipelines, cfg.Pipelines)
	}
}

// Every preset expands to plugins that build, as lw --check builds them
func TestEveryPresetBuilds(t *testing.T) {
	testLogger(t)
	dir := t.TempDir()
	users, pass, empty := filepath.Join(dir, "users.toml"), filepath.Join(dir, "edge.pass"), filepath.Join(dir, "empty.toml")
	writeCredentials(t, users, "edge-01")
	for path, data := range map[string]string{pass: "password-edge-01\n", empty: ""} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pin := "sha256//" + strings.Repeat("A", 43) + "="
	samples := map[string]string{
		"pipe":       "pipe,format=txt",
		"tail":       "tail,path=" + dir,
		"serve":      "serve,path=" + filepath.Join(dir, "*.log") + ",listen=127.0.0.1:15841,tls=self,users=" + users + ",allow=127.0.0.0/8,deny=127.0.0.2",
		"edge":       "edge,to=127.0.0.1:15842,transport=http,pin=" + pin + ",user=edge-01,password_file=" + pass,
		"aggregator": "aggregator,listen=127.0.0.1:15843,users=" + users + ",out=" + filepath.Join(dir, "out") + ",allow=10.0.0.0/8,allow=127.0.0.1",
	}
	for _, p := range config.Presets() {
		sample, ok := samples[p.Name]
		if !ok {
			t.Errorf("preset %s has no sample here", p.Name)
			continue
		}
		if code := checkConfig(loadTestConfig(t, empty, "--preset", sample)); code != 0 {
			t.Errorf("%s: lw --check exit %d", sample, code)
		}
	}
}

// --host, the earlier name of lw tls cert --hosts, still sets the hosts
func TestTLSCertHostIsHosts(t *testing.T) {
	dir := t.TempDir()
	if code, _, stderr := runCommand(t, "tls", "ca", "--dir", dir); code != 0 {
		t.Fatalf("ca: exit %d: %s", code, stderr)
	}
	code, _, stderr := runCommand(t, "tls", "cert", "--ca-dir", dir, "--name", "agg", "--server", "--host", "a.example")
	if code != 0 || !strings.Contains(stderr, "for [a.example CN=agg]") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

// lw tls ca and lw tls cert write a chain a dialer verifies by the CA file,
// keys private, and never replace a file
func TestTLSCommandsIssueAVerifiableChain(t *testing.T) {
	dir := t.TempDir()
	steps := [][]string{
		{"ca", "-dir", dir, "-name", "test CA"},
		{"cert", "-ca-dir", dir, "-name", "agg", "-server", "-hosts", "127.0.0.1"},
	}
	for _, args := range steps {
		if code, _, stderr := runCommand(t, "tls", args...); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, stderr)
		}
	}
	for _, key := range []string{"ca.key", "agg.key"} {
		if fi, err := os.Stat(filepath.Join(dir, key)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", key, fi.Mode(), err)
		}
	}
	server, err := tlsx.Server(&config.TLSOptions{Enabled: true, CertFile: filepath.Join(dir, "agg.crt"), KeyFile: filepath.Join(dir, "agg.key")}, "")
	if err != nil {
		t.Fatal(err)
	}
	client, err := tlsx.Client(&config.TLSOptions{Enabled: true, CAFile: filepath.Join(dir, "ca.crt")}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := testutil.Handshake(t, server, client); err != nil {
		t.Fatalf("issued chain: %v", err)
	}
	if code, _, stderr := runCommand(t, "tls", steps[0]...); code != 1 || !strings.Contains(stderr, "exists") {
		t.Fatalf("second ca: exit %d: %s", code, stderr)
	}
}

// lw config init writes the shipped configuration to the file lw reads without
// -c, or to --out, says how lw finds it, and never replaces a file
func TestConfigInitWritesTheShippedFileOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LOGWISP_CONFIG_FILE", "")
	t.Setenv("LOGWISP_CONFIG_DIR", "")
	other := filepath.Join(t.TempDir(), "etc", "logwisp.toml")
	for _, c := range []struct {
		args []string
		hint string
	}{
		{[]string{"init"}, "lw reads it without -c"},
		{[]string{"init", "--out", other}, "lw -c " + other},
	} {
		if code, _, stderr := runCommand(t, "config", c.args...); code != 0 || !strings.Contains(stderr, c.hint) {
			t.Fatalf("lw config %v: exit %d: %s", c.args, code, stderr)
		}
		if code, _, stderr := runCommand(t, "config", c.args...); code != 1 || !strings.Contains(stderr, "exists") {
			t.Fatalf("lw config %v again: exit %d: %s", c.args, code, stderr)
		}
	}
	for _, path := range []string{filepath.Join(home, ".config", "logwisp", "logwisp.toml"), other} {
		if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, shipped.Sample) {
			t.Errorf("%s is not the shipped configuration: %v", path, err)
		}
	}
}

var update = flag.Bool("update", false, "rewrite the completion scripts: make completion")

// The installed completion scripts are what lw's tables generate
func TestCompletionScriptsAreCurrent(t *testing.T) {
	for _, sh := range shells {
		script := sh.script()
		path := filepath.Join("../../deploy/package/completion", sh.file)
		if *update {
			if err := os.WriteFile(path, script, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		have, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(have, script) {
			t.Errorf("%s is not what lw's tables generate: run make completion", path)
		}
	}
}
