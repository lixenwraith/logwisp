package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/testutil"
	"github.com/lixenwraith/logwisp/internal/tlsx"
)

// lw's own flags: a short is its long flag, an unknown single-dash one fails,
// the last -c wins, a pipeline flag or --color takes the next argument unless
// it starts with '-', -- ends lw's flags, and a command is only the first
// argument. Everything else is a setting for config.
func TestCommandLineGrammar(t *testing.T) {
	for _, c := range []struct {
		argv []string
		want invocation
	}{
		{[]string{"-c", "a.toml", "--config=b.toml", "--quiet"}, invocation{load: config.Args{File: "b.toml", Overrides: []string{"--quiet"}}}},
		{[]string{"-c=a.toml", "--config", "b.toml"}, invocation{load: config.Args{File: "b.toml"}}},
		{[]string{"--source=null", "--sink", "http,port=1", "--filter", "--sink"},
			invocation{load: config.Args{Specs: []config.Spec{{Flag: "source", Value: "null"}, {Flag: "sink", Value: "http,port=1"}, {Flag: "filter"}, {Flag: "sink"}}}}},
		{[]string{"--preset", "tail,path=x", "--pipeline", "b"}, invocation{load: config.Args{Specs: []config.Spec{{Flag: "preset", Value: "tail,path=x"}, {Flag: "pipeline", Value: "b"}}}}},
		{[]string{"--color", "--color", "never", "--color=auto"}, invocation{load: config.Args{Overrides: []string{"--color=always", "--color=never", "--color=auto"}}}},
		{[]string{"--quiet", "--", "-c", "x", "--source", "null"}, invocation{load: config.Args{Overrides: []string{"--quiet", "--", "-c", "x", "--source", "null"}}}},
		{[]string{"--quiet", "-h"}, invocation{help: true, load: config.Args{Overrides: []string{"--quiet"}}}},
		{[]string{"-c", "-h"}, invocation{help: true}},
		{[]string{"help"}, invocation{help: true, load: config.Args{Overrides: []string{"help"}}}},
		{[]string{"tls", "ca", "-h"}, invocation{command: &commands[1], args: []string{"ca", "-h"}}},
		{[]string{"--quiet", "tls"}, invocation{load: config.Args{Overrides: []string{"--quiet", "tls"}}}},
		{[]string{"-q", "-t", "-V", "-p", "tail,path=x", "-c=a.toml", "--logging.file.retention_hours", "-1"},
			invocation{load: config.Args{File: "a.toml", Specs: []config.Spec{{Flag: "preset", Value: "tail,path=x"}},
				Overrides: []string{"--quiet", "--check", "--version", "--logging.file.retention_hours", "-1"}}}},
	} {
		got, err := parseCommandLine(c.argv)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q:\n got %+v %v\nwant %+v", c.argv, got, err, c.want)
		}
	}
	for _, argv := range [][]string{{"-c"}, {"--config"}, {"--config="}, {"-c="}, {"-c", "--quiet"},
		{"-v"}, {"-qt"}, {"-u", "x"}, {"-config", "x"}} {
		if _, err := parseCommandLine(argv); err == nil {
			t.Errorf("%q accepted", argv)
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

// lw tls ca and lw tls cert write a chain a dialer verifies by the CA file,
// keys private, and never replace a file
func TestTLSCommandsIssueAVerifiableChain(t *testing.T) {
	dir := t.TempDir()
	steps := [][]string{
		{"ca", "-dir", dir, "-name", "test CA"},
		{"cert", "-ca-dir", dir, "-name", "agg", "-server", "-host", "127.0.0.1"},
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
