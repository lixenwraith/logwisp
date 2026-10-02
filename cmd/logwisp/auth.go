package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"logwisp/internal/authz"
	"logwisp/internal/config"
	"logwisp/internal/tlsx"

	"github.com/lixenwraith/auth"
)

const reloadHint = "send SIGHUP to logwisp to apply (auto_reload does not watch the credentials file)"

// authCommand is one `logwisp auth` subcommand: define registers its flags
// and returns the command, which runs once they are parsed and checked.
type authCommand struct {
	name, synopsis, summary string
	required                []string
	define                  func(fs *flag.FlagSet) func(stdout, stderr io.Writer) error
}

var authCommands = []authCommand{
	{"add-user", "-credentials FILE -user NAME [-password-file FILE] [-generate]",
		"Add a user to a credentials file, or replace its password",
		[]string{"credentials", "user"}, defineAddUser},
	{"remove-user", "-credentials FILE -user NAME",
		"Remove a user from a credentials file",
		[]string{"credentials", "user"}, defineRemoveUser},
	{"token", "-url https://HOST:PORT -user NAME -password-file FILE [TLS flags]",
		"Log in to an http sink or http_chain source and print a bearer token",
		[]string{"url", "user", "password-file"}, defineToken},
	{"stream", "-addr HOST:PORT -user NAME -password-file FILE [TLS flags]",
		"Log in to a tcp sink and copy its stream to stdout until interrupted",
		[]string{"addr", "user", "password-file"}, defineStream},
}

// usageError is a command-line mistake: exit status 2 rather than 1
type usageError string

func (e usageError) Error() string { return string(e) }

// runAuth runs `logwisp auth` and returns the exit status: 0 success or
// help, 1 failure, 2 usage error.
func runAuth(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || slices.Contains([]string{"-h", "-help", "--help", "help"}, args[0]) {
		printAuthUsage(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	i := slices.IndexFunc(authCommands, func(c authCommand) bool { return c.name == args[0] })
	if i < 0 {
		fmt.Fprintf(stderr, "logwisp auth: unknown command %q\n\n", args[0])
		printAuthUsage(stderr)
		return 2
	}
	c := authCommands[i]
	fs := flag.NewFlagSet("logwisp auth "+c.name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s %s\n\n%s.\n\n", fs.Name(), c.synopsis, c.summary)
		fs.PrintDefaults()
	}
	run := c.define(fs)
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2 // already reported by flag, with the usage
	}
	err := checkArgs(fs, c.required)
	if err == nil {
		err = run(stdout, stderr)
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

func printAuthUsage(w io.Writer) {
	fmt.Fprint(w, "Usage: logwisp auth <command> [flags]\n\n")
	for _, c := range authCommands {
		fmt.Fprintf(w, "  %-12s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, "\nRun logwisp auth <command> -h for its flags. Credential changes apply on SIGHUP.\n"+
		"Exit status: 0 success, 1 failure, 2 usage error.\n")
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

func defineAddUser(fs *flag.FlagSet) func(stdout, stderr io.Writer) error {
	path := fs.String("credentials", "", "credentials `file`, created when missing")
	user := fs.String("user", "", "user `name`")
	passwordFile := fs.String("password-file", "", "read the password from `file` when it exists, else write a generated one there")
	generate := fs.Bool("generate", false, "generate a new password, replacing any -password-file; needed to rotate without one")
	return func(stdout, stderr io.Writer) error {
		creds, err := authz.LoadCredentials(*path)
		// An empty file is one created beforehand to choose its owner
		if fi, serr := os.Stat(*path); errors.Is(err, os.ErrNotExist) || serr == nil && fi.Size() == 0 {
			creds, err = &authz.Credentials{DecoyKey: make([]byte, 32)}, nil
			rand.Read(creds.DecoyKey)
		}
		if err != nil {
			return err
		}
		i := slices.IndexFunc(creds.Users, func(c *auth.Credential) bool { return c.Username == *user })

		var password string
		if *passwordFile != "" && !*generate {
			password, err = authz.ReadPassword(*passwordFile)
			switch {
			case err == nil && len(password) < 8:
				return fmt.Errorf("the password in %s is shorter than 8 bytes", *passwordFile)
			case err != nil && !errors.Is(err, os.ErrNotExist):
				return err
			}
		}
		generated := password == ""
		if generated && i >= 0 && !*generate {
			// A mistyped -password-file must not replace a working password
			return fmt.Errorf("user %q exists: replacing its password needs an existing -password-file or -generate", *user)
		}
		if generated {
			password = rand.Text()
		}

		var cred *auth.Credential
		if len(creds.Users) == 0 {
			cred, err = auth.NewCredential(*user, password)
		} else {
			// One profile per file: mixed ones would tell which users exist
			p := creds.Users[0]
			salt := make([]byte, len(p.Salt))
			rand.Read(salt)
			cred, err = auth.DeriveCredential(*user, password, salt, p.ArgonTime, p.ArgonMemory, p.ArgonThreads)
		}
		if err != nil {
			return err
		}
		done := "added user %q to %s\n"
		if i >= 0 {
			creds.Users[i] = cred
			done = "replaced the password of user %q in %s\n"
		} else {
			creds.Users = append(creds.Users, cred)
		}
		data, err := encodeCredentials(creds)
		if err != nil {
			return err
		}
		if generated && *passwordFile != "" {
			// First, so a failure leaves the verifiers untouched and a rerun
			// without -generate completes the change
			if err := writeAtomic(*passwordFile, []byte(password+"\n")); err != nil {
				return err
			}
			fmt.Fprintf(stderr, "wrote the generated password to %s\n", *passwordFile)
		}
		if err := writeAtomic(*path, data); err != nil {
			return err
		}
		if generated && *passwordFile == "" {
			fmt.Fprintf(stderr, "generated password for %q, shown once:\n", *user)
			fmt.Fprintln(stdout, password)
		}
		fmt.Fprintf(stderr, done+"%s\n", *user, *path, reloadHint)
		return nil
	}
}

func defineRemoveUser(fs *flag.FlagSet) func(stdout, stderr io.Writer) error {
	path := fs.String("credentials", "", "credentials `file`")
	user := fs.String("user", "", "user `name`")
	return func(_, stderr io.Writer) error {
		creds, err := authz.LoadCredentials(*path)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(creds.Users, func(c *auth.Credential) bool { return c.Username == *user })
		switch {
		case i < 0:
			return fmt.Errorf("no user %q in %s", *user, *path)
		case len(creds.Users) == 1:
			// The daemon rejects a file without users
			return fmt.Errorf("refusing to remove %q, the last user: remove the listener's auth block instead", *user)
		}
		creds.Users = slices.Delete(creds.Users, i, i+1)
		data, err := encodeCredentials(creds)
		if err == nil {
			err = writeAtomic(*path, data)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(stderr, "removed user %q from %s\n%s\n", *user, *path, reloadHint)
		return nil
	}
}

func defineToken(fs *flag.FlagSet) func(stdout, stderr io.Writer) error {
	rawURL := fs.String("url", "", "listener `URL`, https://HOST:PORT (with -unbound, a proxy's mount URL may carry a path)")
	user := fs.String("user", "", "user `name`")
	passwordFile := fs.String("password-file", "", "`file` holding the password")
	unbound := fs.Bool("unbound", false, "log in without channel binding, to an http sink behind a TLS-terminating proxy (auth.trusted_proxies)")
	tlsOpts := tlsFlags(fs)
	return func(stdout, _ io.Writer) error {
		u, err := url.Parse(*rawURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return usageError("-url must be https://HOST:PORT")
		}
		if u.Path = strings.TrimSuffix(u.Path, "/"); u.Path != "" && !*unbound {
			// TLS passthrough cannot route by path: only a terminating proxy can
			return usageError("-url takes a path only with -unbound")
		}
		tlsCfg, policy, err := dialPolicy(tlsOpts, u.Hostname(), *user, *passwordFile, authz.HTTP)
		if err != nil {
			return err
		}
		if *unbound {
			policy.Unbind()
		}
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "tcp4", addr)
				},
				TLSClientConfig:     tlsCfg,
				TLSHandshakeTimeout: tlsx.HandshakeTimeout,
			},
			// A redirect would carry the login to another endpoint
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		token, err := policy.Token(context.Background(), client, "https://"+u.Host+u.Path)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, token)
		return nil
	}
}

func defineStream(fs *flag.FlagSet) func(stdout, stderr io.Writer) error {
	addr := fs.String("addr", "", "tcp sink `address`, HOST:PORT")
	user := fs.String("user", "", "user `name`")
	passwordFile := fs.String("password-file", "", "`file` holding the password")
	tlsOpts := tlsFlags(fs)
	return func(stdout, _ io.Writer) error {
		host, _, err := net.SplitHostPort(*addr)
		if err != nil || host == "" {
			return usageError("-addr must be HOST:PORT")
		}
		tlsCfg, policy, err := dialPolicy(tlsOpts, host, *user, *passwordFile, authz.TCP)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		dctx, cancel := context.WithTimeout(ctx, tlsx.HandshakeTimeout)
		conn, err := (&tls.Dialer{Config: tlsCfg}).DialContext(dctx, "tcp4", *addr)
		cancel()
		if err == nil {
			defer conn.Close()
			var r io.Reader
			if r, err = policy.Greet(ctx, conn, ""); err == nil {
				defer context.AfterFunc(ctx, func() { conn.Close() })()
				if _, err = io.Copy(stdout, r); err == nil {
					err = errors.New("stream closed by server")
				}
			}
		}
		if ctx.Err() != nil {
			return nil // interrupted: how a viewer normally ends
		}
		return err
	}
}

// tlsFlags registers the dialer TLS flags. There is no insecure flag: an
// unverified server could relay the login.
func tlsFlags(fs *flag.FlagSet) *config.TLSOptions {
	o := &config.TLSOptions{Enabled: true}
	fs.StringVar(&o.CAFile, "ca-file", "", "CA `file` that verifies the server (default: system roots)")
	fs.StringVar(&o.ServerName, "server-name", "", "`name` the server certificate must carry (default: the host)")
	fs.StringVar(&o.CertFile, "cert-file", "", "client certificate `file`, for listeners with tls.client_auth")
	fs.StringVar(&o.KeyFile, "key-file", "", "client key `file`")
	return o
}

// dialPolicy builds what a scram dialer plugin builds from its tls and auth blocks
func dialPolicy(o *config.TLSOptions, host, user, passwordFile string, transport authz.Transport) (*tls.Config, *authz.Policy, error) {
	tlsCfg, err := tlsx.Client(o, host)
	if err != nil {
		return nil, nil, err
	}
	policy, err := authz.New(&config.AuthOptions{Type: authz.MethodSCRAM, Username: user, PasswordFile: passwordFile},
		tlsCfg, authz.RoleDialer, transport)
	if err != nil {
		return nil, nil, err
	}
	tlsCfg.VerifyConnection = policy.VerifyConnection
	return tlsCfg, policy, nil
}

// encodeCredentials renders creds and refuses what the daemon would not load
func encodeCredentials(creds *authz.Credentials) ([]byte, error) {
	data, err := creds.Marshal()
	if err == nil {
		_, err = authz.ParseCredentials(data)
	}
	return data, err
}

// writeAtomic replaces path (a symlink's target) by rename, so the daemon
// never reads a partial file, keeping an existing file's mode and owner (0600
// for a new one). A change that would lose the owner fails: the daemon could
// no longer read the file and would keep the old users.
func writeAtomic(path string, data []byte) error {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	mode, uid, gid := os.FileMode(0o600), -1, -1
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil && uid >= 0 {
		if err = tmp.Chown(uid, gid); err != nil {
			err = fmt.Errorf("%s: cannot keep owner %d:%d (run as root or that owner): %w", path, uid, gid, err)
		}
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}
