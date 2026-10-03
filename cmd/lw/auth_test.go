package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lixenwraith/logwisp/internal/authz"

	"github.com/lixenwraith/auth"
)

func runAuthTest(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runAuth(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// writeCredentials writes users sharing a cheap Argon2 profile. add-user
// reuses the file's profile, so only a new file costs the default 64 MiB.
func writeCredentials(t *testing.T, path string, users ...string) *authz.Credentials {
	t.Helper()
	c := &authz.Credentials{DecoyKey: bytes.Repeat([]byte{7}, 32)}
	for _, u := range users {
		cred, err := auth.DeriveCredential(u, "password-"+u, bytes.Repeat([]byte{1}, 16), 1, 64, 1)
		if err != nil {
			t.Fatal(err)
		}
		c.Users = append(c.Users, cred)
	}
	data, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAddUserCreatesPrivateFilesWithAMatchingVerifier(t *testing.T) {
	dir := t.TempDir()
	creds, pass := filepath.Join(dir, "users.toml"), filepath.Join(dir, "edge-01.pass")
	code, stdout, stderr := runAuthTest(t, "add-user", "-credentials", creds, "-user", "edge-01", "-password-file", pass)
	if code != 0 || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr: %s", code, stdout, stderr)
	}
	for _, path := range []string{creds, pass} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s has mode %v, want 0600", path, fi.Mode().Perm())
		}
	}
	raw, err := os.ReadFile(pass)
	if err != nil || !strings.HasSuffix(string(raw), "\n") {
		t.Fatalf("password file %q, %v: want one line", raw, err)
	}
	c, err := authz.LoadCredentials(creds)
	if err != nil {
		t.Fatal(err)
	}
	password, err := authz.ReadPassword(pass)
	if err != nil {
		t.Fatal(err)
	}
	u := c.Users[0]
	want, err := auth.DeriveCredential("edge-01", password, u.Salt, u.ArgonTime, u.ArgonMemory, u.ArgonThreads)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want.StoredKey, u.StoredKey) || !bytes.Equal(want.ServerKey, u.ServerKey) {
		t.Fatal("stored verifier does not match the written password")
	}
}

func TestAddUserNeverReplacesAPasswordWithoutASource(t *testing.T) {
	dir := t.TempDir()
	creds, typo := filepath.Join(dir, "users.toml"), filepath.Join(dir, "edge01.pass")
	writeCredentials(t, creds, "edge-01")
	before, err := os.ReadFile(creds)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{nil, {"-password-file", typo}} {
		args := append([]string{"add-user", "-credentials", creds, "-user", "edge-01"}, extra...)
		if code, _, stderr := runAuthTest(t, args...); code != 1 {
			t.Fatalf("%v: exit %d, want 1; stderr: %s", extra, code, stderr)
		}
	}
	after, err := os.ReadFile(creds)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("credentials file changed (%v)", err)
	}
	if _, err := os.Stat(typo); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mistyped password file was created (%v)", err)
	}
}

// The daemon reads a link's target: a rewrite through the link updates it
func TestRewriteKeepsFileModeDecoyKeyAndLink(t *testing.T) {
	dir := t.TempDir()
	creds, target, pass := filepath.Join(dir, "users.toml"), filepath.Join(dir, "real.toml"), filepath.Join(dir, "edge-02.pass")
	orig := writeCredentials(t, target, "edge-01")
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, creds); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pass, []byte("correct horse battery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runAuthTest(t, "add-user", "-credentials", creds, "-user", "edge-02", "-password-file", pass); code != 0 {
		t.Fatalf("exit %d; stderr: %s", code, stderr)
	}
	if fi, err := os.Lstat(creds); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link replaced by a file (%v)", err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v, want 0640", fi.Mode().Perm())
	}
	c, err := authz.LoadCredentials(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.DecoyKey, orig.DecoyKey) || len(c.Users) != 2 || c.Users[1].Username != "edge-02" {
		t.Fatalf("decoy key kept: %v, users: %d", bytes.Equal(c.DecoyKey, orig.DecoyKey), len(c.Users))
	}
}

// A dangling link is refused rather than replaced: its missing target is the
// file the daemon would read
func TestAddUserRefusesADanglingLink(t *testing.T) {
	dir := t.TempDir()
	creds := filepath.Join(dir, "users.toml")
	if err := os.Symlink(filepath.Join(dir, "missing", "users.toml"), creds); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runAuthTest(t, "add-user", "-credentials", creds, "-user", "edge-01"); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if fi, err := os.Lstat(creds); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link replaced (%v)", err)
	}
}

// An empty file is how an operator picks the owner before the first user
func TestAddUserFillsAnEmptyFile(t *testing.T) {
	creds := filepath.Join(t.TempDir(), "users.toml")
	if err := os.WriteFile(creds, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runAuthTest(t, "add-user", "-credentials", creds, "-user", "edge-01"); code != 0 {
		t.Fatalf("exit %d; stderr: %s", code, stderr)
	}
	fi, err := os.Stat(creds)
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v (%v), want 0640", fi.Mode().Perm(), err)
	}
	if c, err := authz.LoadCredentials(creds); err != nil || len(c.Users) != 1 {
		t.Fatalf("credentials after add-user: %v", err)
	}
}

func TestRemoveUserRefusesTheLastUser(t *testing.T) {
	creds := filepath.Join(t.TempDir(), "users.toml")
	writeCredentials(t, creds, "edge-01", "edge-02")
	if code, _, stderr := runAuthTest(t, "remove-user", "-credentials", creds, "-user", "edge-01"); code != 0 {
		t.Fatalf("exit %d; stderr: %s", code, stderr)
	}
	if code, _, _ := runAuthTest(t, "remove-user", "-credentials", creds, "-user", "edge-02"); code != 1 {
		t.Fatalf("removing the last user: exit %d, want 1", code)
	}
	c, err := authz.LoadCredentials(creds)
	if err != nil || len(c.Users) != 1 || c.Users[0].Username != "edge-02" {
		t.Fatalf("users after refusal: %v", err)
	}
}

func TestAuthCommandHelpPrintsAuthUsage(t *testing.T) {
	code, _, stderr := runAuthTest(t, "add-user", "-h")
	if code != 0 || !strings.Contains(stderr, "Usage: lw auth add-user -credentials FILE") {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
}

// The login is posted to the -url given plus /auth: a link-local URL keeps
// its zone escaped, not turned into one that no longer parses
func TestTokenLogsInAtTheURLGiven(t *testing.T) {
	pass := filepath.Join(t.TempDir(), "edge-01.pass")
	if err := os.WriteFile(pass, []byte("correct horse battery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No such interface or listener: the dial fails at once, after the URL is formed
	for _, rawURL := range []string{"https://[fe80::1%25nosuchif0]:1", "https://127.0.0.1:1?"} {
		code, _, stderr := runAuthTest(t, "token", "-url", rawURL, "-user", "edge-01", "-password-file", pass)
		if want := `"` + strings.TrimSuffix(rawURL, "?") + `/auth"`; code != 1 || !strings.Contains(stderr, want) {
			t.Errorf("%s: exit %d, stderr: %s", rawURL, code, stderr)
		}
	}
}
