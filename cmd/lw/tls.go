package main

import (
	"crypto"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lixenwraith/logwisp/internal/tlsx"
)

// maxDays keeps a validity well inside time.Duration, whose overflow would
// date a certificate in the past
const maxDays = 36500

var tlsCommands = []subcommand{
	{"ca", "--dir DIR [--name NAME] [--days N]",
		"Create a certificate authority, DIR/ca.crt and DIR/ca.key, that signs certificates only",
		[]string{"dir"}, defineCA},
	{"cert", "--ca-dir DIR --name NAME [--hosts NAME,...] [--server] [--client] [--days N] [--out DIR]",
		"Issue a certificate and key, OUT/NAME.crt and OUT/NAME.key, from DIR/ca.crt and DIR/ca.key",
		[]string{"ca-dir", "name"}, defineCert},
}

func defineCA(fs *flag.FlagSet) func(stdout, stderr io.Writer) error {
	dir := fs.String("dir", "", "`dir`ectory to write ca.crt and ca.key in, created when missing")
	name := fs.String("name", "logwisp CA", "subject common `name`")
	days := fs.Int("days", int(tlsx.CAValidity/(24*time.Hour)), "validity in `n` days")
	return func(_, stderr io.Writer) error {
		if *days < 1 || *days > maxDays {
			return usageError(fmt.Sprintf("--days must be 1 to %d", maxDays))
		}
		cert, key, err := tlsx.NewCA(*name, time.Duration(*days)*24*time.Hour)
		if err != nil {
			return err
		}
		if err := writePair(*dir, "ca", cert, key); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "wrote %s and %s, valid until %s\n"+
			"ca.crt verifies: dialers' tls.ca_file, listeners' tls.client_ca_file; with ca.key, it signs: lw tls cert, tls.issuer_cert_file\n",
			filepath.Join(*dir, "ca.crt"), filepath.Join(*dir, "ca.key"), cert.NotAfter.UTC().Format(time.DateOnly))
		return nil
	}
}

func defineCert(fs *flag.FlagSet) func(stdout, stderr io.Writer) error {
	caDir := fs.String("ca-dir", "", "`dir`ectory holding ca.crt and ca.key (lw tls ca)")
	name := fs.String("name", "", "subject common `name`, the mtls identity, and the file names")
	hosts := fs.String("hosts", "", "DNS `names` and IP addresses, ',' between them (default with --server: --name)")
	fs.Var(fs.Lookup("hosts").Value, "host", "") // its earlier name, unlisted like a short
	server := fs.Bool("server", false, "for listeners (TLS server authentication)")
	client := fs.Bool("client", false, "for dialers presenting a certificate (TLS client authentication)")
	days := fs.Int("days", int(tlsx.LeafValidity/(24*time.Hour)), "validity in `n` days, at most the CA's")
	out := fs.String("out", "", "`dir`ectory to write in (default: --ca-dir)")
	return func(_, stderr io.Writer) error {
		switch {
		case !*server && !*client:
			return usageError("--server, --client or both is required")
		case *days < 1 || *days > maxDays:
			return usageError(fmt.Sprintf("--days must be 1 to %d", maxDays))
		case strings.ContainsAny(*name, `/\`) || *name == "ca" || strings.HasPrefix(*name, "."):
			return usageError(fmt.Sprintf("--name %q cannot name the files", *name))
		}
		issuer, signer, err := tlsx.LoadIssuer(filepath.Join(*caDir, "ca.crt"), filepath.Join(*caDir, "ca.key"))
		if err != nil {
			return err
		}
		leaf := tlsx.Leaf{Name: *name, Server: *server, Client: *client, Validity: time.Duration(*days) * 24 * time.Hour}
		for h := range strings.SplitSeq(*hosts, ",") {
			if h = strings.TrimSpace(h); h != "" {
				leaf.Hosts = append(leaf.Hosts, h)
			}
		}
		if len(leaf.Hosts) == 0 && *server {
			leaf.Hosts = []string{*name}
		}
		key, err := tlsx.NewKey()
		if err != nil {
			return err
		}
		cert, err := leaf.Issue(&key.PublicKey, issuer, signer)
		if err != nil {
			return err
		}
		dir := *out
		if dir == "" {
			dir = *caDir
		}
		if err := writePair(dir, *name, cert, key); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "wrote %s and %s for %v, valid until %s, pin_sha256 %s\n",
			filepath.Join(dir, *name+".crt"), filepath.Join(dir, *name+".key"),
			append(leaf.Hosts, "CN="+*name), cert.NotAfter.UTC().Format(time.DateOnly), tlsx.PinSHA256(cert))
		return nil
	}
}

// writePair writes NAME.crt (0644) and NAME.key (0600) in dir, refusing to
// replace either: a reissued key would silently break every pin and peer.
func writePair(dir, name string, cert *x509.Certificate, key crypto.PrivateKey) error {
	keyPEM, err := tlsx.EncodeKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s exists; remove it to replace it", p)
		}
	}
	if err := writeNew(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeNew(certPath, tlsx.EncodeCert(cert), 0o644); err != nil {
		os.Remove(keyPath)
		return err
	}
	return nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}
