// Package testutil provides standard-library fixtures shared by logwisp tests.
// Application packages must not import it.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ClearEnvPrefix isolates overrides while preserving the caller's environment.
// Like testing.Setenv, it must not be used by parallel tests.
func ClearEnvPrefix(t testing.TB, prefix string) {
	t.Helper()
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, prefix) {
			t.Setenv(key, value) // Register restoration before unsetting it.
			if err := os.Unsetenv(key); err != nil {
				t.Fatalf("unset fixture variable %s: %v", key, err)
			}
		}
	}
}

func WriteFile(t testing.TB, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write fixture %q: %v", path, err)
	}
}

// RequireIPv6 skips a test on a host without an IPv6 loopback
func RequireIPv6(t testing.TB) {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	ln.Close()
}

// PKI is a throwaway CA with a server certificate for 127.0.0.1 and ::1 and
// one client certificate, written as PEM files for plugins that load TLS from
// disk.
type PKI struct {
	CA, ServerCert, ServerKey, ClientCert, ClientKey string

	dir    string
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	serial int64
}

// NewPKI issues the PKI into a test directory; clientCN names the client.
func NewPKI(t testing.TB, clientCN string) *PKI {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "LogWisp Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pki := &PKI{dir: t.TempDir(), ca: ca, caKey: caKey, serial: 1}
	pki.CA = writePEM(t, pki.dir, "ca.crt", "CERTIFICATE", caDER)
	pki.ServerCert, pki.ServerKey = pki.Leaf(t, "server", "relay.internal", false)
	pki.ClientCert, pki.ClientKey = pki.Leaf(t, "client", clientCN, true)
	return pki
}

// Leaf issues another certificate from the same CA: a client certificate, or
// a server certificate valid for 127.0.0.1 and ::1.
func (p *PKI) Leaf(t testing.TB, name, cn string, client bool) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.serial++
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if client {
		tmpl.ExtKeyUsage, tmpl.IPAddresses = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writePEM(t, p.dir, name+".crt", "CERTIFICATE", der), writePEM(t, p.dir, name+".key", "PRIVATE KEY", keyDER)
}

// Handshake runs a TLS handshake between the two configurations over
// loopback TCP, whose buffers let a failing side's alert go out without a
// reader, and returns the client's error, else the server's.
func Handshake(t testing.TB, server, client *tls.Config) error {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		serverErr <- tls.Server(conn, server).Handshake()
	}()
	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	err = tls.Client(conn, client).Handshake()
	conn.Close()
	if serr := <-serverErr; err == nil {
		err = serr
	}
	return err
}

func writePEM(t testing.TB, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	WriteFile(t, path, string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})))
	return path
}
