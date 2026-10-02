// Package testutil provides standard-library fixtures shared by logwisp tests.
// Application packages must not import it.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// PKI is a throwaway CA with a server certificate for 127.0.0.1 and one client
// certificate, written as PEM files for plugins that load TLS from disk.
type PKI struct {
	CA, ServerCert, ServerKey, ClientCert, ClientKey string
}

// NewPKI issues the PKI into a test directory; clientCN names the client.
func NewPKI(t testing.TB, clientCN string) PKI {
	t.Helper()
	dir := t.TempDir()
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
	pki := PKI{CA: writePEM(t, dir, "ca.crt", "CERTIFICATE", caDER)}
	issue := func(name, cn string, serial int64, usage x509.ExtKeyUsage, ips []net.IP) (string, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return writePEM(t, dir, name+".crt", "CERTIFICATE", der), writePEM(t, dir, name+".key", "PRIVATE KEY", keyDER)
	}
	pki.ServerCert, pki.ServerKey = issue("server", "relay.internal", 2, x509.ExtKeyUsageServerAuth, []net.IP{net.IPv4(127, 0, 0, 1)})
	pki.ClientCert, pki.ClientKey = issue("client", clientCN, 3, x509.ExtKeyUsageClientAuth, nil)
	return pki
}

func writePEM(t testing.TB, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	WriteFile(t, path, string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})))
	return path
}
