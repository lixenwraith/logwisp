package tlsx

import (
	"bytes"
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Certificates are ECDSA P-256, for lw tls and for listeners without files.
// A CA signs leaves only; a leaf lasts at most 397 days, the longest browsers
// accept, and never past its issuer.
const (
	CAValidity   = 10 * 365 * 24 * time.Hour
	LeafValidity = 397 * 24 * time.Hour
	pinPrefix    = "sha256//"
)

// processKey is the key of every generated listener certificate: reloads
// reissue certificates and keep it, so a pin holds until lw restarts.
var processKey = sync.OnceValues(NewKey)

func NewKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// NewCA makes a self-signed certificate authority that signs leaves only
func NewCA(name string, validity time.Duration) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := NewKey()
	if err != nil {
		return nil, nil, err
	}
	t, err := template(name, validity)
	if err != nil {
		return nil, nil, err
	}
	t.IsCA, t.MaxPathLenZero = true, true
	t.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	cert, err := sign(t, t, &key.PublicKey, key)
	return cert, key, err
}

// Leaf describes a certificate to issue. Hosts become DNS or IP SANs, which
// hostname verification reads; Name is the subject CN, which mtls reads.
type Leaf struct {
	Name           string
	Hosts          []string
	Server, Client bool
	Validity       time.Duration
}

// Issue signs a certificate for pub; a nil issuer makes it self-signed.
func (l Leaf) Issue(pub crypto.PublicKey, issuer *x509.Certificate, issuerKey crypto.Signer) (*x509.Certificate, error) {
	t, err := template(l.Name, l.Validity)
	if err != nil {
		return nil, err
	}
	t.KeyUsage = x509.KeyUsageDigitalSignature
	if l.Server {
		t.ExtKeyUsage = append(t.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if l.Client {
		t.ExtKeyUsage = append(t.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	for _, h := range l.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			t.IPAddresses = append(t.IPAddresses, ip)
		} else {
			t.DNSNames = append(t.DNSNames, h)
		}
	}
	if issuer == nil {
		return sign(t, t, pub, issuerKey)
	}
	if !time.Now().Before(issuer.NotAfter) {
		return nil, fmt.Errorf("tls: issuer %q expired on %s", issuer.Subject.CommonName, issuer.NotAfter.UTC().Format(time.DateOnly))
	}
	if t.NotAfter.After(issuer.NotAfter) {
		t.NotAfter = issuer.NotAfter
	}
	return sign(t, issuer, pub, issuerKey)
}

func template(name string, validity time.Duration) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-5 * time.Minute), // peers' clocks drift
		NotAfter:              now.Add(validity),
		BasicConstraintsValid: true,
	}, nil
}

func sign(t, parent *x509.Certificate, pub crypto.PublicKey, key crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, t, parent, pub, key)
	if err != nil {
		return nil, fmt.Errorf("tls: sign certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// LoadIssuer reads a CA certificate and its key, as lw tls ca writes them
func LoadIssuer(certFile, keyFile string) (*x509.Certificate, crypto.Signer, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: load issuer: %w", err)
	}
	ca, err := x509.ParseCertificate(pair.Certificate[0]) // Leaf is nil under GODEBUG=x509keypairleaf=0
	if err != nil {
		return nil, nil, fmt.Errorf("tls: load issuer: %w", err)
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok || !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, fmt.Errorf("tls: %s is no certificate authority", certFile)
	}
	return ca, signer, nil
}

// generated issues a listener certificate on the process key, self-signed
// or from the issuer files, for hosts and the names this machine answers to.
func generated(issuerCert, issuerKey, host string, hosts []string) (tls.Certificate, error) {
	key, err := processKey()
	if err != nil {
		return tls.Certificate{}, err
	}
	var issuer *x509.Certificate
	var signer crypto.Signer = key
	if issuerCert != "" {
		if issuer, signer, err = LoadIssuer(issuerCert, issuerKey); err != nil {
			return tls.Certificate{}, err
		}
	}
	name, _ := os.Hostname()
	all := slices.Clone(hosts)
	if ip := net.ParseIP(host); host != "" && (ip == nil || !ip.IsUnspecified()) {
		all = append(all, host)
	}
	if !strings.ContainsFunc(name, func(r rune) bool { return r > unicode.MaxASCII }) {
		all = append(all, name) // a DNS SAN is ASCII; the CN keeps any name
	}
	all = append(all, "localhost", "127.0.0.1", "::1")
	slices.Sort(all)
	all = slices.Compact(slices.DeleteFunc(all, func(h string) bool { return h == "" }))
	leaf, err := Leaf{Name: cmp.Or(name, "logwisp"), Hosts: all, Server: true, Validity: LeafValidity}.Issue(&key.PublicKey, issuer, signer)
	if err != nil {
		return tls.Certificate{}, err
	}
	chain := [][]byte{leaf.Raw}
	if issuer != nil {
		chain = append(chain, issuer.Raw) // an intermediate needs it to chain to its root
	}
	return tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}, nil
}

// PinSHA256 is the curl --pinnedpubkey form of a certificate's public key
func PinSHA256(c *x509.Certificate) string { return pin(c.RawSubjectPublicKeyInfo) }

func pinOfKey(k *ecdsa.PrivateKey) string {
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey) // P-256 always marshals
	return pin(der)
}

func pin(spki []byte) string {
	h := sha256.Sum256(spki)
	return pinPrefix + base64.StdEncoding.EncodeToString(h[:])
}

// verifyPins replaces chain verification: the server's key must hash to one
// of the ';'-separated pins. Its name and validity are not checked. Go skips
// it on a resumed session, and no dialer keeps a ClientSessionCache.
func verifyPins(s string) (func([][]byte, [][]*x509.Certificate) error, error) {
	var pins [][]byte
	for p := range strings.SplitSeq(s, ";") {
		b64, ok := strings.CutPrefix(strings.TrimSpace(p), pinPrefix)
		h, err := base64.StdEncoding.DecodeString(b64)
		if !ok || err != nil || len(h) != sha256.Size {
			return nil, fmt.Errorf("tls: pin_sha256 %q: want %sBASE64 of a SHA-256, ';' between several", p, pinPrefix)
		}
		pins = append(pins, h)
	}
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("tls: server sent no certificate")
		}
		c, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		if slices.ContainsFunc(pins, func(p []byte) bool { return bytes.Equal(p, h[:]) }) {
			return nil
		}
		// The type of a failed chain check: callers treat both as a refusal
		return &tls.CertificateVerificationError{UnverifiedCertificates: []*x509.Certificate{c},
			Err: fmt.Errorf("server key %s matches no tls.pin_sha256", PinSHA256(c))}
	}, nil
}

// EncodeCert and EncodeKey render PEM, the key as PKCS #8
func EncodeCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func EncodeKey(k crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
