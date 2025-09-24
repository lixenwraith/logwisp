// FILE: src/internal/tls/generator.go
package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

type CertGeneratorCommand struct{}

func NewCertGeneratorCommand() *CertGeneratorCommand {
	return &CertGeneratorCommand{}
}

func (c *CertGeneratorCommand) Execute(args []string) error {
	cmd := flag.NewFlagSet("tls", flag.ContinueOnError)

	// Subcommands
	var (
		genCA     = cmd.Bool("ca", false, "Generate CA certificate")
		genServer = cmd.Bool("server", false, "Generate server certificate")
		genClient = cmd.Bool("client", false, "Generate client certificate")
		selfSign  = cmd.Bool("self-signed", false, "Generate self-signed certificate")

		// Common options
		commonName = cmd.String("cn", "", "Common name (required)")
		org        = cmd.String("org", "LogWisp", "Organization")
		country    = cmd.String("country", "US", "Country code")
		validDays  = cmd.Int("days", 365, "Validity period in days")
		keySize    = cmd.Int("bits", 2048, "RSA key size")

		// Server/Client specific
		hosts     = cmd.String("hosts", "", "Comma-separated hostnames/IPs (server cert)")
		caFile    = cmd.String("ca-cert", "", "CA certificate file (for signing)")
		caKeyFile = cmd.String("ca-key", "", "CA key file (for signing)")

		// Output files
		certOut = cmd.String("cert-out", "", "Output certificate file")
		keyOut  = cmd.String("key-out", "", "Output key file")
	)

	cmd.Usage = func() {
		fmt.Fprintln(os.Stderr, "Generate TLS certificates for LogWisp")
		fmt.Fprintln(os.Stderr, "\nUsage: logwisp tls [options]")
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  # Generate self-signed certificate")
		fmt.Fprintln(os.Stderr, "  logwisp tls --self-signed --cn localhost --hosts localhost,127.0.0.1")
		fmt.Fprintln(os.Stderr, "  ")
		fmt.Fprintln(os.Stderr, "  # Generate CA certificate")
		fmt.Fprintln(os.Stderr, "  logwisp tls --ca --cn \"LogWisp CA\" --cert-out ca.crt --key-out ca.key")
		fmt.Fprintln(os.Stderr, "  ")
		fmt.Fprintln(os.Stderr, "  # Generate server certificate signed by CA")
		fmt.Fprintln(os.Stderr, "  logwisp tls --server --cn server.example.com --hosts server.example.com \\")
		fmt.Fprintln(os.Stderr, "              --ca-cert ca.crt --ca-key ca.key")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		cmd.PrintDefaults()
	}

	if err := cmd.Parse(args); err != nil {
		return err
	}

	// Validate common name
	if *commonName == "" {
		cmd.Usage()
		return fmt.Errorf("common name (--cn) is required")
	}

	// Route to appropriate generator
	switch {
	case *genCA:
		return c.generateCA(*commonName, *org, *country, *validDays, *keySize, *certOut, *keyOut)
	case *selfSign:
		return c.generateSelfSigned(*commonName, *org, *country, *hosts, *validDays, *keySize, *certOut, *keyOut)
	case *genServer:
		return c.generateServerCert(*commonName, *org, *country, *hosts, *caFile, *caKeyFile, *validDays, *keySize, *certOut, *keyOut)
	case *genClient:
		return c.generateClientCert(*commonName, *org, *country, *caFile, *caKeyFile, *validDays, *keySize, *certOut, *keyOut)
	default:
		cmd.Usage()
		return fmt.Errorf("specify certificate type: --ca, --self-signed, --server, or --client")
	}
}

// Crate and manage private CA
// TODO: Future implementation, not useful without implementation of generateServerCert, generateClientCert
func (c *CertGeneratorCommand) generateCA(cn, org, country string, days, bits int, certFile, keyFile string) error {
	// Generate RSA key
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{org},
			Country:      []string{country},
			CommonName:   cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Default output files
	if certFile == "" {
		certFile = "ca.crt"
	}
	if keyFile == "" {
		keyFile = "ca.key"
	}

	// Save certificate
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Save private key
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	fmt.Printf("✓ CA certificate generated:\n")
	fmt.Printf("  Certificate: %s\n", certFile)
	fmt.Printf("  Private key: %s (mode 0600)\n", keyFile)
	fmt.Printf("  Valid for:   %d days\n", days)
	fmt.Printf("  Common name: %s\n", cn)

	return nil
}

// Added parseHosts helper for IP/hostname parsing
func parseHosts(hostList string) ([]string, []net.IP) {
	var dnsNames []string
	var ipAddrs []net.IP

	if hostList == "" {
		return dnsNames, ipAddrs
	}

	hosts := strings.Split(hostList, ",")
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(h); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}

	return dnsNames, ipAddrs
}

// Generate self-signed certificate
func (c *CertGeneratorCommand) generateSelfSigned(cn, org, country, hosts string, days, bits int, certFile, keyFile string) error {
	// 1. Generate an RSA private key with the specified bit size
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// 2. Parse the hosts string into DNS names and IP addresses
	dnsNames, ipAddrs := parseHosts(hosts)

	// 3. Create the certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
			Country:      []string{country},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, days),

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:        false,

		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
	}

	// 4. Create the self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// 5. Default output filenames
	if certFile == "" {
		certFile = "server.crt"
	}
	if keyFile == "" {
		keyFile = "server.key"
	}

	// 6. Save the certificate with 0644 permissions
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	// 7. Save the private key with 0600 permissions
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	keyOut.Close()

	// 8. Print summary
	fmt.Printf("\n✓ Self-signed certificate generated:\n")
	fmt.Printf("  Certificate: %s\n", certFile)
	fmt.Printf("  Private Key: %s (mode 0600)\n", keyFile)
	fmt.Printf("  Valid for:   %d days\n", days)
	fmt.Printf("  Common Name: %s\n", cn)
	if len(hosts) > 0 {
		fmt.Printf("  Hosts (SANs): %s\n", hosts)
	}

	return nil
}

func (c *CertGeneratorCommand) generateServerCert(cn, org, country, hosts, caFile, caKeyFile string, days, bits int, certFile, keyFile string) error {
	return fmt.Errorf("server certificate generation with CA is not implemented; use --self-signed instead")
}

func (c *CertGeneratorCommand) generateClientCert(cn, org, country, caFile, caKeyFile string, days, bits int, certFile, keyFile string) error {
	return fmt.Errorf("client certificate generation with CA is not implemented; use --self-signed instead")
}