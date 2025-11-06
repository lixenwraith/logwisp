// FILE: src/cmd/logwisp/commands/tls.go
package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// TLSCommand handles the generation of TLS certificates.
type TLSCommand struct {
	output io.Writer
	errOut io.Writer
}

// NewTLSCommand creates a new TLS command handler.
func NewTLSCommand() *TLSCommand {
	return &TLSCommand{
		output: os.Stdout,
		errOut: os.Stderr,
	}
}

// Execute parses flags and routes to the appropriate certificate generation function.
func (tc *TLSCommand) Execute(args []string) error {
	cmd := flag.NewFlagSet("tls", flag.ContinueOnError)
	cmd.SetOutput(tc.errOut)

	// Certificate type flags
	var (
		genCA     = cmd.Bool("ca", false, "Generate CA certificate")
		genServer = cmd.Bool("server", false, "Generate server certificate")
		genClient = cmd.Bool("client", false, "Generate client certificate")
		selfSign  = cmd.Bool("self-signed", false, "Generate self-signed certificate")

		// Common options - short forms
		commonName = cmd.String("cn", "", "Common name (required)")
		org        = cmd.String("o", "LogWisp", "Organization")
		country    = cmd.String("c", "US", "Country code")
		validDays  = cmd.Int("d", 365, "Validity period in days")
		keySize    = cmd.Int("b", 2048, "RSA key size")

		// Common options - long forms
		commonNameLong = cmd.String("common-name", "", "Common name (required)")
		orgLong        = cmd.String("org", "LogWisp", "Organization")
		countryLong    = cmd.String("country", "US", "Country code")
		validDaysLong  = cmd.Int("days", 365, "Validity period in days")
		keySizeLong    = cmd.Int("bits", 2048, "RSA key size")

		// Server/Client specific - short forms
		hosts  = cmd.String("h", "", "Comma-separated hostnames/IPs")
		caFile = cmd.String("ca-cert", "", "CA certificate file")
		caKey  = cmd.String("ca-key", "", "CA key file")

		// Server/Client specific - long forms
		hostsLong = cmd.String("hosts", "", "Comma-separated hostnames/IPs")

		// Output files
		certOut = cmd.String("cert-out", "", "Output certificate file")
		keyOut  = cmd.String("key-out", "", "Output key file")
	)

	cmd.Usage = func() {
		fmt.Fprintln(tc.errOut, "Generate TLS certificates for LogWisp")
		fmt.Fprintln(tc.errOut, "\nUsage: logwisp tls [options]")
		fmt.Fprintln(tc.errOut, "\nExamples:")
		fmt.Fprintln(tc.errOut, "  # Generate self-signed certificate")
		fmt.Fprintln(tc.errOut, "  logwisp tls --self-signed --cn localhost --hosts localhost,127.0.0.1")
		fmt.Fprintln(tc.errOut, "  ")
		fmt.Fprintln(tc.errOut, "  # Generate CA certificate")
		fmt.Fprintln(tc.errOut, "  logwisp tls --ca --cn \"LogWisp CA\" --cert-out ca.crt --key-out ca.key")
		fmt.Fprintln(tc.errOut, "  ")
		fmt.Fprintln(tc.errOut, "  # Generate server certificate signed by CA")
		fmt.Fprintln(tc.errOut, "  logwisp tls --server --cn server.example.com --hosts server.example.com \\")
		fmt.Fprintln(tc.errOut, "              --ca-cert ca.crt --ca-key ca.key")
		fmt.Fprintln(tc.errOut, "\nOptions:")
		cmd.PrintDefaults()
		fmt.Fprintln(tc.errOut)
	}

	if err := cmd.Parse(args); err != nil {
		return err
	}

	// Check for unparsed arguments
	if cmd.NArg() > 0 {
		return fmt.Errorf("unexpected argument(s): %s", strings.Join(cmd.Args(), " "))
	}

	// Merge short and long options
	finalCN := coalesceString(*commonName, *commonNameLong)
	finalOrg := coalesceString(*org, *orgLong, "LogWisp")
	finalCountry := coalesceString(*country, *countryLong, "US")
	finalDays := coalesceInt(*validDays, *validDaysLong, 365)
	finalKeySize := coalesceInt(*keySize, *keySizeLong, 2048)
	finalHosts := coalesceString(*hosts, *hostsLong)
	finalCAFile := *caFile   // no short form
	finalCAKey := *caKey     // no short form
	finalCertOut := *certOut // no short form
	finalKeyOut := *keyOut   // no short form

	// Validate common name
	if finalCN == "" {
		cmd.Usage()
		return fmt.Errorf("common name (--cn) is required")
	}

	// Validate RSA key size
	if finalKeySize != 2048 && finalKeySize != 3072 && finalKeySize != 4096 {
		return fmt.Errorf("invalid key size: %d (valid: 2048, 3072, 4096)", finalKeySize)
	}

	// Route to appropriate generator
	switch {
	case *genCA:
		return tc.generateCA(finalCN, finalOrg, finalCountry, finalDays, finalKeySize, finalCertOut, finalKeyOut)
	case *selfSign:
		return tc.generateSelfSigned(finalCN, finalOrg, finalCountry, finalHosts, finalDays, finalKeySize, finalCertOut, finalKeyOut)
	case *genServer:
		return tc.generateServerCert(finalCN, finalOrg, finalCountry, finalHosts, finalCAFile, finalCAKey, finalDays, finalKeySize, finalCertOut, finalKeyOut)
	case *genClient:
		return tc.generateClientCert(finalCN, finalOrg, finalCountry, finalCAFile, finalCAKey, finalDays, finalKeySize, finalCertOut, finalKeyOut)
	default:
		cmd.Usage()
		return fmt.Errorf("specify certificate type: --ca, --self-signed, --server, or --client")
	}
}

// Description returns a brief one-line description of the command.
func (tc *TLSCommand) Description() string {
	return "Generate TLS certificates (CA, server, client, self-signed)"
}

// Help returns the detailed help text for the command.
func (tc *TLSCommand) Help() string {
	return `TLS Command - Generate TLS certificates for LogWisp

Usage: 
  logwisp tls [options]

Certificate Types:
  --ca           Generate Certificate Authority (CA) certificate
  --server       Generate server certificate (requires CA or self-signed)
  --client       Generate client certificate (for mTLS)
  --self-signed  Generate self-signed certificate (single cert for testing)

Common Options:
  --cn, --common-name <name>     Common Name (required)
  -o, --org <organization>       Organization name (default: "LogWisp")
  -c, --country <code>           Country code (default: "US")
  -d, --days <number>            Validity period in days (default: 365)
  -b, --bits <size>              RSA key size (default: 2048)

Server Certificate Options:
  -h, --hosts <list>             Comma-separated hostnames/IPs
                                 Example: "localhost,10.0.0.1,example.com"
  --ca-cert <file>       CA certificate file (for signing)
  --ca-key <file>        CA key file (for signing)

Output Options:
  --cert-out <file>      Output certificate file (default: stdout)
  --key-out <file>       Output private key file (default: stdout)

Examples:
  # Generate self-signed certificate for testing
  logwisp tls --self-signed --cn localhost --hosts "localhost,127.0.0.1" \
    --cert-out server.crt --key-out server.key
  
  # Generate CA certificate
  logwisp tls --ca --cn "LogWisp CA" --days 3650 \
    --cert-out ca.crt --key-out ca.key
  
  # Generate server certificate signed by CA
  logwisp tls --server --cn "logwisp.example.com" \
    --hosts "logwisp.example.com,10.0.0.100" \
    --ca-cert ca.crt --ca-key ca.key \
    --cert-out server.crt --key-out server.key
  
  # Generate client certificate for mTLS
  logwisp tls --client --cn "client1" \
    --ca-cert ca.crt --ca-key ca.key \
    --cert-out client.crt --key-out client.key

Security Notes:
  - Keep private keys secure and never share them
  - Use 2048-bit RSA minimum, 3072 or 4096 for higher security
  - For production, use certificates from a trusted CA
  - Self-signed certificates are only for development/testing
  - Rotate certificates before expiration
`
}

// generateCA creates a new Certificate Authority (CA) certificate and private key.
func (tc *TLSCommand) generateCA(cn, org, country string, days, bits int, certFile, keyFile string) error {
	// Generate RSA key
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Create certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			Country:      []string{country},
			CommonName:   cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
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
	if err := saveCert(certFile, certDER); err != nil {
		return err
	}
	if err := saveKey(keyFile, priv); err != nil {
		return err
	}

	fmt.Printf("✓ CA certificate generated:\n")
	fmt.Printf("  Certificate: %s\n", certFile)
	fmt.Printf("  Private key: %s (mode 0600)\n", keyFile)
	fmt.Printf("  Valid for:   %d days\n", days)
	fmt.Printf("  Common name: %s\n", cn)

	return nil
}

// generateSelfSigned creates a new self-signed server certificate and private key.
func (tc *TLSCommand) generateSelfSigned(cn, org, country, hosts string, days, bits int, certFile, keyFile string) error {
	// 1. Generate an RSA private key with the specified bit size
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// 2. Parse the hosts string into DNS names and IP addresses
	dnsNames, ipAddrs := parseHosts(hosts)

	// 3. Create the certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

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
	if err := saveCert(certFile, certDER); err != nil {
		return err
	}
	if err := saveKey(keyFile, priv); err != nil {
		return err
	}

	// 7. Print summary
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

// generateServerCert creates a new server certificate signed by a provided CA.
func (tc *TLSCommand) generateServerCert(cn, org, country, hosts, caFile, caKeyFile string, days, bits int, certFile, keyFile string) error {
	caCert, caKey, err := loadCA(caFile, caKeyFile)
	if err != nil {
		return err
	}

	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("failed to generate server private key: %w", err)
	}

	dnsNames, ipAddrs := parseHosts(hosts)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	certExpiry := time.Now().AddDate(0, 0, days)
	if certExpiry.After(caCert.NotAfter) {
		return fmt.Errorf("certificate validity period (%d days) exceeds CA expiry (%s)", days, caCert.NotAfter.Format(time.RFC3339))
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
			Country:      []string{country},
		},
		NotBefore:   time.Now(),
		NotAfter:    certExpiry,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to sign server certificate: %w", err)
	}

	if certFile == "" {
		certFile = "server.crt"
	}
	if keyFile == "" {
		keyFile = "server.key"
	}

	if err := saveCert(certFile, certDER); err != nil {
		return err
	}
	if err := saveKey(keyFile, priv); err != nil {
		return err
	}

	fmt.Printf("\n✓ Server certificate generated:\n")
	fmt.Printf("  Certificate: %s\n", certFile)
	fmt.Printf("  Private Key: %s (mode 0600)\n", keyFile)
	fmt.Printf("  Signed by:   CN=%s\n", caCert.Subject.CommonName)
	if len(hosts) > 0 {
		fmt.Printf("  Hosts (SANs): %s\n", hosts)
	}
	return nil
}

// generateClientCert creates a new client certificate signed by a provided CA for mTLS.
func (tc *TLSCommand) generateClientCert(cn, org, country, caFile, caKeyFile string, days, bits int, certFile, keyFile string) error {
	caCert, caKey, err := loadCA(caFile, caKeyFile)
	if err != nil {
		return err
	}

	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("failed to generate client private key: %w", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	certExpiry := time.Now().AddDate(0, 0, days)
	if certExpiry.After(caCert.NotAfter) {
		return fmt.Errorf("certificate validity period (%d days) exceeds CA expiry (%s)", days, caCert.NotAfter.Format(time.RFC3339))
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
			Country:      []string{country},
		},
		NotBefore:   time.Now(),
		NotAfter:    certExpiry,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to sign client certificate: %w", err)
	}

	if certFile == "" {
		certFile = "client.crt"
	}
	if keyFile == "" {
		keyFile = "client.key"
	}

	if err := saveCert(certFile, certDER); err != nil {
		return err
	}
	if err := saveKey(keyFile, priv); err != nil {
		return err
	}

	fmt.Printf("\n✓ Client certificate generated:\n")
	fmt.Printf("  Certificate: %s\n", certFile)
	fmt.Printf("  Private Key: %s (mode 0600)\n", keyFile)
	fmt.Printf("  Signed by:   CN=%s\n", caCert.Subject.CommonName)
	return nil
}

// loadCA reads and parses a CA certificate and its corresponding private key from files.
func loadCA(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load CA certificate
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("invalid CA certificate format")
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Load CA private key
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("invalid CA key format")
	}

	var caKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse CA key: %w", err)
		}
		var ok bool
		caKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("CA key is not RSA")
		}
	default:
		return nil, nil, fmt.Errorf("unsupported CA key type: %s", keyBlock.Type)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Verify CA certificate is actually a CA
	if !caCert.IsCA {
		return nil, nil, fmt.Errorf("certificate is not a CA certificate")
	}

	return caCert, caKey, nil
}

// saveCert saves a DER-encoded certificate to a file in PEM format.
func saveCert(filename string, certDER []byte) error {
	certFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Set readable permissions
	if err := os.Chmod(filename, 0644); err != nil {
		return fmt.Errorf("failed to set certificate permissions: %w", err)
	}

	return nil
}

// saveKey saves an RSA private key to a file in PEM format with restricted permissions.
func saveKey(filename string, key *rsa.PrivateKey) error {
	keyFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	privKeyDER := x509.MarshalPKCS1PrivateKey(key)
	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyDER,
	}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Set restricted permissions for private key
	if err := os.Chmod(filename, 0600); err != nil {
		return fmt.Errorf("failed to set key permissions: %w", err)
	}

	return nil
}

// parseHosts splits a comma-separated string of hosts into slices of DNS names and IP addresses.
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