package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv"
)

func main() {

	GenerateCertificate("example.netsepio.com")
	VerifyCertificate()

}

func VerifyCertificate() {

	if err := godotenv.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load .env file: %v\n", err)
	}

	caCertBase64 := os.Getenv("ROOT_CA_CERT_BASE64")
	caKeyBase64 := os.Getenv("ROOT_CA_KEY_BASE64")

	dir := "certs/leaf"

	leafCertPath := filepath.Join(dir, "leaf_cert.pem")
	leafKeyPath := filepath.Join(dir, "leaf_key.pem")

	// Just to show the key is read (optional)
	leafKeyPEM, err := os.ReadFile(leafKeyPath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Loaded leaf private key file (%s), length: %d bytes\n", leafKeyPath, len(leafKeyPEM))

	// Verify leaf cert
	if err := verifyCertFromFiles(caCertBase64, caKeyBase64, leafCertPath); err != nil {
		panic("Verification failed: " + err.Error())
	}

	fmt.Println("Leaf certificate verified successfully!")

}

func GenerateCertificate(domain string) {

	if err := godotenv.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load .env file: %v\n", err)
	}

	caCertBase64 := os.Getenv("ROOT_CA_CERT_BASE64")
	caKeyBase64 := os.Getenv("ROOT_CA_KEY_BASE64")

	caCertPEM, err := base64.StdEncoding.DecodeString(caCertBase64)
	if err != nil {
		panic(err)
	}
	caKeyPEM, err := base64.StdEncoding.DecodeString(caKeyBase64)
	if err != nil {
		panic(err)
	}

	caCert, caKey, err := parseCACertKey(caCertPEM, caKeyPEM)
	if err != nil {
		panic(err)
	}

	fmt.Println("Loaded CA certificate and key successfully.")

	leafCertPEM, leafKeyPEM, err := generateSignedCert(caCert, caKey, domain)
	if err != nil {
		panic(err)
	}

	// Create folder if not exist
	dir := "certs/leaf"
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		panic(err)
	}

	leafCertPath := filepath.Join(dir, "leaf_cert.pem")
	leafKeyPath := filepath.Join(dir, "leaf_key.pem")

	if err := os.WriteFile(leafCertPath, leafCertPEM, 0644); err != nil {
		panic(err)
	}
	if err := os.WriteFile(leafKeyPath, leafKeyPEM, 0600); err != nil {
		panic(err)
	}

	fmt.Printf("Leaf certificate and key saved:\n - %s\n - %s\n", leafCertPath, leafKeyPath)

}

func generateSignedCert(caCert *x509.Certificate, caKey ed25519.PrivateKey, commonName string) ([]byte, []byte, error) {
	_, leafPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, leafPrivKey.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyBytes, err := x509.MarshalPKCS8PrivateKey(leafPrivKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	return certPEM, keyPEM, nil
}

func parseCACertKey(certPEM, keyPEM []byte) (*x509.Certificate, ed25519.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("invalid CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("invalid CA private key PEM")
	}
	keyParsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	edPrivKey, ok := keyParsed.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA private key is not Ed25519")
	}

	return caCert, edPrivKey, nil
}

func verifyCertFromFiles(caCertBase64, caKeyBase64, leafCertPath string) error {

	caCertPEM, err := base64.StdEncoding.DecodeString(caCertBase64)
	if err != nil {
		panic(err)
	}

	caKeyPEM, err := base64.StdEncoding.DecodeString(caKeyBase64)
	if err != nil {
		panic(err)
	}

	caCert, _, err := parseCACertKey(caCertPEM, caKeyPEM)
	if err != nil {
		panic(err)
	}

	leafCertPEM, err := os.ReadFile(leafCertPath)
	if err != nil {
		return fmt.Errorf("failed to read leaf cert file: %w", err)
	}

	block, _ := pem.Decode(leafCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid leaf cert PEM")
	}
	leafCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := leafCert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify leaf certificate: %w", err)
	}

	return nil
}
