package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/joho/godotenv"
)

func generateClientCertFromEnv(clientCommonName, outputPrefix string) error {
	// Load .env
	err := godotenv.Load(".env")
	if err != nil {
		return fmt.Errorf("loading .env file: %w", err)
	}

	caCertB64 := os.Getenv("ROOT_CA_CERT_BASE64")
	caKeyB64 := os.Getenv("ROOT_CA_KEY_BASE64")
	if caCertB64 == "" || caKeyB64 == "" {
		return fmt.Errorf("missing ROOT_CA_CERT_BASE64 or ROOT_CA_KEY_BASE64")
	}

	// Decode and parse CA certificate
	caCertDER, err := base64.StdEncoding.DecodeString(caCertB64)
	if err != nil {
		return fmt.Errorf("decoding CA cert: %w", err)
	}
	caBlock, _ := pem.Decode(caCertDER)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid PEM block for CA cert")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parsing CA cert: %w", err)
	}

	// Decode and parse CA private key
	caKeyDER, err := base64.StdEncoding.DecodeString(caKeyB64)
	if err != nil {
		return fmt.Errorf("decoding CA key: %w", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyDER)
	if caKeyBlock == nil {
		return fmt.Errorf("invalid PEM block for CA key")
	}

	var caKey interface{}
	switch caKeyBlock.Type {
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	case "EC PRIVATE KEY":
		caKey, err = x509.ParseECPrivateKey(caKeyBlock.Bytes)
	default:
		return fmt.Errorf("unsupported CA private key type: %s", caKeyBlock.Type)
	}
	if err != nil {
		return fmt.Errorf("parsing CA private key: %w", err)
	}

	// Generate client ECDSA key
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating client key: %w", err)
	}

	// Create certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	clientTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: clientCommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign client cert with CA
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating client cert: %w", err)
	}

	// Save client cert
	certOut, err := os.Create(outputPrefix + ".crt")
	if err != nil {
		return fmt.Errorf("writing cert file: %w", err)
	}
	defer certOut.Close()
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	if err != nil {
		return fmt.Errorf("encoding cert PEM: %w", err)
	}

	// Save client private key
	keyOut, err := os.Create(outputPrefix + ".key")
	if err != nil {
		return fmt.Errorf("writing key file: %w", err)
	}
	defer keyOut.Close()
	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return fmt.Errorf("marshalling EC key: %w", err)
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes})
	if err != nil {
		return fmt.Errorf("encoding key PEM: %w", err)
	}

	fmt.Println("✅ Client cert and key written to", outputPrefix+".crt", "and", outputPrefix+".key")
	return nil
}

func main() {
	err := generateClientCertFromEnv("client1.wallet123", "./output/client1")
	if err != nil {
		fmt.Println("❌ Error:", err)
	}
}
