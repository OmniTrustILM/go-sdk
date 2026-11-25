package cms

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mustHex decodes a hex literal, ignoring whitespace.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// readGoldenHex reads a hex file from testdata.
func readGoldenHex(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return mustHex(t, string(raw))
}

// loadCertificate parses the first PEM certificate in testdata.
func loadCertificate(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s: no PEM block", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return cert
}

// certOptions tunes the certificate made by selfSigned.
type certOptions struct {
	serial *big.Int
	ski    []byte
}

// selfSigned makes a self-signed certificate for the given key pair.
func selfSigned(t *testing.T, pub crypto.PublicKey, priv crypto.Signer, opts certOptions) *x509.Certificate {
	t.Helper()
	serial := opts.serial
	if serial == nil {
		serial = big.NewInt(1)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "cms test"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          opts.ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
