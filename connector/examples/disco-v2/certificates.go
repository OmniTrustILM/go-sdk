package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"
)

// fixtureSeed fixes the signing key, so every instance builds the same
// certificates and a checkpointed position means the same item wherever the
// next call lands. It signs demonstration certificates only.
var fixtureSeed = [ed25519.SeedSize]byte{'d', 'i', 's', 'c', 'o', '-', 'v', '2', '-', 'e', 'x', 'a', 'm', 'p', 'l', 'e'}

// certificateFixtures creates public, self-signed demonstration certificates.
// Discovery exports certificate DER only.
func certificateFixtures() ([]string, error) {
	key := ed25519.NewKeyFromSeed(fixtureSeed[:])
	pub := key.Public()
	certs := make([]string, 0, 3)
	for n := int64(1); n <= 3; n++ {
		cert := &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: fmt.Sprintf("discovered-%d.example.test", n)}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature}
		der, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
		if e != nil {
			return nil, e
		}
		certs = append(certs, base64.StdEncoding.EncodeToString(der))
	}
	return certs, nil
}
