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

// fixtureSeed makes every instance build the same certificates, so a
// checkpointed position means the same item wherever the next call lands.
var fixtureSeed = [ed25519.SeedSize]byte{'d', 'i', 's', 'c', 'o', '-', 'v', '2', '-', 'e', 'x', 'a', 'm', 'p', 'l', 'e'}

// fixture is a discoverable certificate and when the example pretends it was
// created, which is what discoverSince is compared with.
type fixture struct {
	ref     string
	der     string
	created time.Time
}

// certificateFixtures creates public, self-signed demonstration certificates,
// created a month apart in fixture order. Discovery exports certificate DER only.
func certificateFixtures() ([]fixture, error) {
	key := ed25519.NewKeyFromSeed(fixtureSeed[:])
	pub := key.Public()
	certs := make([]fixture, 0, 3)
	for n := int64(1); n <= 3; n++ {
		cert := &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: fmt.Sprintf("discovered-%d.example.test", n)}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature}
		der, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
		if e != nil {
			return nil, e
		}
		certs = append(certs, fixture{ref: fmt.Sprintf("example-certificate-%d", n), der: base64.StdEncoding.EncodeToString(der), created: time.Date(2026, time.Month(n), 1, 0, 0, 0, 0, time.UTC)})
	}
	return certs, nil
}
