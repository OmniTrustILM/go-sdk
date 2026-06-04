package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// CA is a real, in-memory X.509 certificate authority. At construction it
// generates a P-256 root key and a self-signed root certificate, and from
// then on signs real PKCS#10 CSRs, tracks issued and revoked serials, and
// produces signed CRLs via x509.CreateRevocationList.
//
// Everything lives in memory: a restart discards the root key and every
// record. Not for production — it exists to give the authority-v3 example
// connector a genuinely working backend instead of placeholder blobs.
type CA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate

	mu            sync.RWMutex
	serialCounter int64
	issued        map[string]*issuedCert    // serial (decimal string) -> record
	revoked       map[string]revocationInfo // serial -> revocation record
	registrations map[string]*registration  // registration id -> identity
	crlNumber     int64
}

// issuedCert records one signed certificate.
type issuedCert struct {
	cert    *x509.Certificate
	der     []byte
	revoked bool
}

// revocationInfo records one revocation for CRL generation.
type revocationInfo struct {
	serial *big.Int
	when   time.Time
	reason int // RFC 5280 CRLReason code
}

// registration is a pre-registered certificate identity created via
// /certificates/register and consumed by a later issue carrying the
// registration id in meta.
type registration struct {
	id         string
	subjectDn  string
	subjectAlt string
	consumed   bool
}

// NewCA generates the root key + self-signed root certificate.
func NewCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"OmniTrust Example"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign root: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse root: %w", err)
	}
	return &CA{
		key:           key,
		cert:          cert,
		serialCounter: 1, // serial 1 is the root itself
		issued:        make(map[string]*issuedCert),
		revoked:       make(map[string]revocationInfo),
		registrations: make(map[string]*registration),
	}, nil
}

// RootDER returns the DER bytes of the root certificate.
func (ca *CA) RootDER() []byte {
	return ca.cert.Raw
}

// Sign signs the CSR and returns the issued certificate's DER bytes plus its
// serial as a decimal string. When subjectOverride is non-nil the CSR's
// subject is replaced (used for issuance against a prior registration).
func (ca *CA) Sign(csr *x509.CertificateRequest, validity time.Duration, subjectOverride *pkix.Name) (der []byte, serial string, err error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("CSR signature invalid: %w", err)
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()

	ca.serialCounter++
	sn := big.NewInt(ca.serialCounter)

	subject := csr.Subject
	if subjectOverride != nil {
		subject = *subjectOverride
	}

	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               subject,
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, "", fmt.Errorf("sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", fmt.Errorf("parse issued certificate: %w", err)
	}
	serial = sn.String()
	ca.issued[serial] = &issuedCert{cert: cert, der: der}
	return der, serial, nil
}

// Lookup returns the issued certificate record for a serial, or nil.
func (ca *CA) Lookup(serial string) *issuedCert {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.issued[serial]
}

// Revoke marks an issued certificate revoked with the given RFC 5280 reason
// code. Returns false when the serial is unknown; revoking an already-revoked
// certificate is idempotent and returns true.
func (ca *CA) Revoke(serial string, reason int) bool {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	rec, ok := ca.issued[serial]
	if !ok {
		return false
	}
	if rec.revoked {
		return true
	}
	rec.revoked = true
	ca.revoked[serial] = revocationInfo{
		serial: rec.cert.SerialNumber,
		when:   time.Now(),
		reason: reason,
	}
	return true
}

// CRL builds and signs a fresh full CRL over every revoked serial.
func (ca *CA) CRL() ([]byte, error) {
	ca.mu.Lock()
	ca.crlNumber++
	num := big.NewInt(ca.crlNumber)
	entries := make([]x509.RevocationListEntry, 0, len(ca.revoked))
	for _, ri := range ca.revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   ri.serial,
			RevocationTime: ri.when,
			ReasonCode:     ri.reason,
		})
	}
	ca.mu.Unlock()

	tmpl := &x509.RevocationList{
		Number:                    num,
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, ca.cert, ca.key)
}

// AddRegistration stores a pre-registered identity and returns its id.
func (ca *CA) AddRegistration(id, subjectDn, subjectAlt string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.registrations[id] = &registration{id: id, subjectDn: subjectDn, subjectAlt: subjectAlt}
}

// TakeRegistration fetches a registration by id and marks it consumed.
// Returns nil when unknown or already consumed.
func (ca *CA) TakeRegistration(id string) *registration {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	reg, ok := ca.registrations[id]
	if !ok || reg.consumed {
		return nil
	}
	reg.consumed = true
	return reg
}

// GetRegistration fetches a registration without consuming it.
func (ca *CA) GetRegistration(id string) *registration {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.registrations[id]
}
