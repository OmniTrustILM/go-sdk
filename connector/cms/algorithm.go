// Package cms builds and checks CMS SignedData structures for two-phase signing: the signed
// attributes are produced first, the signature is made elsewhere, and the SignedData is assembled
// afterwards. All output is DER.
package cms

import (
	"crypto"
	_ "crypto/sha256" // registers SHA-224 and SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // registers SHA-384 and SHA-512 for crypto.Hash.New
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// KeyType is the family of a signing key.
type KeyType string

// Key types supported by the algorithm table.
const (
	KeyRSA     KeyType = "RSA"
	KeyECDSA   KeyType = "ECDSA"
	KeyEd25519 KeyType = "Ed25519"
	KeyMLDSA   KeyType = "ML-DSA"
	KeySLHDSA  KeyType = "SLH-DSA"
)

// Algorithm describes a platform signature algorithm code in CMS terms.
type Algorithm struct {
	Code       string                   // platform code, e.g. "SHA256withRSAandMGF1"
	KeyType    KeyType                  // family of the signing key
	Parameter  string                   // ML-DSA and SLH-DSA parameter set, else empty
	Hash       crypto.Hash              // digest the platform pairs with the code
	Signature  pkix.AlgorithmIdentifier // signatureAlgorithm of the SignerInfo
	Digest     pkix.AlgorithmIdentifier // digestAlgorithm of the SignerInfo
	Verifiable bool                     // false for ML-DSA and SLH-DSA
}

// pqcSet is one ML-DSA or SLH-DSA parameter set.
type pqcSet struct {
	parameter string
	keyType   KeyType
	oid       asn1.ObjectIdentifier
	hash      crypto.Hash
}

var pqcSets = []pqcSet{
	{"ML-DSA-44", KeyMLDSA, nistSignatureOID(17), crypto.SHA512},
	{"ML-DSA-65", KeyMLDSA, nistSignatureOID(18), crypto.SHA512},
	{"ML-DSA-87", KeyMLDSA, nistSignatureOID(19), crypto.SHA512},
	{"SLH-DSA-SHA2-128s", KeySLHDSA, nistSignatureOID(20), crypto.SHA256},
	{"SLH-DSA-SHA2-128f", KeySLHDSA, nistSignatureOID(21), crypto.SHA256},
	{"SLH-DSA-SHA2-192s", KeySLHDSA, nistSignatureOID(22), crypto.SHA512},
	{"SLH-DSA-SHA2-192f", KeySLHDSA, nistSignatureOID(23), crypto.SHA512},
	{"SLH-DSA-SHA2-256s", KeySLHDSA, nistSignatureOID(24), crypto.SHA512},
	{"SLH-DSA-SHA2-256f", KeySLHDSA, nistSignatureOID(25), crypto.SHA512},
}

// pssParams is RSASSA-PSS-params of RFC 4055 section 3.1 with trailerField left at its default.
type pssParams struct {
	Hash       pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF        pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength int                      `asn1:"explicit,tag:2"`
}

var algorithms = buildAlgorithms()

// Lookup returns the algorithm for a platform signature algorithm code.
func Lookup(code string) (Algorithm, bool) {
	alg, ok := algorithms[code]
	return alg, ok
}

// Codes returns the supported platform signature algorithm codes in ascending order.
func Codes() []string {
	return slices.Sorted(maps.Keys(algorithms))
}

// DigestIdentifier returns the AlgorithmIdentifier of a SHA-2 hash, without parameters.
func DigestIdentifier(h crypto.Hash) (pkix.AlgorithmIdentifier, bool) {
	oid, ok := digestOIDs[h]
	return pkix.AlgorithmIdentifier{Algorithm: oid}, ok
}

// CertificateKeyType returns the key type of the certificate's public key and, for ML-DSA and
// SLH-DSA, the parameter set name. The standard library does not parse those keys, so they are
// recognised by the algorithm identifier of the SubjectPublicKeyInfo.
func CertificateKeyType(cert *x509.Certificate) (KeyType, string, error) {
	if cert == nil {
		return "", "", errors.New("cms: certificate is nil")
	}
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return KeyRSA, "", nil
	case x509.ECDSA:
		return KeyECDSA, "", nil
	case x509.Ed25519:
		return KeyEd25519, "", nil
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return "", "", fmt.Errorf("cms: parse subject public key info: %w", err)
	}
	for _, set := range pqcSets {
		if set.oid.Equal(spki.Algorithm.Algorithm) {
			return set.keyType, set.parameter, nil
		}
	}
	return "", "", fmt.Errorf("cms: unsupported public key algorithm %s", spki.Algorithm.Algorithm)
}

func buildAlgorithms() map[string]Algorithm {
	table := make(map[string]Algorithm)
	add := func(alg Algorithm) { table[alg.Code] = alg }
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		name := fmt.Sprintf("SHA%d", h.Size()*8)
		digest, _ := DigestIdentifier(h)
		add(Algorithm{Code: name + "withRSA", KeyType: KeyRSA, Hash: h, Digest: digest, Verifiable: true,
			Signature: pkix.AlgorithmIdentifier{Algorithm: rsaOIDs[h], Parameters: asn1.NullRawValue}})
		add(Algorithm{Code: name + "withRSAandMGF1", KeyType: KeyRSA, Hash: h, Digest: digest, Verifiable: true,
			Signature: pssIdentifier(h)})
		add(Algorithm{Code: name + "withECDSA", KeyType: KeyECDSA, Hash: h, Digest: digest, Verifiable: true,
			Signature: pkix.AlgorithmIdentifier{Algorithm: ecdsaOIDs[h]}})
	}
	sha512, _ := DigestIdentifier(crypto.SHA512)
	add(Algorithm{Code: "Ed25519", KeyType: KeyEd25519, Hash: crypto.SHA512, Digest: sha512, Verifiable: true,
		Signature: pkix.AlgorithmIdentifier{Algorithm: oidEd25519}})
	for _, set := range pqcSets {
		digest, _ := DigestIdentifier(set.hash)
		add(Algorithm{Code: strings.ToUpper(set.parameter), KeyType: set.keyType, Parameter: set.parameter,
			Hash: set.hash, Digest: digest, Signature: pkix.AlgorithmIdentifier{Algorithm: set.oid}})
	}
	return table
}

// pssIdentifier builds the RSASSA-PSS identifier whose salt length equals the hash length and
// whose hash identifiers carry NULL parameters, as RFC 4055 writes them.
func pssIdentifier(h crypto.Hash) pkix.AlgorithmIdentifier {
	hashID := pkix.AlgorithmIdentifier{Algorithm: digestOIDs[h], Parameters: asn1.NullRawValue}
	params := mustMarshal(pssParams{
		Hash: hashID,
		MGF: pkix.AlgorithmIdentifier{
			Algorithm:  oidMGF1,
			Parameters: asn1.RawValue{FullBytes: mustMarshal(hashID)},
		},
		SaltLength: h.Size(),
	})
	return pkix.AlgorithmIdentifier{Algorithm: oidRSAPSS, Parameters: asn1.RawValue{FullBytes: params}}
}

// mustMarshal marshals a statically known structure; a failure is a programming error.
func mustMarshal(v any) []byte {
	der, err := asn1.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("cms: marshal %T: %v", v, err))
	}
	return der
}
