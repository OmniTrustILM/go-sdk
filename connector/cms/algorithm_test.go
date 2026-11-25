package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"slices"
	"testing"
)

const (
	hexSHA256 = "300b0609608648016503040201"
	hexSHA384 = "300b0609608648016503040202"
	hexSHA512 = "300b0609608648016503040203"

	// RSASSA-PSS-params per RFC 4055: [0] hash with NULL, [1] MGF1 with the same hash with NULL,
	// [2] salt length, trailerField omitted.
	hexPSS256 = "3041" + "06092a864886f70d01010a" + "3034" +
		"a00f300d06096086480165030402010500" +
		"a11c301a06092a864886f70d010108" + "300d06096086480165030402010500" +
		"a203020120"
	hexPSS384 = "3041" + "06092a864886f70d01010a" + "3034" +
		"a00f300d06096086480165030402020500" +
		"a11c301a06092a864886f70d010108" + "300d06096086480165030402020500" +
		"a203020130"
	hexPSS512 = "3041" + "06092a864886f70d01010a" + "3034" +
		"a00f300d06096086480165030402030500" +
		"a11c301a06092a864886f70d010108" + "300d06096086480165030402030500" +
		"a203020140"
)

var lookupCases = []struct {
	code       string
	keyType    KeyType
	parameter  string
	hash       crypto.Hash
	signature  string
	digest     string
	verifiable bool
}{
	{"SHA256withRSA", KeyRSA, "", crypto.SHA256, "300d06092a864886f70d01010b0500", hexSHA256, true},
	{"SHA384withRSA", KeyRSA, "", crypto.SHA384, "300d06092a864886f70d01010c0500", hexSHA384, true},
	{"SHA512withRSA", KeyRSA, "", crypto.SHA512, "300d06092a864886f70d01010d0500", hexSHA512, true},
	{"SHA256withRSAandMGF1", KeyRSA, "", crypto.SHA256, hexPSS256, hexSHA256, true},
	{"SHA384withRSAandMGF1", KeyRSA, "", crypto.SHA384, hexPSS384, hexSHA384, true},
	{"SHA512withRSAandMGF1", KeyRSA, "", crypto.SHA512, hexPSS512, hexSHA512, true},
	{"SHA256withECDSA", KeyECDSA, "", crypto.SHA256, "300a06082a8648ce3d040302", hexSHA256, true},
	{"SHA384withECDSA", KeyECDSA, "", crypto.SHA384, "300a06082a8648ce3d040303", hexSHA384, true},
	{"SHA512withECDSA", KeyECDSA, "", crypto.SHA512, "300a06082a8648ce3d040304", hexSHA512, true},
	{"Ed25519", KeyEd25519, "", crypto.SHA512, "300506032b6570", hexSHA512, true},
	{"ML-DSA-44", KeyMLDSA, "ML-DSA-44", crypto.SHA512, "300b0609608648016503040311", hexSHA512, false},
	{"ML-DSA-65", KeyMLDSA, "ML-DSA-65", crypto.SHA512, "300b0609608648016503040312", hexSHA512, false},
	{"ML-DSA-87", KeyMLDSA, "ML-DSA-87", crypto.SHA512, "300b0609608648016503040313", hexSHA512, false},
	{"SLH-DSA-SHA2-128S", KeySLHDSA, "SLH-DSA-SHA2-128s", crypto.SHA256, "300b0609608648016503040314", hexSHA256, false},
	{"SLH-DSA-SHA2-128F", KeySLHDSA, "SLH-DSA-SHA2-128f", crypto.SHA256, "300b0609608648016503040315", hexSHA256, false},
	{"SLH-DSA-SHA2-192S", KeySLHDSA, "SLH-DSA-SHA2-192s", crypto.SHA512, "300b0609608648016503040316", hexSHA512, false},
	{"SLH-DSA-SHA2-192F", KeySLHDSA, "SLH-DSA-SHA2-192f", crypto.SHA512, "300b0609608648016503040317", hexSHA512, false},
	{"SLH-DSA-SHA2-256S", KeySLHDSA, "SLH-DSA-SHA2-256s", crypto.SHA512, "300b0609608648016503040318", hexSHA512, false},
	{"SLH-DSA-SHA2-256F", KeySLHDSA, "SLH-DSA-SHA2-256f", crypto.SHA512, "300b0609608648016503040319", hexSHA512, false},
}

func TestLookup(t *testing.T) {
	for _, tc := range lookupCases {
		t.Run(tc.code, func(t *testing.T) {
			alg, ok := Lookup(tc.code)
			if !ok {
				t.Fatalf("%s not found", tc.code)
			}
			if alg.Code != tc.code || alg.KeyType != tc.keyType || alg.Parameter != tc.parameter ||
				alg.Hash != tc.hash || alg.Verifiable != tc.verifiable {
				t.Errorf("unexpected algorithm %+v", alg)
			}
			if got := marshalHex(t, alg.Signature); got != tc.signature {
				t.Errorf("signature identifier\n got %s\nwant %s", got, tc.signature)
			}
			if got := marshalHex(t, alg.Digest); got != tc.digest {
				t.Errorf("digest identifier\n got %s\nwant %s", got, tc.digest)
			}
		})
	}
}

func TestLookupUnknown(t *testing.T) {
	for _, code := range []string{"Ed448", "FALCON-1024", "", "sha256withrsa"} {
		if _, ok := Lookup(code); ok {
			t.Errorf("%q must not resolve", code)
		}
	}
}

func TestLookupDigestIdentifier(t *testing.T) {
	cases := map[crypto.Hash]string{
		crypto.SHA224: "300b0609608648016503040204",
		crypto.SHA256: hexSHA256,
		crypto.SHA384: hexSHA384,
		crypto.SHA512: hexSHA512,
	}
	for h, want := range cases {
		id, ok := DigestIdentifier(h)
		if !ok {
			t.Fatalf("%v not supported", h)
		}
		if got := marshalHex(t, id); got != want {
			t.Errorf("%v: got %s want %s", h, got, want)
		}
	}
	if _, ok := DigestIdentifier(crypto.MD5); ok {
		t.Error("MD5 must not be supported")
	}
}

func TestCodes(t *testing.T) {
	codes := Codes()
	if len(codes) != 19 {
		t.Errorf("got %d codes, want 19", len(codes))
	}
	if !slices.IsSorted(codes) {
		t.Errorf("codes not sorted: %v", codes)
	}
	for _, tc := range lookupCases {
		if !slices.Contains(codes, tc.code) {
			t.Errorf("missing %s", tc.code)
		}
	}
}

func TestCertificateKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		cert      *x509.Certificate
		keyType   KeyType
		parameter string
	}{
		{"rsa", selfSigned(t, &rsaKey.PublicKey, rsaKey, certOptions{}), KeyRSA, ""},
		{"ecdsa", selfSigned(t, &ecKey.PublicKey, ecKey, certOptions{}), KeyECDSA, ""},
		{"ed25519", selfSigned(t, edPub, edKey, certOptions{}), KeyEd25519, ""},
		{"ml-dsa-65", loadCertificate(t, "mldsa65.pem"), KeyMLDSA, "ML-DSA-65"},
		{"slh-dsa", loadCertificate(t, "slhdsa-sha2-128s.pem"), KeySLHDSA, "SLH-DSA-SHA2-128s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kt, param, err := CertificateKeyType(tc.cert)
			if err != nil {
				t.Fatal(err)
			}
			if kt != tc.keyType || param != tc.parameter {
				t.Errorf("got %s/%s, want %s/%s", kt, param, tc.keyType, tc.parameter)
			}
		})
	}
}

func TestCertificateKeyTypeErrors(t *testing.T) {
	unknownOID, err := asn1.Marshal(struct {
		Algorithm struct{ OID asn1.ObjectIdentifier }
		Key       asn1.BitString
	}{
		Algorithm: struct{ OID asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 3, 4}},
		Key:       asn1.BitString{Bytes: []byte{1}, BitLength: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]*x509.Certificate{
		"nil":         nil,
		"unknown oid": {RawSubjectPublicKeyInfo: unknownOID},
		"malformed":   {RawSubjectPublicKeyInfo: []byte{0x01, 0x02}},
		"empty":       {},
	}
	for name, cert := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := CertificateKeyType(cert); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func marshalHex(t *testing.T, v any) string {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(der)
}
