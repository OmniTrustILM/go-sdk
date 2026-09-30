package cryptography

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Envelopes made by the two producers the platform relies on, both around the
// same P-256 key: OpenSSL 3.5 (`openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf
// hmacWithSHA256 -iter 100000`, a 16-byte salt) and Bouncy Castle 1.85's
// JceOpenSSLPKCS8EncryptorBuilder configured as Core configures it (a 32-byte
// salt; 100000 iterations here). The plaintext was recovered with OpenSSL's
// own PBKDF2 and AES, not with the code under test.
const (
	fixturePKCS8    = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXW5wjJcGNPHMVaauFkca6yQQjV1L9ogVXYQZ3mfdSsahRANCAATzW11tA/epFGRXn3QIdujl4UsD3Q/xvqtccVRLIk4hXKxOxcOtz/OV6vW0RZFpdTVrCf/4cfIq+jjF74VX5LfX"
	opensslEnvelope = "MIH1MGAGCSqGSIb3DQEFDTBTMDIGCSqGSIb3DQEFDDAlBBCCdQZrT+tPCaXnHkdV2MbPAgMBhqAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEF5CvgXm9cZ1TfHrhNkxz4QEgZD09zLsdfg5O1H0BLWFMd4E2E1v8vLQ5He16MKbFdvoC3eJkTbGUG6s2+wbKoQ/zDYO925zVZF9K5zeZh2hNsSzUIvKtdZhU+Di4/WKWR0L4SiXWsq2ttweajXHAGisb/pz3nF06EgvK6qygEEjiUfJX+XM5TSzJs7+NULXUBWSCB/iYfbAo2mdWVb3MSC5aX0="
	opensslPhrase   = "openssl-fixture"
	bcEnvelope      = "MIIBBTBwBgkqhkiG9w0BBQ0wYzBCBgkqhkiG9w0BBQwwNQQgb+jqtZoKWaqQb/kTpFupfldSfHdBycj41gAalKcGDpgCAwGGoDAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQj/JNYlFkKJT/McXrnwoZpgSBkE4YIPMyZ26PAFkV/SMHNGqZCTWs9UPqdGEy6Xlj0d5YA/I1INPH3uKJpP7DQytRDuWDHGJg8gLmwR5eSlysQYx3MzDvAe/2UmacMm3Ao5nlw1khIQu9ch+vdZ5uqDKsYmikqZ89j0F1mdRMuNGHZrqpkcuSewuJqFVIlZKJRI5QI1zx+U+s8ctA1+gBSWR4wQ=="
	bcPhrase        = "bc-fixture"
)

// Object identifiers written out independently of material.go.
var (
	testOIDPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	testOIDPBES1      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 10}
	testOIDPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	testOIDScrypt     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
	testOIDHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	testOIDHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	testOIDAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	testOIDAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
)

func derOf(t *testing.T, v any) []byte {
	t.Helper()
	out, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return out
}

func sequence(t *testing.T, elements ...[]byte) []byte {
	t.Helper()
	return derOf(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(elements, nil)})
}

func decodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return out
}

func materialOf(der []byte) mdl.EncryptedKeyMaterialV2Dto {
	return mdl.EncryptedKeyMaterialV2Dto{EncryptedPrivateKeyInfo: base64.StdEncoding.EncodeToString(der)}
}

// envelopeSpec describes an EncryptedPrivateKeyInfo field by field, so a test
// can break exactly one rule of the profile. A non-nil *DER field replaces the
// encoding of its value.
type envelopeSpec struct {
	scheme        asn1.ObjectIdentifier
	kdf           asn1.ObjectIdentifier
	salt          []byte
	iterations    int
	iterationsDER []byte
	keyLength     int    // 0 leaves the optional field out
	prf           []byte // the prf AlgorithmIdentifier; nil leaves it out
	extraKDF      []byte // an element appended to the PBKDF2 parameters
	cipher        asn1.ObjectIdentifier
	iv            []byte
	ciphertext    []byte
	ciphertextDER []byte
	ivDER         []byte
	pbes2DER      []byte // replaces the PBES2 parameters as a whole
	extra         []byte // an element appended to the EncryptedPrivateKeyInfo
}

func inProfile(t *testing.T) envelopeSpec {
	t.Helper()
	return envelopeSpec{
		scheme:     testOIDPBES2,
		kdf:        testOIDPBKDF2,
		salt:       bytes.Repeat([]byte{0x11}, 16),
		iterations: 100000,
		prf:        sequence(t, derOf(t, testOIDHMACSHA256), asn1.NullBytes),
		cipher:     testOIDAES256CBC,
		iv:         bytes.Repeat([]byte{0x22}, 16),
		ciphertext: bytes.Repeat([]byte{0x33}, 32),
	}
}

func orDER(t *testing.T, override []byte, v any) []byte {
	t.Helper()
	if override != nil {
		return override
	}
	return derOf(t, v)
}

func (s envelopeSpec) encode(t *testing.T) []byte {
	t.Helper()
	kdfParams := [][]byte{derOf(t, s.salt), orDER(t, s.iterationsDER, s.iterations)}
	if s.keyLength != 0 {
		kdfParams = append(kdfParams, derOf(t, s.keyLength))
	}
	if s.prf != nil {
		kdfParams = append(kdfParams, s.prf)
	}
	if s.extraKDF != nil {
		kdfParams = append(kdfParams, s.extraKDF)
	}
	kdf := sequence(t, derOf(t, s.kdf), sequence(t, kdfParams...))
	encryption := sequence(t, derOf(t, s.cipher), orDER(t, s.ivDER, s.iv))
	pbes2 := s.pbes2DER
	if pbes2 == nil {
		pbes2 = sequence(t, kdf, encryption)
	}
	algorithm := sequence(t, derOf(t, s.scheme), pbes2)
	elements := [][]byte{algorithm, orDER(t, s.ciphertextDER, s.ciphertext)}
	if s.extra != nil {
		elements = append(elements, s.extra)
	}
	return sequence(t, elements...)
}

// sealed encrypts plaintext, PKCS#7-padded, under phrase with the spec's own
// salt, iterations and IV.
func (s envelopeSpec) sealed(t *testing.T, plaintext []byte, phrase string) envelopeSpec {
	t.Helper()
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	return s.sealedRaw(t, append(bytes.Clone(plaintext), bytes.Repeat([]byte{byte(pad)}, pad)...), phrase)
}

// sealedRaw encrypts blocks as they are, padding included.
func (s envelopeSpec) sealedRaw(t *testing.T, blocks []byte, phrase string) envelopeSpec {
	t.Helper()
	key, err := pbkdf2.Key(sha256.New, phrase, s.salt, s.iterations, 32)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	s.ciphertext = make([]byte, len(blocks))
	cipher.NewCBCEncrypter(block, s.iv).CryptBlocks(s.ciphertext, blocks)
	return s
}

func assertProblemError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var se *shared.Error
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want a *shared.Error", err)
	}
	if se.Status != status || se.ErrorCode != code {
		t.Fatalf("err = %d %s, want %d %s", se.Status, se.ErrorCode, status, code)
	}
}

func TestOpenKeyMaterialOpensEnvelopesOfBothProducers(t *testing.T) {
	want := decodeBase64(t, fixturePKCS8)
	for name, tc := range map[string]struct{ envelope, phrase string }{
		"OpenSSL 3.5":        {opensslEnvelope, opensslPhrase},
		"Bouncy Castle 1.85": {bcEnvelope, bcPhrase},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := OpenKeyMaterial(mdl.EncryptedKeyMaterialV2Dto{EncryptedPrivateKeyInfo: tc.envelope}, tc.phrase)
			if err != nil {
				t.Fatalf("OpenKeyMaterial: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("plaintext = %x, want %x", got, want)
			}
		})
	}
}

func TestOpenKeyMaterialRefusesAPassphraseThatDoesNotOpenIt(t *testing.T) {
	_, err := OpenKeyMaterial(mdl.EncryptedKeyMaterialV2Dto{EncryptedPrivateKeyInfo: opensslEnvelope}, "not-the-fixture")
	if !errors.Is(err, ErrKeyDecryptionFailed) {
		t.Fatalf("err = %v, want ErrKeyDecryptionFailed", err)
	}
}

// Without integrity protection a wrong passphrase can still yield valid
// padding; what decrypts must also be a PrivateKeyInfo.
func TestOpenKeyMaterialRefusesPlaintextThatIsNoPrivateKeyInfo(t *testing.T) {
	const phrase = "right"
	pkcs8 := decodeBase64(t, fixturePKCS8)
	cases := map[string]envelopeSpec{
		"valid padding over other data": inProfile(t).sealed(t, []byte("not a private key"), phrase),
		"a PrivateKeyInfo and more":     inProfile(t).sealed(t, append(bytes.Clone(pkcs8), 0x00), phrase),
		"an element after the key":      inProfile(t).sealed(t, withElement(t, pkcs8, derOf(t, 5)), phrase),
		"invalid padding":               inProfile(t).sealedRaw(t, make([]byte, 32), phrase),
		"padding longer than a block":   inProfile(t).sealedRaw(t, bytes.Repeat([]byte{0x20}, 32), phrase),
		"padding bytes that disagree":   inProfile(t).sealedRaw(t, append(make([]byte, 29), 0x03, 0x02, 0x03), phrase),
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := OpenKeyMaterial(materialOf(spec.encode(t)), phrase)
			if !errors.Is(err, ErrKeyDecryptionFailed) {
				t.Fatalf("err = %v, want ErrKeyDecryptionFailed", err)
			}
		})
	}
}

func TestOpenKeyMaterialRefusesMaterialOutsideTheProfile(t *testing.T) {
	spec := inProfile(t)
	spec.iterations = 99999
	_, err := OpenKeyMaterial(materialOf(spec.encode(t)), "any")
	assertProblemError(t, err, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
}

func TestOpenKeyMaterialRefusesMaterialThatIsNotBase64(t *testing.T) {
	_, err := OpenKeyMaterial(mdl.EncryptedKeyMaterialV2Dto{EncryptedPrivateKeyInfo: "not base64!"}, "any")
	assertProblemError(t, err, http.StatusBadRequest, "BAD_REQUEST")
}

// protectedFields reads the fields a Protect envelope must carry, with its own
// parser rather than the one under test.
type protectedFields struct {
	scheme, kdf, prf, cipher asn1.ObjectIdentifier
	prfParams                []byte
	kdfElements              int
	salt, iv, ciphertext     []byte
	iterations               int
}

func readProtected(t *testing.T, m mdl.EncryptedKeyMaterialV2Dto) protectedFields {
	t.Helper()
	var envelope struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters struct {
				KDF struct {
					Algorithm  asn1.ObjectIdentifier
					Parameters asn1.RawValue
				}
				Encryption struct {
					Algorithm asn1.ObjectIdentifier
					IV        []byte
				}
			}
		}
		Ciphertext []byte
	}
	if rest, err := asn1.Unmarshal(decodeBase64(t, m.EncryptedPrivateKeyInfo), &envelope); err != nil || len(rest) != 0 {
		t.Fatalf("parse envelope: %v, %d trailing bytes", err, len(rest))
	}
	var kdf struct {
		Salt       []byte
		Iterations int
		PRF        struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}
	}
	if _, err := asn1.Unmarshal(envelope.Algorithm.Parameters.KDF.Parameters.FullBytes, &kdf); err != nil {
		t.Fatalf("parse PBKDF2 parameters: %v", err)
	}
	elements := 0
	for rest := envelope.Algorithm.Parameters.KDF.Parameters.Bytes; len(rest) > 0; elements++ {
		var element asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &element); err != nil {
			t.Fatalf("walk PBKDF2 parameters: %v", err)
		}
	}
	return protectedFields{
		scheme:      envelope.Algorithm.Algorithm,
		kdf:         envelope.Algorithm.Parameters.KDF.Algorithm,
		prf:         kdf.PRF.Algorithm,
		prfParams:   kdf.PRF.Parameters.FullBytes,
		cipher:      envelope.Algorithm.Parameters.Encryption.Algorithm,
		kdfElements: elements,
		salt:        kdf.Salt,
		iv:          envelope.Algorithm.Parameters.Encryption.IV,
		ciphertext:  envelope.Ciphertext,
		iterations:  kdf.Iterations,
	}
}

// The phrase is in Unicode normalization form D: the envelope must open under
// exactly those UTF-8 bytes, so any normalization would fail the decryption.
func TestProtectKeyMaterialUsesThePinnedProfile(t *testing.T) {
	const phrase = "café export"
	pkcs8 := decodeBase64(t, fixturePKCS8)
	m, err := ProtectKeyMaterial(pkcs8, phrase)
	if err != nil {
		t.Fatalf("ProtectKeyMaterial: %v", err)
	}
	got := readProtected(t, m)

	if !got.scheme.Equal(testOIDPBES2) || !got.kdf.Equal(testOIDPBKDF2) || !got.prf.Equal(testOIDHMACSHA256) || !got.cipher.Equal(testOIDAES256CBC) {
		t.Fatalf("scheme %v / %v / %v / %v, want PBES2, PBKDF2, hmacWithSHA256, AES-256-CBC", got.scheme, got.kdf, got.prf, got.cipher)
	}
	if !bytes.Equal(got.prfParams, asn1.NullBytes) {
		t.Errorf("prf parameters = %x, want NULL", got.prfParams)
	}
	if got.kdfElements != 3 {
		t.Errorf("PBKDF2 parameters carry %d elements, want salt, iterations and prf with no key length", got.kdfElements)
	}
	if len(got.salt) != 16 || len(got.iv) != 16 || got.iterations != 600000 {
		t.Errorf("salt %d bytes, IV %d bytes, %d iterations, want 16, 16, 600000", len(got.salt), len(got.iv), got.iterations)
	}

	opened := envelopeSpec{salt: got.salt, iterations: got.iterations, iv: got.iv}.sealed(t, pkcs8, phrase)
	if !bytes.Equal(opened.ciphertext, got.ciphertext) {
		t.Fatal("ciphertext is not the PrivateKeyInfo under the phrase's UTF-8 bytes")
	}
}

func TestProtectKeyMaterialDrawsAFreshSaltAndIV(t *testing.T) {
	pkcs8 := decodeBase64(t, fixturePKCS8)
	first, err := ProtectKeyMaterial(pkcs8, "phrase")
	if err != nil {
		t.Fatalf("ProtectKeyMaterial: %v", err)
	}
	second, err := ProtectKeyMaterial(pkcs8, "phrase")
	if err != nil {
		t.Fatalf("ProtectKeyMaterial: %v", err)
	}
	a, b := readProtected(t, first), readProtected(t, second)
	if bytes.Equal(a.salt, b.salt) || bytes.Equal(a.iv, b.iv) {
		t.Fatal("two envelopes share a salt or an IV")
	}
}

func TestProtectedMaterialOpensAgain(t *testing.T) {
	pkcs8 := decodeBase64(t, fixturePKCS8)
	m, err := ProtectKeyMaterial(pkcs8, "round trip")
	if err != nil {
		t.Fatalf("ProtectKeyMaterial: %v", err)
	}
	got, err := OpenKeyMaterial(m, "round trip")
	if err != nil {
		t.Fatalf("OpenKeyMaterial: %v", err)
	}
	if !bytes.Equal(got, pkcs8) {
		t.Fatal("round trip changed the key")
	}
}

func TestProtectKeyMaterialRefusesWhatItCannotProtect(t *testing.T) {
	pkcs8 := decodeBase64(t, fixturePKCS8)
	oversized := sequence(t, derOf(t, 0), sequence(t, derOf(t, testOIDAES256CBC)), derOf(t, make([]byte, 70000)))
	cases := map[string]struct {
		key    []byte
		phrase string
	}{
		"empty passphrase":           {pkcs8, ""},
		"not a PrivateKeyInfo":       {[]byte("key"), "phrase"},
		"a PrivateKeyInfo and more":  {append(bytes.Clone(pkcs8), 0x00), "phrase"},
		"beyond the envelope limit":  {oversized, "phrase"},
		"an unknown version":         {sequence(t, derOf(t, 7), sequence(t, derOf(t, testOIDAES256CBC)), derOf(t, []byte{1})), "phrase"},
		"an empty private key value": {sequence(t, derOf(t, 0), sequence(t, derOf(t, testOIDAES256CBC)), derOf(t, []byte{})), "phrase"},
		"an element after the key":   {withElement(t, pkcs8, derOf(t, 5)), "phrase"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ProtectKeyMaterial(tc.key, tc.phrase); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// withElement appends one DER element inside the PrivateKeyInfo SEQUENCE.
func withElement(t *testing.T, privateKeyInfo, element []byte) []byte {
	t.Helper()
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(privateKeyInfo, &outer); err != nil {
		t.Fatalf("parse PrivateKeyInfo: %v", err)
	}
	return sequence(t, outer.Bytes, element)
}

// RFC 5958 lets a OneAsymmetricKey carry attributes and, from version 1, its
// public key.
func TestProtectKeyMaterialKeepsTheOptionalFieldsOfAKey(t *testing.T) {
	pkcs8 := decodeBase64(t, fixturePKCS8)
	attributes := derOf(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sequence(t, derOf(t, testOIDHMACSHA1))})
	publicKey := derOf(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte{0x00, 0x04}})
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(pkcs8, &outer); err != nil {
		t.Fatalf("parse PrivateKeyInfo: %v", err)
	}
	var fields []asn1.RawValue
	for rest := outer.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			t.Fatalf("walk PrivateKeyInfo: %v", err)
		}
		fields = append(fields, field)
	}
	fields[0] = asn1.RawValue{FullBytes: derOf(t, 1)}
	versionOne := sequence(t, fields[0].FullBytes, fields[1].FullBytes, fields[2].FullBytes, attributes, publicKey)

	if _, err := ProtectKeyMaterial(versionOne, "phrase"); err != nil {
		t.Fatalf("ProtectKeyMaterial: %v", err)
	}
}

func TestParseEnvelopeAcceptsTheVariationsProducersUse(t *testing.T) {
	cases := map[string]func(*envelopeSpec){
		"key length stated as 32": func(s *envelopeSpec) { s.keyLength = 32 },
		"20-byte salt":            func(s *envelopeSpec) { s.salt = make([]byte, 20) },
		"32-byte salt":            func(s *envelopeSpec) { s.salt = make([]byte, 32) },
		"fewest iterations":       func(s *envelopeSpec) { s.iterations = 100000 },
		"most iterations":         func(s *envelopeSpec) { s.iterations = 10000000 },
		"one cipher block":        func(s *envelopeSpec) { s.ciphertext = make([]byte, 16) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := inProfile(t)
			mutate(&spec)
			env, err := parseEnvelope(spec.encode(t))
			if err != nil {
				t.Fatalf("parseEnvelope: %v", err)
			}
			if env.iterations != spec.iterations || !bytes.Equal(env.salt, spec.salt) || !bytes.Equal(env.iv, spec.iv) || !bytes.Equal(env.ciphertext, spec.ciphertext) {
				t.Fatalf("parsed %+v, want the spec's salt, iterations, IV and ciphertext", env)
			}
		})
	}
}

func TestParseEnvelopeRefusesWhatFallsOutsideTheProfile(t *testing.T) {
	valid := inProfile(t).encode(t)
	nonMinimalLength := append([]byte{0x30, 0x82, 0x00, byte(len(valid) - 2)}, valid[2:]...)
	constructedOctets := derOf(t, asn1.RawValue{Tag: asn1.TagOctetString, IsCompound: true, Bytes: derOf(t, make([]byte, 32))})
	cases := []struct {
		name   string
		der    []byte
		mutate func(*envelopeSpec)
		want   error
	}{
		{name: "longer than 65536 bytes", der: bytes.Repeat([]byte{0x30}, 65537), want: errEnvelopeTooLarge},
		{name: "65536 bytes of something else", der: bytes.Repeat([]byte{0x30}, 65536), want: errEnvelopeMalformed},
		{name: "empty", der: []byte{}, want: errEnvelopeMalformed},
		{name: "not DER", der: []byte("not an envelope"), want: errEnvelopeMalformed},
		{name: "trailing bytes", der: append(bytes.Clone(valid), 0x00), want: errEnvelopeMalformed},
		{name: "non-minimal length", der: nonMinimalLength, want: errEnvelopeMalformed},
		{name: "extra element in the envelope", mutate: func(s *envelopeSpec) { s.extra = derOf(t, 1) }, want: errEnvelopeMalformed},
		{name: "extra element in the PBKDF2 parameters", mutate: func(s *envelopeSpec) { s.extraKDF = derOf(t, 1) }, want: errEnvelopeMalformed},
		{name: "non-minimal iterations", mutate: func(s *envelopeSpec) { s.iterationsDER = []byte{0x02, 0x04, 0x00, 0x01, 0x86, 0xa0} }, want: errEnvelopeMalformed},
		{name: "constructed ciphertext", mutate: func(s *envelopeSpec) { s.ciphertextDER = constructedOctets }, want: errEnvelopeMalformed},
		{name: "PBES2 parameters that are no sequence", mutate: func(s *envelopeSpec) { s.pbes2DER = derOf(t, 1) }, want: errEnvelopeMalformed},
		{name: "an IV that is no octet string", mutate: func(s *envelopeSpec) { s.ivDER = derOf(t, 1) }, want: errEnvelopeMalformed},
		{name: "PBES1", mutate: func(s *envelopeSpec) { s.scheme = testOIDPBES1 }, want: errEnvelopeScheme},
		{name: "scrypt", mutate: func(s *envelopeSpec) { s.kdf = testOIDScrypt }, want: errEnvelopeScheme},
		{name: "hmacWithSHA1", mutate: func(s *envelopeSpec) { s.prf = sequence(t, derOf(t, testOIDHMACSHA1), asn1.NullBytes) }, want: errEnvelopeScheme},
		{name: "default prf", mutate: func(s *envelopeSpec) { s.prf = nil }, want: errEnvelopeScheme},
		{name: "prf without parameters", mutate: func(s *envelopeSpec) { s.prf = sequence(t, derOf(t, testOIDHMACSHA256)) }, want: errEnvelopeScheme},
		{name: "prf with other parameters", mutate: func(s *envelopeSpec) { s.prf = sequence(t, derOf(t, testOIDHMACSHA256), derOf(t, []byte{0})) }, want: errEnvelopeScheme},
		{name: "AES-128-CBC", mutate: func(s *envelopeSpec) { s.cipher = testOIDAES128CBC }, want: errEnvelopeScheme},
		{name: "8-byte salt", mutate: func(s *envelopeSpec) { s.salt = make([]byte, 8) }, want: errEnvelopeParameters},
		{name: "12-byte IV", mutate: func(s *envelopeSpec) { s.iv = make([]byte, 12) }, want: errEnvelopeParameters},
		{name: "too few iterations", mutate: func(s *envelopeSpec) { s.iterations = 99999 }, want: errEnvelopeParameters},
		{name: "too many iterations", mutate: func(s *envelopeSpec) { s.iterations = 10000001 }, want: errEnvelopeParameters},
		{name: "16-byte key length", mutate: func(s *envelopeSpec) { s.keyLength = 16 }, want: errEnvelopeParameters},
		{name: "empty ciphertext", mutate: func(s *envelopeSpec) { s.ciphertext = []byte{} }, want: errEnvelopeBlocks},
		{name: "partial block", mutate: func(s *envelopeSpec) { s.ciphertext = make([]byte, 17) }, want: errEnvelopeBlocks},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der := tc.der
			if tc.mutate != nil {
				spec := inProfile(t)
				tc.mutate(&spec)
				der = spec.encode(t)
			}
			if _, err := parseEnvelope(der); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
