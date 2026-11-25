package cms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
)

// tlv is one parsed DER element.
type tlv struct {
	tag     byte
	content []byte
	full    []byte
}

// readTLV parses one element and fails the test on indefinite or non-minimal lengths.
func readTLV(t *testing.T, b []byte) (tlv, []byte) {
	t.Helper()
	if len(b) < 2 {
		t.Fatalf("truncated element %x", b)
	}
	tag, first := b[0], int(b[1])
	header, length := 2, first
	if first >= 0x80 {
		n := first & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			t.Fatalf("indefinite or oversized length in %x", b[:2])
		}
		if b[2] == 0 {
			t.Fatalf("non-minimal length with leading zero: %x", b[:2+n])
		}
		length = 0
		for _, c := range b[2 : 2+n] {
			length = length<<8 | int(c)
		}
		if length < 0x80 {
			t.Fatalf("long form used for length %d", length)
		}
		header = 2 + n
	}
	if len(b) < header+length {
		t.Fatalf("element of tag %#x overruns its parent", tag)
	}
	return tlv{tag: tag, content: b[header : header+length], full: b[:header+length]}, b[header+length:]
}

// children parses the elements inside a constructed element.
func children(t *testing.T, content []byte) []tlv {
	t.Helper()
	var out []tlv
	for len(content) > 0 {
		var e tlv
		e, content = readTLV(t, content)
		out = append(out, e)
	}
	return out
}

// checkDER walks every constructed element and checks the lengths.
func checkDER(t *testing.T, e tlv) {
	t.Helper()
	if e.tag&0x20 == 0 {
		return
	}
	for _, c := range children(t, e.content) {
		checkDER(t, c)
	}
}

type signerInfoView struct {
	version     int
	sid         tlv
	digestAlg   tlv
	signedAttrs *tlv
	sigAlg      tlv
	signature   tlv
	unsigned    *tlv
}

type signedDataView struct {
	contentInfoType asn1.ObjectIdentifier
	version         int
	digestAlgs      tlv
	eContentType    asn1.ObjectIdentifier
	eContent        *tlv
	certificates    []tlv
	hasCRLs         bool
	signer          signerInfoView
}

func smallInt(t *testing.T, e tlv) int {
	t.Helper()
	var v int
	if _, err := asn1.Unmarshal(e.full, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func oidOf(t *testing.T, e tlv) asn1.ObjectIdentifier {
	t.Helper()
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(e.full, &oid); err != nil {
		t.Fatal(err)
	}
	return oid
}

func parseSignedData(t *testing.T, der []byte) signedDataView {
	t.Helper()
	top, rest := readTLV(t, der)
	if len(rest) != 0 || top.tag != 0x30 {
		t.Fatalf("ContentInfo is not a single SEQUENCE")
	}
	checkDER(t, top)
	ci := children(t, top.content)
	if len(ci) != 2 || ci[1].tag != 0xa0 {
		t.Fatalf("ContentInfo must hold a type and an explicit [0]")
	}
	view := signedDataView{contentInfoType: oidOf(t, ci[0])}
	sd, rest := readTLV(t, ci[1].content)
	if len(rest) != 0 || sd.tag != 0x30 {
		t.Fatalf("SignedData is not a single SEQUENCE")
	}
	parts := children(t, sd.content)
	view.version = smallInt(t, parts[0])
	view.digestAlgs = parts[1]
	encap := children(t, parts[2].content)
	view.eContentType = oidOf(t, encap[0])
	if len(encap) > 1 {
		view.eContent = &encap[1]
	}
	parts = parts[3:]
	if parts[0].tag == 0xa0 {
		view.certificates = children(t, parts[0].content)
		parts = parts[1:]
	}
	if parts[0].tag == 0xa1 {
		view.hasCRLs = true
		parts = parts[1:]
	}
	if len(parts) != 1 || parts[0].tag != 0x31 {
		t.Fatalf("SignedData must end with one signerInfos SET")
	}
	signers := children(t, parts[0].content)
	if len(signers) != 1 {
		t.Fatalf("got %d signer infos", len(signers))
	}
	view.signer = parseSignerInfo(t, signers[0])
	return view
}

func parseSignerInfo(t *testing.T, si tlv) signerInfoView {
	t.Helper()
	p := children(t, si.content)
	view := signerInfoView{version: smallInt(t, p[0]), sid: p[1], digestAlg: p[2]}
	p = p[3:]
	if p[0].tag == 0xa0 {
		view.signedAttrs = &p[0]
		p = p[1:]
	}
	view.sigAlg, view.signature = p[0], p[1]
	if len(p) > 2 {
		view.unsigned = &p[2]
	}
	return view
}

type fixtureOptions struct {
	contentType asn1.ObjectIdentifier
	content     []byte
	sid         SignerIdentifier
}

// fixtureInput builds a valid input around the RSA-PSS signer certificate.
func fixtureInput(t *testing.T, opts fixtureOptions) SignedDataInput {
	t.Helper()
	alg, _ := Lookup("SHA256withRSAandMGF1")
	signer := loadCertificate(t, "rsa-signer.pem")
	if opts.contentType == nil {
		opts.contentType = oidMRTDSecurityObject
	}
	if opts.sid == 0 {
		opts.sid = IssuerAndSerialNumber
	}
	return SignedDataInput{
		ContentType:      opts.contentType,
		Content:          opts.content,
		Certificates:     []*x509.Certificate{signer},
		Signer:           signer,
		SignerIdentifier: opts.sid,
		Algorithm:        alg,
		SignedAttributes: readGoldenHex(t, "signedattrs-basic.hex"),
		Signature:        bytes.Repeat([]byte{0x5a}, 256),
	}
}

func TestSignedDataVersions(t *testing.T) {
	cases := []struct {
		name        string
		contentType asn1.ObjectIdentifier
		sid         SignerIdentifier
		wantSD      int
		wantSigner  int
	}{
		{"data with issuer and serial", oidData, IssuerAndSerialNumber, 1, 1},
		{"data with key identifier", oidData, SubjectKeyIdentifier, 3, 3},
		{"other content with issuer and serial", oidMRTDSecurityObject, IssuerAndSerialNumber, 3, 1},
		{"other content with key identifier", oidMRTDSecurityObject, SubjectKeyIdentifier, 3, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der, err := SignedData(fixtureInput(t, fixtureOptions{contentType: tc.contentType, sid: tc.sid, content: []byte("x")}))
			if err != nil {
				t.Fatal(err)
			}
			view := parseSignedData(t, der)
			if view.version != tc.wantSD || view.signer.version != tc.wantSigner {
				t.Errorf("versions %d/%d, want %d/%d", view.version, view.signer.version, tc.wantSD, tc.wantSigner)
			}
			if !view.contentInfoType.Equal(oidSignedData) {
				t.Errorf("content info type %v", view.contentInfoType)
			}
		})
	}
}

func TestSignedDataDigestAlgorithmsAndContent(t *testing.T) {
	in := fixtureInput(t, fixtureOptions{content: []byte{1, 2, 3}})
	der, err := SignedData(in)
	if err != nil {
		t.Fatal(err)
	}
	view := parseSignedData(t, der)
	if want := mustMarshal(in.Algorithm.Digest); !bytes.Equal(view.digestAlgs.content, want) {
		t.Errorf("digestAlgorithms %x, want exactly %x", view.digestAlgs.content, want)
	}
	if !bytes.Equal(view.signer.digestAlg.full, view.digestAlgs.content) {
		t.Error("signer digest algorithm differs from digestAlgorithms")
	}
	if !view.eContentType.Equal(oidMRTDSecurityObject) {
		t.Errorf("eContentType %v", view.eContentType)
	}
	if view.eContent == nil || view.eContent.tag != 0xa0 ||
		!bytes.Equal(view.eContent.content, []byte{0x04, 0x03, 1, 2, 3}) {
		t.Errorf("eContent %+v", view.eContent)
	}
}

func TestSignedDataDetached(t *testing.T) {
	der, err := SignedData(fixtureInput(t, fixtureOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	if view := parseSignedData(t, der); view.eContent != nil {
		t.Error("detached content must have no eContent")
	}
}

func TestSignedDataCertificatesAndAbsentParts(t *testing.T) {
	in := fixtureInput(t, fixtureOptions{})
	other := loadCertificate(t, "ecdsa-signer.pem")
	in.Certificates = []*x509.Certificate{other, in.Signer}
	der, err := SignedData(in)
	if err != nil {
		t.Fatal(err)
	}
	view := parseSignedData(t, der)
	if len(view.certificates) != 2 || bytes.Compare(view.certificates[0].full, view.certificates[1].full) > 0 {
		t.Error("certificates not in DER SET OF order")
	}
	in.Certificates = []*x509.Certificate{in.Signer, other}
	if swapped, err := SignedData(in); err != nil || !bytes.Equal(swapped, der) {
		t.Errorf("certificate order changed the encoding: %v", err)
	}
	if view.hasCRLs || view.signer.unsigned != nil {
		t.Error("crls and unsigned attributes must be absent")
	}
	in.Certificates = nil
	der, err = SignedData(in)
	if err != nil {
		t.Fatal(err)
	}
	if view := parseSignedData(t, der); len(view.certificates) != 0 {
		t.Error("no certificates expected")
	}
}

func TestSignedDataSignedAttributes(t *testing.T) {
	in := fixtureInput(t, fixtureOptions{})
	der, err := SignedData(in)
	if err != nil {
		t.Fatal(err)
	}
	view := parseSignedData(t, der)
	got := view.signer.signedAttrs
	if got == nil || got.tag != 0xa0 {
		t.Errorf("signed attributes %+v", got)
	}
	if !bytes.Equal(got.full[1:], in.SignedAttributes[1:]) {
		t.Error("signed attributes differ beyond the tag byte")
	}
	if !bytes.Equal(view.signer.signature.content, in.Signature) || view.signer.signature.tag != 0x04 {
		t.Error("signature value not carried as OCTET STRING")
	}
	if !bytes.Equal(view.signer.sigAlg.full, mustMarshal(in.Algorithm.Signature)) {
		t.Error("signature algorithm not carried")
	}
}

func TestSignedDataIssuerAndSerial(t *testing.T) {
	in := fixtureInput(t, fixtureOptions{})
	der, err := SignedData(in)
	if err != nil {
		t.Fatal(err)
	}
	sid := children(t, parseSignedData(t, der).signer.sid.content)
	if sid[0].tag != 0x30 || !bytes.Equal(sid[0].full, in.Signer.RawIssuer) {
		t.Error("issuer differs from RawIssuer")
	}
	serial := sid[1].content
	if sid[1].tag != 0x02 || serial[0] != 0x00 || serial[1]&0x80 == 0 {
		t.Errorf("high-bit serial must be padded with one zero byte: %x", serial)
	}
	if new(big.Int).SetBytes(serial).Cmp(in.Signer.SerialNumber) != 0 {
		t.Error("serial number differs")
	}
}

func TestSignedDataSerialFromGeneratedCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, 20))
	cert := selfSigned(t, &key.PublicKey, key, certOptions{serial: serial})
	in := fixtureInput(t, fixtureOptions{})
	in.Signer = cert
	der, err := SignedData(in)
	if err != nil {
		t.Fatal(err)
	}
	sid := children(t, parseSignedData(t, der).signer.sid.content)
	if want := append([]byte{0}, bytes.Repeat([]byte{0xff}, 20)...); !bytes.Equal(sid[1].content, want) {
		t.Errorf("serial %x, want %x", sid[1].content, want)
	}
}

func TestSignedDataSubjectKeyIdentifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{20, 32} {
		ski := bytes.Repeat([]byte{0x9c}, size)
		cert := selfSigned(t, &key.PublicKey, key, certOptions{ski: ski})
		in := fixtureInput(t, fixtureOptions{sid: SubjectKeyIdentifier})
		in.Signer = cert
		der, err := SignedData(in)
		if err != nil {
			t.Fatal(err)
		}
		sid := parseSignedData(t, der).signer.sid
		if sid.tag != 0x80 || !bytes.Equal(sid.content, cert.SubjectKeyId) || len(sid.content) != size {
			t.Errorf("size %d: sid %x", size, sid.full)
		}
	}
}

func TestSignedDataErrors(t *testing.T) {
	noSKI := func() *x509.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		cert := selfSigned(t, &key.PublicKey, key, certOptions{})
		cert.SubjectKeyId = nil
		return cert
	}()
	cases := map[string]func(*SignedDataInput){
		"no signer":           func(in *SignedDataInput) { in.Signer = nil },
		"empty content type":  func(in *SignedDataInput) { in.ContentType = nil },
		"unknown identifier":  func(in *SignedDataInput) { in.SignerIdentifier = 0 },
		"no key identifier":   func(in *SignedDataInput) { in.SignerIdentifier, in.Signer = SubjectKeyIdentifier, noSKI },
		"no signature":        func(in *SignedDataInput) { in.Signature = nil },
		"no algorithm":        func(in *SignedDataInput) { in.Algorithm = Algorithm{} },
		"no signed attrs":     func(in *SignedDataInput) { in.SignedAttributes = nil },
		"attrs not a SET":     func(in *SignedDataInput) { in.SignedAttributes = []byte{0x30, 0x00} },
		"attrs truncated":     func(in *SignedDataInput) { in.SignedAttributes = []byte{0x31, 0x05, 0x00} },
		"attrs trailing data": func(in *SignedDataInput) { in.SignedAttributes = []byte{0x31, 0x00, 0x00} },
		"nil certificate":     func(in *SignedDataInput) { in.Certificates = []*x509.Certificate{nil} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := fixtureInput(t, fixtureOptions{})
			mutate(&in)
			if _, err := SignedData(in); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestSignedDataGolden(t *testing.T) {
	content := bytes.Repeat([]byte{0x77, 0x01}, 20)
	rsaIn := fixtureInput(t, fixtureOptions{content: content})
	rsaIn.Signature = patternBytes(256)

	ecAlg, _ := Lookup("SHA256withECDSA")
	ecSigner := loadCertificate(t, "ecdsa-signer.pem")
	ecSig, err := asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(patternBytes(32)), new(big.Int).SetBytes(patternBytes(31)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ecIn := fixtureInput(t, fixtureOptions{content: content, sid: SubjectKeyIdentifier})
	ecIn.Algorithm, ecIn.Signer, ecIn.Certificates, ecIn.Signature = ecAlg, ecSigner, []*x509.Certificate{ecSigner}, ecSig

	for name, in := range map[string]SignedDataInput{"signeddata-rsapss.hex": rsaIn, "signeddata-ecdsa.hex": ecIn} {
		t.Run(name, func(t *testing.T) {
			got, err := SignedData(in)
			if err != nil {
				t.Fatal(err)
			}
			if want := readGoldenHex(t, name); !bytes.Equal(got, want) {
				t.Errorf("SignedData differs from %s\n got %x", name, got)
			}
		})
	}
}

// patternBytes returns n bytes 0x01, 0x02, ... with the top bit cleared.
func patternBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i+1) & 0x7f
	}
	return b
}
