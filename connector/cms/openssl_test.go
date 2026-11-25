package cms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

const (
	workDir        = "/w"
	caFile         = "ca.pem"
	signedAttrFile = "signedattrs.der"
	signedDataFile = "signeddata.der"
	contentOutFile = "content.out"
	signatureFile  = "signature.bin"
	extensionsFile = "ds.ext"
)

// signerExtensions are the certificate extensions of the PQC signers made by OpenSSL.
const signerExtensions = `basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
`

var contentTypeOID = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 1}

var (
	dockerOnce sync.Once
	dockerOK   bool
)

// requireDocker skips the test under -short or without a reachable Docker daemon.
func requireDocker(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping OpenSSL cross-check in -short mode")
	}
	dockerOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		provider, err := testcontainers.NewDockerProvider()
		if err != nil {
			return
		}
		defer func() { _ = provider.Close() }()
		dockerOK = provider.Health(ctx) == nil
	})
	if !dockerOK {
		t.Skip("skipping OpenSSL cross-check: no reachable Docker daemon")
	}
}

// opensslBox runs OpenSSL commands in one container and copies files in and out.
type opensslBox struct {
	ctx context.Context
	ctr testcontainers.Container
}

func startOpenSSL(t *testing.T) *opensslBox {
	t.Helper()
	requireDocker(t)
	buildContext, err := filepath.Abs(filepath.Join("testdata", "openssl"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{Context: buildContext, Dockerfile: "Dockerfile"},
			Cmd:            []string{"sleep", "infinity"},
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start OpenSSL container: %v", err)
	}
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(ctr) })
	return &opensslBox{ctx: ctx, ctr: ctr}
}

// run executes a shell command in the container and returns its exit code and output.
func (b *opensslBox) run(t *testing.T, script string) (int, string) {
	t.Helper()
	code, out, err := b.ctr.Exec(b.ctx, []string{"sh", "-c", script}, tcexec.Multiplexed())
	if err != nil {
		t.Fatalf("exec %q: %v", script, err)
	}
	text, _ := io.ReadAll(out)
	return code, string(text)
}

func (b *opensslBox) mustRun(t *testing.T, script string) {
	t.Helper()
	if code, out := b.run(t, script); code != 0 {
		t.Fatalf("%q exited %d: %s", script, code, out)
	}
}

func (b *opensslBox) write(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := b.ctr.CopyToContainer(b.ctx, data, workDir+"/"+name, 0o644); err != nil {
		t.Fatalf("copy %s into container: %v", name, err)
	}
}

func (b *opensslBox) read(t *testing.T, name string) []byte {
	t.Helper()
	rc, err := b.ctr.CopyFileFromContainer(b.ctx, workDir+"/"+name)
	if err != nil {
		t.Fatalf("copy %s out of container: %v", name, err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// testCA is the certificate authority the signers are issued by.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, box *opensslBox) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	box.write(t, caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	box.write(t, "ca.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	box.write(t, extensionsFile, []byte(signerExtensions))
	return &testCA{cert: cert, key: key}
}

// issue makes a signer certificate for pub, valid for digital signatures.
func (ca *testCA) issue(t *testing.T, pub crypto.PublicKey, serial int64) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "Test signer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// opensslSigner is a signer whose key lives in the container.
type opensslSigner struct {
	box  *opensslBox
	name string
}

// makeOpenSSLSigner generates a key and a CA-issued certificate in the container.
func makeOpenSSLSigner(t *testing.T, box *opensslBox, name, keyAlgorithm string) (*x509.Certificate, signFunc) {
	t.Helper()
	box.mustRun(t, "set -e; "+
		"openssl genpkey -algorithm "+keyAlgorithm+" -out "+name+".key; "+
		"openssl req -new -key "+name+".key -subj /CN=Test-"+name+" -out "+name+".csr; "+
		"openssl x509 -req -in "+name+".csr -CA "+caFile+" -CAkey ca.key -CAcreateserial -days 30 "+
		"-extfile "+extensionsFile+" -out "+name+".pem")
	block, _ := pem.Decode(box.read(t, name+".pem"))
	if block == nil {
		t.Fatalf("%s.pem: no PEM block", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signer := opensslSigner{box: box, name: name}
	return cert, signer.sign
}

func (s opensslSigner) sign(t *testing.T, signedAttributes []byte) []byte {
	t.Helper()
	s.box.write(t, signedAttrFile, signedAttributes)
	s.box.mustRun(t, "openssl pkeyutl -sign -rawin -inkey "+s.name+".key -in "+signedAttrFile+" -out "+signatureFile)
	return s.box.read(t, signatureFile)
}

// signFunc signs the DER of the signed attributes.
type signFunc func(t *testing.T, signedAttributes []byte) []byte

func hashedSigner(h crypto.Hash, sign func(digest []byte) ([]byte, error)) signFunc {
	return func(t *testing.T, signedAttributes []byte) []byte {
		t.Helper()
		hasher := h.New()
		hasher.Write(signedAttributes)
		sig, err := sign(hasher.Sum(nil))
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
}

type crossCheckCase struct {
	code string
	cert *x509.Certificate
	sign signFunc
}

func goKeyCases(t *testing.T, ca *testCA) []crossCheckCase {
	t.Helper()
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
	pssOptions := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	return []crossCheckCase{
		{"SHA256withRSA", ca.issue(t, &rsaKey.PublicKey, 10),
			hashedSigner(crypto.SHA256, func(d []byte) ([]byte, error) {
				return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, d)
			})},
		{"SHA256withRSAandMGF1", ca.issue(t, &rsaKey.PublicKey, 11),
			hashedSigner(crypto.SHA256, func(d []byte) ([]byte, error) {
				return rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, d, pssOptions)
			})},
		{"SHA256withECDSA", ca.issue(t, &ecKey.PublicKey, 12),
			hashedSigner(crypto.SHA256, func(d []byte) ([]byte, error) {
				return ecdsa.SignASN1(rand.Reader, ecKey, d)
			})},
		{"Ed25519", ca.issue(t, edPub, 13),
			func(t *testing.T, msg []byte) []byte { return ed25519.Sign(edKey, msg) }},
	}
}

func opensslKeyCases(t *testing.T, box *opensslBox) []crossCheckCase {
	t.Helper()
	mldsaCert, mldsaSign := makeOpenSSLSigner(t, box, "mldsa65", "ML-DSA-65")
	slhCert, slhSign := makeOpenSSLSigner(t, box, "slhdsa128s", "SLH-DSA-SHA2-128s")
	return []crossCheckCase{
		{"ML-DSA-65", mldsaCert, mldsaSign},
		{"SLH-DSA-SHA2-128S", slhCert, slhSign},
	}
}

// buildSignedData signs content with the case's key and returns the SignedData.
func buildSignedData(t *testing.T, c crossCheckCase, content []byte) []byte {
	t.Helper()
	alg, ok := Lookup(c.code)
	if !ok {
		t.Fatalf("unknown code %s", c.code)
	}
	hasher := alg.Hash.New()
	hasher.Write(content)
	signingTime := time.Now().UTC()
	attrs, err := SignedAttributes(SignedAttributesInput{
		ContentType:         contentTypeOID,
		MessageDigest:       hasher.Sum(nil),
		SigningTime:         &signingTime,
		AlgorithmProtection: &alg,
	})
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := SignedData(SignedDataInput{
		ContentType:      contentTypeOID,
		Content:          content,
		Certificates:     []*x509.Certificate{c.cert},
		Signer:           c.cert,
		SignerIdentifier: IssuerAndSerialNumber,
		Algorithm:        alg,
		SignedAttributes: attrs,
		Signature:        c.sign(t, attrs),
	})
	if err != nil {
		t.Fatal(err)
	}
	return signedData
}

func (b *opensslBox) cmsVerify(t *testing.T, signedData []byte) (int, string) {
	t.Helper()
	b.write(t, signedDataFile, signedData)
	return b.run(t, "rm -f "+contentOutFile+"; openssl cms -verify -inform DER -binary -CAfile "+caFile+
		" -in "+signedDataFile+" -out "+contentOutFile)
}

func TestOpenSSLVerifiesSignedData(t *testing.T) {
	box := startOpenSSL(t)
	ca := newTestCA(t, box)
	cases := append(goKeyCases(t, ca), opensslKeyCases(t, box)...)
	content := bytes.Repeat([]byte("EF.SOD content "), 4)

	for _, c := range cases {
		t.Run(c.code, func(t *testing.T) {
			signedData := buildSignedData(t, c, content)

			code, out := box.cmsVerify(t, signedData)
			if code != 0 {
				t.Fatalf("openssl cms -verify exited %d: %s", code, out)
			}
			if got := box.read(t, contentOutFile); !bytes.Equal(got, content) {
				t.Fatalf("content = %x, want %x", got, content)
			}

			tampered := bytes.Clone(signedData)
			at := bytes.Index(tampered, content)
			if at < 0 {
				t.Fatal("content not found in SignedData")
			}
			tampered[at] ^= 0x01
			if code, _ := box.cmsVerify(t, tampered); code == 0 {
				t.Fatal("openssl accepted SignedData with a changed content byte")
			}
		})
	}
}
