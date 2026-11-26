package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

var verifyMessage = []byte{0x31, 0x03, 0x04, 0x01, 0x07}

// signer produces a signature over the message and returns it with the matching certificate.
type signer func(t *testing.T, alg Algorithm, msg []byte) (*x509.Certificate, []byte)

func hashed(h crypto.Hash, msg []byte) []byte {
	hh := h.New()
	hh.Write(msg)
	return hh.Sum(nil)
}

func rsaSigner(pss bool, saltLength int) signer {
	return func(t *testing.T, alg Algorithm, msg []byte) (*x509.Certificate, []byte) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		var sig []byte
		if pss {
			sig, err = rsa.SignPSS(rand.Reader, key, alg.Hash, hashed(alg.Hash, msg), &rsa.PSSOptions{SaltLength: saltLength})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, key, alg.Hash, hashed(alg.Hash, msg))
		}
		if err != nil {
			t.Fatal(err)
		}
		return selfSigned(t, &key.PublicKey, key, certOptions{}), sig
	}
}

func ecdsaSigner(curve elliptic.Curve, raw bool) signer {
	return func(t *testing.T, alg Algorithm, msg []byte) (*x509.Certificate, []byte) {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		digest := hashed(alg.Hash, msg)
		var sig []byte
		if raw {
			r, s, err := ecdsa.Sign(rand.Reader, key, digest)
			if err != nil {
				t.Fatal(err)
			}
			sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		} else if sig, err = ecdsa.SignASN1(rand.Reader, key, digest); err != nil {
			t.Fatal(err)
		}
		return selfSigned(t, &key.PublicKey, key, certOptions{}), sig
	}
}

func ed25519Signer(t *testing.T, _ Algorithm, msg []byte) (*x509.Certificate, []byte) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return selfSigned(t, pub, key, certOptions{}), ed25519.Sign(key, msg)
}

func TestVerifyValidAndTampered(t *testing.T) {
	cases := []struct {
		name string
		code string
		sign signer
	}{
		{"pkcs1 sha256", "SHA256withRSA", rsaSigner(false, 0)},
		{"pkcs1 sha512", "SHA512withRSA", rsaSigner(false, 0)},
		{"pss sha256", "SHA256withRSAandMGF1", rsaSigner(true, 32)},
		{"pss sha384", "SHA384withRSAandMGF1", rsaSigner(true, 48)},
		{"pss sha512", "SHA512withRSAandMGF1", rsaSigner(true, 64)},
		{"ecdsa p256", "SHA256withECDSA", ecdsaSigner(elliptic.P256(), false)},
		{"ecdsa p384", "SHA384withECDSA", ecdsaSigner(elliptic.P384(), false)},
		{"ed25519", "Ed25519", ed25519Signer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alg, _ := Lookup(tc.code)
			cert, sig := tc.sign(t, alg, verifyMessage)
			if err := Verify(alg, cert, verifyMessage, sig); err != nil {
				t.Fatalf("valid signature rejected: %v", err)
			}
			flipped := append([]byte(nil), sig...)
			flipped[len(flipped)-1] ^= 0x01
			if err := Verify(alg, cert, verifyMessage, flipped); err == nil {
				t.Error("flipped signature bit accepted")
			}
			other := append([]byte(nil), verifyMessage...)
			other[len(other)-1] ^= 0x01
			if err := Verify(alg, cert, other, sig); err == nil {
				t.Error("changed message accepted")
			}
		})
	}
}

func TestVerifyRejectsWrongForm(t *testing.T) {
	cases := []struct {
		name string
		code string
		sign signer
	}{
		{"pss with maximal salt", "SHA256withRSAandMGF1", rsaSigner(true, rsa.PSSSaltLengthAuto)},
		{"pss with empty salt", "SHA256withRSAandMGF1", rsaSigner(true, 0)},
		{"pkcs1 signature under pss algorithm", "SHA256withRSAandMGF1", rsaSigner(false, 0)},
		{"pss signature under pkcs1 algorithm", "SHA256withRSA", rsaSigner(true, 32)},
		{"raw ecdsa r||s", "SHA256withECDSA", ecdsaSigner(elliptic.P256(), true)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alg, _ := Lookup(tc.code)
			cert, sig := tc.sign(t, alg, verifyMessage)
			if err := Verify(alg, cert, verifyMessage, sig); err == nil {
				t.Error("signature accepted")
			}
		})
	}
}

func TestVerifyKeyTypeMismatch(t *testing.T) {
	alg, _ := Lookup("SHA256withRSA")
	ecAlg, _ := Lookup("SHA256withECDSA")
	cert, sig := ecdsaSigner(elliptic.P256(), false)(t, ecAlg, verifyMessage)
	err := Verify(alg, cert, verifyMessage, sig)
	if err == nil || !strings.Contains(err.Error(), "ECDSA") || !strings.Contains(err.Error(), "RSA") {
		t.Errorf("error must name both key types, got %v", err)
	}
}

func TestVerifyNotVerifiable(t *testing.T) {
	cases := map[string]string{"ML-DSA-65": "mldsa65.pem", "SLH-DSA-SHA2-128S": "slhdsa-sha2-128s.pem"}
	for code, certFile := range cases {
		t.Run(code, func(t *testing.T) {
			alg, _ := Lookup(code)
			err := Verify(alg, loadCertificate(t, certFile), verifyMessage, []byte{1})
			if !errors.Is(err, ErrNotVerifiable) {
				t.Errorf("got %v, want ErrNotVerifiable", err)
			}
		})
	}
}

func TestVerifyInvalidInput(t *testing.T) {
	alg, _ := Lookup("SHA256withRSA")
	if err := Verify(alg, nil, verifyMessage, []byte{1}); err == nil {
		t.Error("nil certificate accepted")
	}
	if err := Verify(alg, loadCertificate(t, "mldsa65.pem"), verifyMessage, []byte{1}); err == nil {
		t.Error("certificate of another key type accepted")
	}
}
