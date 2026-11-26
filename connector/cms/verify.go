package cms

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

// ErrNotVerifiable reports an algorithm whose signatures this package cannot check.
var ErrNotVerifiable = errors.New("cms: signature algorithm cannot be verified")

var errBadSignature = errors.New("cms: signature verification failed")

// Verify checks signature over signedAttributes (the DER SET returned by SignedAttributes) with
// the public key of cert. RSASSA-PSS needs a salt as long as the hash, and an ECDSA signature
// must be a DER SEQUENCE of r and s. ML-DSA and SLH-DSA yield ErrNotVerifiable.
func Verify(alg Algorithm, cert *x509.Certificate, signedAttributes, signature []byte) error {
	if !alg.Verifiable {
		return fmt.Errorf("%w: %s", ErrNotVerifiable, alg.Code)
	}
	keyType, _, err := CertificateKeyType(cert)
	if err != nil {
		return err
	}
	if keyType != alg.KeyType {
		return fmt.Errorf("cms: certificate key type %s does not match algorithm key type %s", keyType, alg.KeyType)
	}
	switch pub := cert.PublicKey.(type) {
	case ed25519.PublicKey:
		if ed25519.Verify(pub, signedAttributes, signature) {
			return nil
		}
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(pub, digestOf(alg, signedAttributes), signature) {
			return nil
		}
	case *rsa.PublicKey:
		return verifyRSA(alg, pub, digestOf(alg, signedAttributes), signature)
	default:
		return fmt.Errorf("cms: unsupported public key type %T", cert.PublicKey)
	}
	return errBadSignature
}

func verifyRSA(alg Algorithm, pub *rsa.PublicKey, digest, signature []byte) error {
	var err error
	if alg.Signature.Algorithm.Equal(oidRSAPSS) {
		err = rsa.VerifyPSS(pub, alg.Hash, digest, signature, &rsa.PSSOptions{SaltLength: alg.Hash.Size()})
	} else {
		err = rsa.VerifyPKCS1v15(pub, alg.Hash, digest, signature) // NOSONAR - verifies an RFC 5754 sha*WithRSAEncryption signature; nothing is encrypted
	}
	if err != nil {
		return fmt.Errorf("%w: %v", errBadSignature, err)
	}
	return nil
}

func digestOf(alg Algorithm, msg []byte) []byte {
	h := alg.Hash.New()
	h.Write(msg)
	return h.Sum(nil)
}
