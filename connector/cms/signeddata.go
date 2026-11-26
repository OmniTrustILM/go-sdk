package cms

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
)

// SignerIdentifier selects how the SignerInfo names the signing certificate.
type SignerIdentifier int

// Signer identifier choices of RFC 5652 section 5.3.
const (
	IssuerAndSerialNumber SignerIdentifier = iota + 1
	SubjectKeyIdentifier
)

// SignedDataInput holds everything needed to assemble a SignedData with one signer.
type SignedDataInput struct {
	ContentType      asn1.ObjectIdentifier // eContentType
	Content          []byte                // encapsulated content, nil for detached
	Certificates     []*x509.Certificate   // written in DER SET OF order
	Signer           *x509.Certificate
	SignerIdentifier SignerIdentifier
	Algorithm        Algorithm
	SignedAttributes []byte // DER SET as returned by SignedAttributes
	Signature        []byte // signature value over SignedAttributes
}

type contentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	Encapsulated     encapsulatedContent
	Certificates     asn1.RawValue `asn1:"optional"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type encapsulatedContent struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"optional"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

// SignedData returns the DER ContentInfo wrapping a SignedData with one SignerInfo.
func SignedData(in SignedDataInput) ([]byte, error) {
	if err := validateSignedDataInput(in); err != nil {
		return nil, err
	}
	sid, sidVersion, err := signerIdentifier(in.Signer, in.SignerIdentifier)
	if err != nil {
		return nil, err
	}
	attrs, err := implicitSignedAttributes(in.SignedAttributes)
	if err != nil {
		return nil, err
	}
	encap, err := encapsulate(in.ContentType, in.Content)
	if err != nil {
		return nil, err
	}
	body, err := asn1.Marshal(signedData{
		Version:          signedDataVersion(in.ContentType, sidVersion),
		DigestAlgorithms: []pkix.AlgorithmIdentifier{in.Algorithm.Digest},
		Encapsulated:     encap,
		Certificates:     certificateSet(in.Certificates),
		SignerInfos: []signerInfo{{
			Version:            sidVersion,
			SID:                sid,
			DigestAlgorithm:    in.Algorithm.Digest,
			SignedAttrs:        attrs,
			SignatureAlgorithm: in.Algorithm.Signature,
			Signature:          in.Signature,
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("cms: encode SignedData: %w", err)
	}
	return asn1.Marshal(contentInfo{Type: oidSignedData, Content: contextTagged(0, true, body)})
}

func validateSignedDataInput(in SignedDataInput) error {
	switch {
	case in.Signer == nil:
		return errors.New("cms: signer certificate is missing")
	case len(in.ContentType) == 0:
		return errors.New("cms: content type is empty")
	case len(in.Algorithm.Digest.Algorithm) == 0 || len(in.Algorithm.Signature.Algorithm) == 0:
		return errors.New("cms: algorithm is not set")
	case len(in.Signature) == 0:
		return errors.New("cms: signature is empty")
	}
	for _, cert := range in.Certificates {
		if cert == nil {
			return errors.New("cms: certificate list holds a nil entry")
		}
	}
	return nil
}

// signerIdentifier returns the SignerIdentifier element and the SignerInfo version it implies.
func signerIdentifier(cert *x509.Certificate, choice SignerIdentifier) (asn1.RawValue, int, error) {
	switch choice {
	case IssuerAndSerialNumber:
		der, err := asn1.Marshal(issuerAndSerial{
			Issuer: asn1.RawValue{FullBytes: cert.RawIssuer},
			Serial: cert.SerialNumber,
		})
		if err != nil {
			return asn1.RawValue{}, 0, fmt.Errorf("cms: encode issuer and serial number: %w", err)
		}
		return asn1.RawValue{FullBytes: der}, 1, nil
	case SubjectKeyIdentifier:
		if len(cert.SubjectKeyId) == 0 {
			return asn1.RawValue{}, 0, errors.New("cms: signer certificate has no subject key identifier")
		}
		return contextTagged(0, false, cert.SubjectKeyId), 3, nil
	}
	return asn1.RawValue{}, 0, fmt.Errorf("cms: unknown signer identifier %d", choice)
}

// signedDataVersion applies RFC 5652 section 5.1: 3 when a SignerInfo is version 3 or the content
// type is not id-data, otherwise 1.
func signedDataVersion(contentType asn1.ObjectIdentifier, signerVersion int) int {
	if signerVersion == 3 || !contentType.Equal(oidData) {
		return 3
	}
	return 1
}

// implicitSignedAttributes turns the DER SET returned by SignedAttributes into the [0] IMPLICIT
// form used inside a SignerInfo.
func implicitSignedAttributes(set []byte) (asn1.RawValue, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(set, &raw)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("cms: signed attributes are not DER: %w", err)
	}
	if len(rest) != 0 || raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSet || !raw.IsCompound {
		return asn1.RawValue{}, errors.New("cms: signed attributes must be a single DER SET")
	}
	return contextTagged(0, true, raw.Bytes), nil
}

// encapsulate builds EncapsulatedContentInfo with the content in an explicit [0] OCTET STRING.
func encapsulate(contentType asn1.ObjectIdentifier, content []byte) (encapsulatedContent, error) {
	encap := encapsulatedContent{Type: contentType}
	if content == nil {
		return encap, nil
	}
	octets, err := asn1.Marshal(content)
	if err != nil {
		return encapsulatedContent{}, fmt.Errorf("cms: encode content: %w", err)
	}
	encap.Content = contextTagged(0, true, octets)
	return encap, nil
}

// certificateSet returns [0] IMPLICIT CertificateSet with the encodings sorted as DER requires
// for a SET OF, or the zero value when there is none.
func certificateSet(certs []*x509.Certificate) asn1.RawValue {
	if len(certs) == 0 {
		return asn1.RawValue{}
	}
	raws := make([][]byte, len(certs))
	for i, cert := range certs {
		raws[i] = cert.Raw
	}
	slices.SortFunc(raws, bytes.Compare)
	return contextTagged(0, true, bytes.Join(raws, nil))
}

func contextTagged(tag int, constructed bool, content []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: constructed, Bytes: content}
}
