package cms

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Attribute is a CMS attribute: a type and its values.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue // each value carries its complete DER in FullBytes
}

// SignedAttributesInput describes the signed attributes of a SignerInfo.
type SignedAttributesInput struct {
	ContentType         asn1.ObjectIdentifier // eContentType of the signed content
	MessageDigest       []byte                // digest of the content
	SigningTime         *time.Time            // omitted when nil
	AlgorithmProtection *Algorithm            // adds the CMS algorithm protection attribute when set
	Extra               []Attribute           // further attributes chosen by the caller
}

// attributeDER is Attribute of RFC 5652 section 5.3.
type attributeDER struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// algorithmProtection is CMSAlgorithmProtection of RFC 6211 section 3, with the signature
// algorithm in the implicitly tagged [1] field.
type algorithmProtection struct {
	Digest    pkix.AlgorithmIdentifier
	Signature pkix.AlgorithmIdentifier `asn1:"tag:1"`
}

// SignedAttributes returns the DER SET OF Attribute (tag 0x31) that the signature is made over,
// with the members in ascending order of their DER encodings.
func SignedAttributes(in SignedAttributesInput) ([]byte, error) {
	attrs, err := collectAttributes(in)
	if err != nil {
		return nil, err
	}
	encoded := make([][]byte, 0, len(attrs))
	for _, attr := range attrs {
		der, err := asn1.Marshal(attributeDER{Type: attr.Type, Values: attr.Values})
		if err != nil {
			return nil, fmt.Errorf("cms: encode attribute %s: %w", attr.Type, err)
		}
		encoded = append(encoded, der)
	}
	slices.SortFunc(encoded, bytes.Compare)
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: bytes.Join(encoded, nil),
	})
}

// collectAttributes gathers the mandatory, optional and extra attributes and checks the extras.
func collectAttributes(in SignedAttributesInput) ([]Attribute, error) {
	if len(in.ContentType) == 0 {
		return nil, errors.New("cms: content type is empty")
	}
	if len(in.MessageDigest) == 0 {
		return nil, errors.New("cms: message digest is empty")
	}
	contentType, err := valueOf(in.ContentType)
	if err != nil {
		return nil, err
	}
	digest, err := valueOf(in.MessageDigest)
	if err != nil {
		return nil, err
	}
	attrs := []Attribute{
		{Type: oidAttrContentType, Values: []asn1.RawValue{contentType}},
		{Type: oidAttrMessageDigest, Values: []asn1.RawValue{digest}},
	}
	if in.SigningTime != nil {
		when, err := valueOf(in.SigningTime.UTC().Truncate(time.Second))
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, Attribute{Type: oidAttrSigningTime, Values: []asn1.RawValue{when}})
	}
	if in.AlgorithmProtection != nil {
		protection, err := valueOf(algorithmProtection{
			Digest: in.AlgorithmProtection.Digest, Signature: in.AlgorithmProtection.Signature,
		})
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, Attribute{Type: oidAttrAlgorithmProtection, Values: []asn1.RawValue{protection}})
	}
	return appendExtra(attrs, in.Extra)
}

// appendExtra adds the caller's attributes, refusing empty ones and any type already present.
func appendExtra(attrs []Attribute, extra []Attribute) ([]Attribute, error) {
	seen := make(map[string]bool, len(attrs)+len(extra))
	for _, oid := range []asn1.ObjectIdentifier{oidAttrContentType, oidAttrMessageDigest, oidAttrSigningTime} {
		seen[oid.String()] = true
	}
	for _, attr := range attrs {
		seen[attr.Type.String()] = true
	}
	for _, attr := range extra {
		if len(attr.Values) == 0 {
			return nil, fmt.Errorf("cms: attribute %s has no values", attr.Type)
		}
		if seen[attr.Type.String()] {
			return nil, fmt.Errorf("cms: attribute %s is reserved or given twice", attr.Type)
		}
		seen[attr.Type.String()] = true
		attrs = append(attrs, attr)
	}
	return attrs, nil
}

// valueOf encodes v and returns it as an attribute value.
func valueOf(v any) (asn1.RawValue, error) {
	der, err := asn1.Marshal(v)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("cms: encode attribute value: %w", err)
	}
	return asn1.RawValue{FullBytes: der}, nil
}
