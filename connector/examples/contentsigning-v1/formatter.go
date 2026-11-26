package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/contentsigning/v1"
	contentsigning "github.com/OmniTrustILM/go-sdk/connector/provider/contentsigning/v1"
)

const (
	familyCode   = "demo"
	prefixName   = "prefix"
	prefixUUID   = "5b0c3f1e-7a54-4c1d-9d38-2f6a1c8e4b70"
	mediaTypeBin = "application/octet-stream"
)

// formatter is a signed-level content-signing provider with no real format:
// the data to be signed is a configured prefix followed by the document's
// SHA-256, and the signed document is that data followed by the signature.
// It declares one signature algorithm, so the SHA-256 digest always pairs with
// the requested algorithm and the context needs no algorithm of its own.
type formatter struct{}

func (formatter) Family() contentsigning.Family {
	return contentsigning.Family{
		Code:                familyCode,
		Label:               "Demo",
		Levels:              []mdl.SignatureLevelDeclaration{{Level: mdl.SIGNATURELEVEL_SIGNED, Name: "Signed"}},
		TransferModes:       []mdl.DocumentTransferMode{mdl.DOCUMENTTRANSFERMODE_INLINE},
		SignatureAlgorithms: []mdl.SignatureAlgorithm{mdl.SIGNATUREALGORITHM_SHA256WITH_RSA},
	}
}

func (formatter) Attributes(op contentsigning.Operation) contentsigning.Attributes {
	if op != mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_DTBS {
		return contentsigning.Attributes{}
	}
	v3 := mdl.DataAttributeV3AsBaseAttributeDtoV3(&mdl.DataAttributeV3{
		Uuid:          prefixUUID,
		Name:          prefixName,
		Version:       3,
		SchemaVersion: mdl.ATTRIBUTEVERSION_V3,
		Type:          mdl.ATTRIBUTETYPE_DATA,
		ContentType:   mdl.ATTRIBUTECONTENTTYPE_STRING,
		Properties:    mdl.DataAttributeProperties{Label: "Prefix", Visible: true, Required: true},
	})
	return contentsigning.Attributes{Profile: []mdl.BaseAttributeDto{mdl.BaseAttributeDtoV3AsBaseAttributeDto(&v3)}}
}

func (f formatter) ComputeDtbs(_ context.Context, req *mdl.ComputeDtbsRequest) (*mdl.ComputeDtbsResponse, error) {
	values, err := contentsigning.Resolve(f.Attributes(mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_DTBS), req.FormattingAttributes, req.RequestAttributes)
	if err != nil {
		return nil, err
	}
	prefix, ok := values.String(prefixName)
	if !ok {
		return nil, contentsigning.AttributesRejected("attribute %q is required", prefixName)
	}
	document, err := base64.StdEncoding.DecodeString(req.Document.InlineDocumentTransfer.Document)
	if err != nil {
		return nil, contentsigning.DocumentMalformed("document is not base64: %v", err)
	}
	digest := sha256.Sum256(document)
	dtbs := base64.StdEncoding.EncodeToString(append([]byte(prefix), digest[:]...))
	return &mdl.ComputeDtbsResponse{
		Dtbs:                    dtbs,
		DocumentDigest:          base64.StdEncoding.EncodeToString(digest[:]),
		DocumentDigestAlgorithm: mdl.DIGESTALGORITHM_SHA_256,
		FormattingContext:       dtbs,
	}, nil
}

func (formatter) EmbedSignatureValue(_ context.Context, req *mdl.EmbedSignatureValueRequest) (*mdl.SignedDocumentResponse, error) {
	signed, err := base64.StdEncoding.DecodeString(req.FormattingContext)
	if err != nil {
		return nil, contentsigning.DocumentMalformed("formatting context is not base64: %v", err)
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureValue)
	if err != nil {
		return nil, contentsigning.ValidationFailed("signatureValue is not base64: %v", err)
	}
	return &mdl.SignedDocumentResponse{
		SignedDocument: base64.StdEncoding.EncodeToString(append(signed, signature...)),
		MediaType:      mediaTypeBin,
	}, nil
}
