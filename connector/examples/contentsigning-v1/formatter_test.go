package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/contentsigning/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func prefixAttr(t *testing.T, value string) mdl.RequestAttribute {
	t.Helper()
	raw := `{"uuid":"` + prefixUUID + `","name":"prefix","version":"v3","contentType":"string","content":[{"contentType":"string","data":"` + value + `"}]}`
	var a mdl.RequestAttribute
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func computeRequest(document []byte, attrs ...mdl.RequestAttribute) *mdl.ComputeDtbsRequest {
	return &mdl.ComputeDtbsRequest{
		Family:               familyCode,
		Document:             mdl.InlineDocumentTransferAsDocumentTransfer(&mdl.InlineDocumentTransfer{Document: b64(document), TransferMode: mdl.DOCUMENTTRANSFERMODE_INLINE}),
		FormattingAttributes: attrs,
	}
}

func TestComputeDtbsPrefixesDocumentDigest(t *testing.T) {
	document := []byte("hello")
	digest := sha256.Sum256(document)
	want := b64(append([]byte("P:"), digest[:]...))
	got, err := formatter{}.ComputeDtbs(context.Background(), computeRequest(document, prefixAttr(t, "P:")))
	if err != nil {
		t.Fatal(err)
	}
	if got.Dtbs != want || got.FormattingContext != want {
		t.Fatalf("dtbs %q, context %q, want %q", got.Dtbs, got.FormattingContext, want)
	}
	if got.DocumentDigest != b64(digest[:]) || got.DocumentDigestAlgorithm != mdl.DIGESTALGORITHM_SHA_256 {
		t.Fatalf("digest %q %q", got.DocumentDigest, got.DocumentDigestAlgorithm)
	}
}

func TestComputeDtbsErrors(t *testing.T) {
	bad := computeRequest(nil, prefixAttr(t, "P"))
	bad.Document.InlineDocumentTransfer.Document = "%%%"
	for name, tc := range map[string]struct {
		req  *mdl.ComputeDtbsRequest
		code string
	}{
		"missing prefix":   {computeRequest([]byte("x")), "ATTRIBUTES_REJECTED"},
		"document not b64": {bad, "DOCUMENT_MALFORMED"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := formatter{}.ComputeDtbs(context.Background(), tc.req)
			var se *shared.Error
			if !errors.As(err, &se) || se.Status != 422 || se.ErrorCode != tc.code {
				t.Fatalf("error = %v, want 422 %s", err, tc.code)
			}
		})
	}
}

func TestEmbedSignatureValueAppendsSignature(t *testing.T) {
	got, err := formatter{}.EmbedSignatureValue(context.Background(), &mdl.EmbedSignatureValueRequest{
		FormattingContext: b64([]byte("ctx")),
		SignatureValue:    b64([]byte("sig")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.SignedDocument != b64([]byte("ctxsig")) || got.MediaType != "application/octet-stream" {
		t.Fatalf("%+v", got)
	}
}

func TestEmbedSignatureValueErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		context, signature, code string
	}{
		"context not b64":   {"%%%", b64([]byte("s")), "DOCUMENT_MALFORMED"},
		"signature not b64": {b64([]byte("c")), "%%%", "VALIDATION_FAILED"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := formatter{}.EmbedSignatureValue(context.Background(), &mdl.EmbedSignatureValueRequest{FormattingContext: tc.context, SignatureValue: tc.signature})
			var se *shared.Error
			if !errors.As(err, &se) || se.Status != 422 || se.ErrorCode != tc.code {
				t.Fatalf("error = %v, want 422 %s", err, tc.code)
			}
		})
	}
}

func TestAttributesDeclarePrefixOnComputeOnly(t *testing.T) {
	f := formatter{}
	if got := f.Attributes(mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_DTBS); len(got.Profile) != 1 || len(got.Request) != 0 {
		t.Fatalf("%+v", got)
	}
	if got := f.Attributes(mdl.CONTENTSIGNINGFORMATTINGOPERATION_EMBED_SIGNATURE_VALUE); len(got.Profile) != 0 {
		t.Fatalf("%+v", got)
	}
}
