package main_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/contentsigning/v1"
)

const base = "/v1/signatureProvider/contentSigning"

func startConnector(t *testing.T) *itest.Harness {
	t.Helper()
	return itest.Start(t, itest.Example{Path: "connector/examples/contentsigning-v1"})
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// wire marshals v, which makes models comparable by their wire form.
func wire(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestContentSigningV1InfoHealthAndDeclaration(t *testing.T) {
	h := startConnector(t)
	h.AssertHealthy(t, "/v2/health")
	var info mdl.InfoResponse
	if status := h.GetJSON(t, "GET", "/v2/info", nil, &info); status != 200 {
		t.Fatal(status)
	}
	if !slices.ContainsFunc(info.Interfaces, func(i mdl.ConnectorInterfaceInfo) bool {
		return i.Code == mdl.CONNECTORINTERFACE_CONTENT_SIGNING_FORMATTING && i.Version == "v1"
	}) {
		t.Fatalf("contentSigningFormatting v1 absent: %+v", info)
	}
	var decl mdl.ContentSigningDeclaration
	if status := h.GetJSON(t, "GET", base+"/declaration", nil, &decl); status != 200 || len(decl.Families) != 1 {
		t.Fatalf("%d %+v", status, decl)
	}
	f := decl.Families[0]
	if f.Code != "demo" || len(f.Levels) != 1 || f.Levels[0].Level != mdl.SIGNATURELEVEL_SIGNED ||
		!slices.Equal(f.TransferModes, []mdl.DocumentTransferMode{mdl.DOCUMENTTRANSFERMODE_INLINE}) || !slices.Equal(f.SignatureAlgorithms, []mdl.SignatureAlgorithm{mdl.SIGNATUREALGORITHM_SHA256WITH_RSA}) {
		t.Fatalf("%+v", f)
	}
	var attrs mdl.ContentSigningFormattingAttributes
	if status := h.GetJSON(t, "GET", base+"/computeDtbs/attributes", nil, &attrs); status != 200 || len(attrs.ProfileAttributes) != 1 || len(attrs.RequestAttributes) != 0 {
		t.Fatalf("%d %+v", status, attrs)
	}
	h.AssertLogsConform(t)
}

func TestContentSigningV1ComputeAndEmbed(t *testing.T) {
	h := startConnector(t)
	document := []byte("document body")
	digest := sha256.Sum256(document)
	dtbs := append([]byte("PFX-"), digest[:]...)
	compute := map[string]any{
		"family":                 "demo",
		"document":               map[string]any{"transferMode": "inline", "document": b64(document)},
		"signerCertificateChain": []string{b64([]byte("cert"))},
		"signingTime":            "2026-01-01T00:00:00Z",
		"signatureAlgorithm":     "SHA256withRSA",
		"requestAttributes":      []any{},
		"formattingAttributes": []any{map[string]any{
			"uuid": "5b0c3f1e-7a54-4c1d-9d38-2f6a1c8e4b70", "name": "prefix", "version": "v3", "contentType": "string",
			"content": []any{map[string]any{"contentType": "string", "data": "PFX-"}},
		}},
	}
	var computed mdl.ComputeDtbsResponse
	if status := h.GetJSON(t, "POST", base+"/computeDtbs", compute, &computed); status != 200 {
		t.Fatal(status)
	}
	want := mdl.ComputeDtbsResponse{Dtbs: b64(dtbs), DocumentDigest: b64(digest[:]), DocumentDigestAlgorithm: mdl.DIGESTALGORITHM_SHA_256, FormattingContext: b64(dtbs)}
	if wire(t, computed) != wire(t, want) {
		t.Fatalf("computeDtbs = %s, want %s", wire(t, computed), wire(t, want))
	}
	signature := []byte("signature")
	var signed mdl.SignedDocumentResponse
	embed := map[string]any{"family": "demo", "formattingAttributes": []any{}, "signatureValue": b64(signature), "signatureAlgorithm": "SHA256withRSA", "formattingContext": computed.FormattingContext}
	if status := h.GetJSON(t, "POST", base+"/embedSignatureValue", embed, &signed); status != 200 {
		t.Fatal(status)
	}
	got, err := base64.StdEncoding.DecodeString(signed.SignedDocument)
	if err != nil || !bytes.Equal(got, append(dtbs, signature...)) || signed.MediaType != "application/octet-stream" {
		t.Fatalf("signed document %q (%v), media type %q", got, err, signed.MediaType)
	}
	h.AssertLogsConform(t)
}

func TestContentSigningV1ExtendToLevelUnsupported(t *testing.T) {
	h := startConnector(t)
	body := map[string]any{
		"family":               "demo",
		"formattingAttributes": []any{},
		"signedDocument":       b64([]byte("signed")),
		"targetLevel":          "long_term",
		"certificateChain":     map[string]any{"certificates": []string{}, "trustAnchors": []string{}},
		"executionMode":        "synchronous",
	}
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: base + "/extendToLevel", Body: body})
	itest.AssertProblem(t, resp, 422, "PARAMETER_UNSUPPORTED")
	h.AssertLogsConform(t)
}
