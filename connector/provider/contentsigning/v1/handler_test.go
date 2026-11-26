package contentsigning

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/contentsigning/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const base = DefaultBasePath

var (
	levelSigned      = mdl.SIGNATURELEVEL_SIGNED
	levelTimestamped = mdl.SIGNATURELEVEL_TIMESTAMPED
	levelLongTerm    = mdl.SIGNATURELEVEL_LONG_TERM
	levelArchival    = mdl.SIGNATURELEVEL_ARCHIVAL
)

func demoFamily(levels ...mdl.SignatureLevel) Family {
	f := Family{Code: "demo", Label: "Demo", TransferModes: []mdl.DocumentTransferMode{mdl.DOCUMENTTRANSFERMODE_INLINE}}
	for _, l := range levels {
		f.Levels = append(f.Levels, mdl.SignatureLevelDeclaration{Level: l, Name: string(l)})
	}
	return f
}

func dataAttr(name, label string, ct mdl.AttributeContentType) mdl.BaseAttributeDto {
	v3 := mdl.DataAttributeV3AsBaseAttributeDtoV3(&mdl.DataAttributeV3{
		Uuid:          "d0235059-d463-4937-a2aa-20efdd000001",
		Name:          name,
		SchemaVersion: mdl.ATTRIBUTEVERSION_V3,
		Version:       3,
		Type:          mdl.ATTRIBUTETYPE_DATA,
		ContentType:   ct,
		Properties:    mdl.DataAttributeProperties{Label: label, Visible: true},
	})
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&v3)
}

func infoAttr(name string) mdl.BaseAttributeDto {
	v3 := mdl.InfoAttributeV3AsBaseAttributeDtoV3(&mdl.InfoAttributeV3{
		Uuid:          "d0235059-d463-4937-a2aa-20efdd000002",
		Name:          name,
		SchemaVersion: mdl.ATTRIBUTEVERSION_V3,
		Type:          mdl.ATTRIBUTETYPE_INFO,
		ContentType:   mdl.ATTRIBUTECONTENTTYPE_TEXT,
		Properties:    mdl.InfoAttributeProperties{Label: name, Visible: true},
	})
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&v3)
}

// basic implements Provider only.
type basic struct {
	family      Family
	attrs       map[Operation]Attributes
	err         error
	nilResponse bool

	gotDtbs  *mdl.ComputeDtbsRequest
	gotEmbed *mdl.EmbedSignatureValueRequest
}

func newBasic(levels ...mdl.SignatureLevel) *basic {
	return &basic{family: demoFamily(levels...)}
}

func (b *basic) Family() Family                     { return b.family }
func (b *basic) Attributes(op Operation) Attributes { return b.attrs[op] }

func (b *basic) ComputeDtbs(_ context.Context, in *mdl.ComputeDtbsRequest) (*mdl.ComputeDtbsResponse, error) {
	b.gotDtbs = in
	if b.nilResponse {
		return nil, b.err
	}
	return mdl.NewComputeDtbsResponse("ZHRicw==", "ZGlnZXN0", mdl.DIGESTALGORITHM_SHA_256, "Y3R4"), b.err
}

func (b *basic) EmbedSignatureValue(_ context.Context, in *mdl.EmbedSignatureValueRequest) (*mdl.SignedDocumentResponse, error) {
	b.gotEmbed = in
	return mdl.NewSignedDocumentResponse("c2lnbmVk", "application/octet-stream"), b.err
}

type validateMethods struct{}

func (validateMethods) ValidateProfile(context.Context, *mdl.ValidateProfileRequest) (*mdl.ValidateProfileResponse, error) {
	return &mdl.ValidateProfileResponse{Errors: []mdl.ProfileAttributeError{{AttributeName: "x", Reason: "bad"}}}, nil
}

type timestampMethods struct{}

func (timestampMethods) ComputeSignatureTimestampImprint(context.Context, *mdl.SignedDocumentRequest) (*mdl.TimestampImprintResponse, error) {
	return mdl.NewTimestampImprintResponse("c2ln", mdl.DIGESTALGORITHM_SHA_256), nil
}
func (timestampMethods) EmbedSignatureTimestamp(context.Context, *mdl.EmbedTimestampRequest) (*mdl.SignedDocumentResponse, error) {
	return mdl.NewSignedDocumentResponse("c2ln", "application/octet-stream"), nil
}

type archiveMethods struct{}

func (archiveMethods) ComputeArchiveTimestampImprint(context.Context, *mdl.SignedDocumentRequest) (*mdl.TimestampImprintResponse, error) {
	return mdl.NewTimestampImprintResponse("YXJj", mdl.DIGESTALGORITHM_SHA_256), nil
}
func (archiveMethods) EmbedArchiveTimestamp(context.Context, *mdl.EmbedTimestampRequest) (*mdl.SignedDocumentResponse, error) {
	return mdl.NewSignedDocumentResponse("YXJj", "application/octet-stream"), nil
}

type extendMethods struct{ cancelled *bool }

func (extendMethods) ExtendToLevel(context.Context, *mdl.ExtendToLevelRequest) (*mdl.ExtendToLevelResponse, error) {
	return mdl.NewExtendToLevelResponse(), nil
}
func (extendMethods) ExtendStatus(context.Context, *mdl.ExtendOperationScopedRequest) (*mdl.ExtendOperationStatusResponse, error) {
	return mdl.NewExtendOperationStatusResponse(mdl.OPERATIONSTATUS_COMPLETED), nil
}
func (e extendMethods) ExtendCancel(context.Context, *mdl.ExtendOperationScopedRequest) error {
	*e.cancelled = true
	return nil
}

type withValidator struct {
	*basic
	validateMethods
}

type withTimestamp struct {
	*basic
	timestampMethods
}

type withArchive struct {
	*basic
	archiveMethods
}

type withExtend struct {
	*basic
	extendMethods
}

// full implements every optional capability.
type full struct {
	*basic
	validateMethods
	timestampMethods
	archiveMethods
	extendMethods
}

func newFull(cancelled *bool) *full {
	return &full{basic: newBasic(levelSigned, levelTimestamped, levelLongTerm, levelArchival), extendMethods: extendMethods{cancelled}}
}

func serve(t *testing.T, p Provider, opts ...Option) *shared.Connector {
	t.Helper()
	h, err := NewHandler(p, opts...)
	if err != nil {
		t.Fatal(err)
	}
	c, err := shared.New(shared.Register(h))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func do(t *testing.T, c *shared.Connector, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c.Handler().ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewBufferString(body)))
	return w
}

func post(t *testing.T, c *shared.Connector, route string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, ok := body.(string)
	if !ok {
		raw = string(mustJSON(t, body))
	}
	return do(t, c, http.MethodPost, base+"/"+route, raw)
}

func get(t *testing.T, c *shared.Connector, route string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, c, http.MethodGet, base+"/"+route, "")
}

// wantProblem asserts a problem response and returns its detail.
func wantProblem(t *testing.T, w *httptest.ResponseRecorder, status int, code string) string {
	t.Helper()
	var p shared.ProblemDetail
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("not a problem: %v: %s", err, w.Body)
	}
	if w.Code != status || p.ErrorCode != code {
		t.Fatalf("got %d %s, want %d %s: %s", w.Code, p.ErrorCode, status, code, w.Body)
	}
	if p.Detail == nil {
		return ""
	}
	return *p.Detail
}

func decodeBody[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type body map[string]any

func (b body) with(k string, v any) body {
	c := body{}
	for key, val := range b {
		c[key] = val
	}
	c[k] = v
	return c
}

func (b body) without(k string) body {
	c := b.with(k, nil)
	delete(c, k)
	return c
}

var (
	inlineDoc = body{"transferMode": "inline", "document": "aGk="}
	digestDoc = body{"transferMode": "digestOnly", "documentDigest": "ZGlnZXN0", "digestAlgorithm": "SHA-256"}
	common    = body{"family": "demo", "formattingAttributes": []any{}}

	dtbsBody = common.with("document", inlineDoc).with("signerCertificateChain", []string{"Y2VydA=="}).
			with("signingTime", "2026-11-24T12:00:00Z").with("signatureAlgorithm", "SHA256withRSA").with("requestAttributes", []any{})
	embedBody  = common.with("signatureValue", "c2ln").with("signatureAlgorithm", "SHA256withRSA").with("formattingContext", "Y3R4")
	signedBody = common.with("signedDocument", "c2Q=")
	stampBody  = signedBody.with("timestampToken", "dG9rZW4=")
	extendBody = signedBody.with("targetLevel", "long_term").with("certificateChain", body{"certificates": []any{}, "trustAnchors": []any{}}).
			with("executionMode", "synchronous")
	scopedBody = common.with("operationMeta", []any{body{"uuid": "d0235059-d463-4937-a2aa-20efdd000002", "name": "handle", "version": 3,
		"schemaVersion": "v3", "type": "meta", "contentType": "string", "properties": body{"label": "Handle", "visible": false},
		"content": []any{body{"contentType": "string", "data": "op-1"}}}})
	profileBody = common.with("allowedRequestAttributes", []any{})
)

func TestDeclaration(t *testing.T) {
	c := serve(t, newBasic(levelSigned))
	got := decodeBody[mdl.ContentSigningDeclaration](t, get(t, c, "declaration"))
	if len(got.Families) != 1 || got.Families[0].Code != "demo" || len(got.Families[0].Levels) != 1 {
		t.Fatalf("declaration = %+v", got)
	}
}

func TestAttributesListsDeclaredAndNeverNull(t *testing.T) {
	p := newBasic(levelSigned)
	p.attrs = map[Operation]Attributes{
		mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_DTBS: {
			Profile: []mdl.BaseAttributeDto{dataAttr("prefix", "Prefix", mdl.ATTRIBUTECONTENTTYPE_STRING)},
			Request: []mdl.BaseAttributeDto{dataAttr("tag", "Tag", mdl.ATTRIBUTECONTENTTYPE_STRING)},
		},
	}
	c := serve(t, p)

	got := decodeBody[mdl.ContentSigningFormattingAttributes](t, get(t, c, "computeDtbs/attributes"))
	if len(got.ProfileAttributes) != 1 || len(got.RequestAttributes) != 1 {
		t.Fatalf("attributes = %+v", got)
	}
	w := get(t, c, "embedSignatureValue/attributes")
	if s := strings.TrimSpace(w.Body.String()); s != `{"profileAttributes":[],"requestAttributes":[]}` {
		t.Fatalf("empty lists must be []: %s", s)
	}
	wantProblem(t, get(t, c, "nonsense/attributes"), 400, "BAD_REQUEST")
}

func TestInterfaceInfo(t *testing.T) {
	c := serve(t, newBasic(levelSigned))
	info := decodeBody[shared.V2InfoResponse](t, do(t, c, http.MethodGet, "/v2/info", ""))
	want := shared.InterfaceInfo{Code: "contentSigningFormatting", Version: "v1"}
	if !slices.ContainsFunc(info.Interfaces, func(i shared.InterfaceInfo) bool { return i.Code == want.Code && i.Version == want.Version }) {
		t.Fatalf("interfaces = %+v", info.Interfaces)
	}
}

func TestBaseOptionsApply(t *testing.T) {
	c := serve(t, newBasic(levelSigned), Base(handlerbase.WithBasePath("/custom")))
	if w := do(t, c, http.MethodGet, "/custom/declaration", ""); w.Code != 200 {
		t.Fatalf("custom base path: %d", w.Code)
	}
	if _, err := NewHandler(newBasic(levelSigned), Base(handlerbase.WithBasePath(""))); err == nil {
		t.Fatal("an invalid base option must fail NewHandler")
	}
}

func TestBodiesThatAreNotRequests(t *testing.T) {
	c := serve(t, newBasic(levelSigned), Base(handlerbase.WithMaxRequestBytes(64)))
	for name, raw := range map[string]string{"malformed": `{"family":`, "empty": ``, "trailing": string(mustJSON(t, dtbsBody)) + ` {}`} {
		t.Run(name, func(t *testing.T) { wantProblem(t, post(t, c, "computeDtbs", raw), 400, "BAD_REQUEST") })
	}
	t.Run("too large", func(t *testing.T) { wantProblem(t, post(t, c, "computeDtbs", dtbsBody), 400, "BAD_REQUEST") })
	c = serve(t, newBasic(levelSigned))
	for name, b := range map[string]any{
		"unknown transfer mode":         dtbsBody.with("document", body{"transferMode": "stream"}),
		"absent transfer mode":          dtbsBody.with("document", body{"document": "aGk="}),
		"detached without transferMode": extendBody.with("detachedContent", body{"document": "aGk="}),
	} {
		t.Run(name, func(t *testing.T) {
			route := "computeDtbs"
			if _, ok := b.(body)["signedDocument"]; ok {
				route = "extendToLevel"
			}
			if detail := wantProblem(t, post(t, c, route, b), 400, "BAD_REQUEST"); !strings.Contains(detail, "transferMode") {
				t.Fatalf("detail %q does not name transferMode", detail)
			}
		})
	}
	for name, b := range map[string]any{
		"wrong field type":       dtbsBody.with("family", 5),
		"null signing time":      dtbsBody.with("signingTime", nil),
		"unknown algorithm code": dtbsBody.with("signatureAlgorithm", "SHA1withDSA"),
	} {
		t.Run(name, func(t *testing.T) { wantProblem(t, post(t, c, "computeDtbs", b), 422, "VALIDATION_FAILED") })
	}
}

func TestComputeDtbsRejections(t *testing.T) {
	p := newBasic(levelSigned)
	p.family.SignatureAlgorithms = []mdl.SignatureAlgorithm{mdl.SIGNATUREALGORITHM_SHA256WITH_RSA}
	c := serve(t, p)
	for _, f := range []string{"family", "document", "signerCertificateChain", "signingTime", "signatureAlgorithm"} {
		t.Run("missing "+f, func(t *testing.T) {
			detail := wantProblem(t, post(t, c, "computeDtbs", dtbsBody.without(f)), 422, "VALIDATION_FAILED")
			if !strings.Contains(detail, f) {
				t.Fatalf("detail %q does not name %s", detail, f)
			}
		})
	}
	for name, tc := range map[string]struct {
		b      body
		code   string
		detail string
	}{
		"empty chain":         {dtbsBody.with("signerCertificateChain", []string{}), "VALIDATION_FAILED", "signerCertificateChain"},
		"empty family":        {dtbsBody.with("family", ""), "VALIDATION_FAILED", "family"},
		"malformed family":    {dtbsBody.with("family", "Demo"), "VALIDATION_FAILED", "must match"},
		"empty document":      {dtbsBody.with("document", body{"transferMode": "inline", "document": ""}), "VALIDATION_FAILED", "document"},
		"empty digest":        {dtbsBody.with("document", digestDoc.with("documentDigest", "")), "VALIDATION_FAILED", "documentDigest"},
		"other family":        {dtbsBody.with("family", "other"), "PARAMETER_UNSUPPORTED", "demo"},
		"digest only":         {dtbsBody.with("document", digestDoc), "PARAMETER_UNSUPPORTED", "inline"},
		"other algorithm":     {dtbsBody.with("signatureAlgorithm", "SHA256withECDSA"), "PARAMETER_UNSUPPORTED", "SHA256withRSA"},
		"field before family": {dtbsBody.with("family", "other").without("signingTime"), "VALIDATION_FAILED", "signingTime"},
	} {
		t.Run(name, func(t *testing.T) {
			detail := wantProblem(t, post(t, c, "computeDtbs", tc.b), 422, tc.code)
			if !strings.Contains(detail, tc.detail) {
				t.Fatalf("detail %q does not name %q", detail, tc.detail)
			}
		})
	}
}

func TestComputeDtbsReachesProvider(t *testing.T) {
	p := newBasic(levelSigned)
	c := serve(t, p)
	got := decodeBody[mdl.ComputeDtbsResponse](t, post(t, c, "computeDtbs", dtbsBody))
	if got.Dtbs != "ZHRicw==" || got.FormattingContext != "Y3R4" {
		t.Fatalf("response = %+v", got)
	}
	if p.gotDtbs == nil || p.gotDtbs.Family != "demo" || p.gotDtbs.Document.InlineDocumentTransfer == nil {
		t.Fatalf("provider saw %+v", p.gotDtbs)
	}
}

func TestFamilyWithoutAlgorithmsAcceptsAny(t *testing.T) {
	c := serve(t, newBasic(levelSigned))
	for _, alg := range []string{"SHA256withRSA", "Ed25519", "ML-DSA-65"} {
		if w := post(t, c, "computeDtbs", dtbsBody.with("signatureAlgorithm", alg)); w.Code != 200 {
			t.Fatalf("%s: %d %s", alg, w.Code, w.Body)
		}
	}
}

func TestDigestOnlyAccepted(t *testing.T) {
	p := newBasic(levelSigned)
	p.family.TransferModes = []mdl.DocumentTransferMode{mdl.DOCUMENTTRANSFERMODE_INLINE, mdl.DOCUMENTTRANSFERMODE_DIGEST_ONLY}
	c := serve(t, p)
	if w := post(t, c, "computeDtbs", dtbsBody.with("document", digestDoc)); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestProviderAnswers(t *testing.T) {
	t.Run("nil response", func(t *testing.T) {
		p := newBasic(levelSigned)
		p.nilResponse = true
		wantProblem(t, post(t, serve(t, p), "computeDtbs", dtbsBody), 500, "INTERNAL_SERVER_ERROR")
	})
	t.Run("provider error", func(t *testing.T) {
		p := newBasic(levelSigned)
		p.err = ContextMismatch("algorithm differs")
		wantProblem(t, post(t, serve(t, p), "embedSignatureValue", embedBody), 422, "CONTEXT_MISMATCH")
	})
}

func TestEmbedSignatureValue(t *testing.T) {
	p := newBasic(levelSigned)
	p.family.SignatureAlgorithms = []mdl.SignatureAlgorithm{mdl.SIGNATUREALGORITHM_SHA256WITH_RSA}
	c := serve(t, p)
	for _, f := range []string{"family", "signatureValue", "signatureAlgorithm", "formattingContext"} {
		t.Run("missing "+f, func(t *testing.T) {
			detail := wantProblem(t, post(t, c, "embedSignatureValue", embedBody.without(f)), 422, "VALIDATION_FAILED")
			if !strings.Contains(detail, f) {
				t.Fatalf("detail %q does not name %s", detail, f)
			}
		})
	}
	if w := post(t, c, "embedSignatureValue", embedBody.with("formattingContext", "")); w.Code != 200 {
		t.Fatalf("an empty formattingContext must reach the provider: %d %s", w.Code, w.Body.String())
	}
	wantProblem(t, post(t, c, "embedSignatureValue", embedBody.with("family", "other")), 422, "PARAMETER_UNSUPPORTED")
	wantProblem(t, post(t, c, "embedSignatureValue", embedBody.with("signatureValue", "")), 422, "VALIDATION_FAILED")
	wantProblem(t, post(t, c, "embedSignatureValue", embedBody.with("signatureAlgorithm", "SHA256withECDSA")), 422, "PARAMETER_UNSUPPORTED")

	got := decodeBody[mdl.SignedDocumentResponse](t, post(t, c, "embedSignatureValue", embedBody))
	if got.SignedDocument != "c2lnbmVk" || p.gotEmbed == nil || p.gotEmbed.FormattingContext != "Y3R4" {
		t.Fatalf("response %+v, provider saw %+v", got, p.gotEmbed)
	}
}

func TestValidateProfile(t *testing.T) {
	t.Run("without validator", func(t *testing.T) {
		c := serve(t, newBasic(levelSigned))
		got := decodeBody[mdl.ValidateProfileResponse](t, post(t, c, "validateProfile", profileBody))
		if len(got.Errors) != 0 || len(got.TransferModes) != 1 || got.TransferModes[0] != mdl.DOCUMENTTRANSFERMODE_INLINE {
			t.Fatalf("response = %+v", got)
		}
		if s := post(t, c, "validateProfile", profileBody).Body.String(); !strings.Contains(s, `"errors":[]`) {
			t.Fatalf("errors must be []: %s", s)
		}
		wantProblem(t, post(t, c, "validateProfile", profileBody.with("family", "other")), 422, "PARAMETER_UNSUPPORTED")
		wantProblem(t, post(t, c, "validateProfile", profileBody.without("allowedRequestAttributes")), 422, "VALIDATION_FAILED")
	})
	t.Run("with validator", func(t *testing.T) {
		c := serve(t, withValidator{basic: newBasic(levelSigned)})
		got := decodeBody[mdl.ValidateProfileResponse](t, post(t, c, "validateProfile", profileBody))
		if len(got.Errors) != 1 || got.Errors[0].AttributeName != "x" {
			t.Fatalf("response = %+v", got)
		}
		if s := post(t, c, "validateProfile", profileBody).Body.String(); !strings.Contains(s, `"transferModes":[]`) {
			t.Fatalf("transferModes must be []: %s", s)
		}
	})
	t.Run("validator without transfer modes", func(t *testing.T) {
		c := serve(t, fixedValidator{basic: newBasic(levelSigned), out: mdl.ValidateProfileResponse{}})
		got := decodeBody[mdl.ValidateProfileResponse](t, post(t, c, "validateProfile", profileBody))
		if len(got.Errors) != 0 || !slices.Equal(got.TransferModes, []mdl.DocumentTransferMode{mdl.DOCUMENTTRANSFERMODE_INLINE}) {
			t.Fatalf("response = %+v", got)
		}
	})
	t.Run("validator with an undeclared transfer mode", func(t *testing.T) {
		out := mdl.ValidateProfileResponse{TransferModes: []mdl.DocumentTransferMode{mdl.DOCUMENTTRANSFERMODE_DIGEST_ONLY}}
		c := serve(t, fixedValidator{basic: newBasic(levelSigned), out: out})
		wantProblem(t, post(t, c, "validateProfile", profileBody), 500, "INTERNAL_SERVER_ERROR")
	})
}

type fixedValidator struct {
	*basic
	out mdl.ValidateProfileResponse
}

func (v fixedValidator) ValidateProfile(context.Context, *mdl.ValidateProfileRequest) (*mdl.ValidateProfileResponse, error) {
	out := v.out
	return &out, nil
}

type optionalRoute struct {
	route string
	body  body
	level string
}

var optionalRoutes = []optionalRoute{
	{"computeSignatureTimestampImprint", signedBody, "timestamped"},
	{"embedSignatureTimestamp", stampBody, "timestamped"},
	{"computeArchiveTimestampImprint", signedBody, "archival"},
	{"embedArchiveTimestamp", stampBody, "archival"},
	{"extendToLevel", extendBody, "long_term"},
}

func TestOptionalRoutesWithoutCapability(t *testing.T) {
	c := serve(t, newBasic(levelSigned))
	for _, tc := range optionalRoutes {
		t.Run(tc.route, func(t *testing.T) {
			detail := wantProblem(t, post(t, c, tc.route, tc.body), 422, "PARAMETER_UNSUPPORTED")
			if !strings.Contains(detail, tc.level) {
				t.Fatalf("detail %q does not name %s", detail, tc.level)
			}
			wantProblem(t, post(t, c, tc.route, tc.body.without("signedDocument")), 422, "VALIDATION_FAILED")
			wantProblem(t, post(t, c, tc.route, tc.body.with("family", "other")), 422, "PARAMETER_UNSUPPORTED")
		})
	}
	wantProblem(t, post(t, c, "extendToLevel/status", scopedBody), 404, "OPERATION_NOT_TRACKED")
	wantProblem(t, post(t, c, "extendToLevel/cancel", scopedBody), 404, "OPERATION_NOT_TRACKED")
	wantProblem(t, post(t, c, "extendToLevel/status", scopedBody.with("family", "other")), 422, "PARAMETER_UNSUPPORTED")
	wantProblem(t, post(t, c, "extendToLevel", extendBody.with("targetLevel", "archival")), 422, "VALIDATION_FAILED")
	wantProblem(t, post(t, c, "extendToLevel/status", scopedBody.with("operationMeta", []any{})), 422, "VALIDATION_FAILED")
	wantProblem(t, post(t, c, "extendToLevel/cancel", scopedBody.with("operationMeta", nil)), 422, "VALIDATION_FAILED")
	for _, op := range operations {
		w := get(t, c, string(op)+"/attributes")
		if op != mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_DTBS && op != mdl.CONTENTSIGNINGFORMATTINGOPERATION_EMBED_SIGNATURE_VALUE &&
			strings.TrimSpace(w.Body.String()) != `{"profileAttributes":[],"requestAttributes":[]}` {
			t.Fatalf("%s: %s", op, w.Body)
		}
	}
}

func TestOptionalRoutesWithCapability(t *testing.T) {
	var cancelled bool
	c := serve(t, newFull(&cancelled))
	for _, tc := range optionalRoutes {
		t.Run(tc.route, func(t *testing.T) {
			if w := post(t, c, tc.route, tc.body); w.Code != 200 {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
	got := decodeBody[mdl.ExtendOperationStatusResponse](t, post(t, c, "extendToLevel/status", scopedBody))
	if got.Status != mdl.OPERATIONSTATUS_COMPLETED {
		t.Fatalf("status = %+v", got)
	}
	if w := post(t, c, "extendToLevel/cancel", scopedBody); w.Code != 204 || !cancelled {
		t.Fatalf("cancel: %d, reached provider %v", w.Code, cancelled)
	}
}

func TestOnlyDeclaredLevelsAreServed(t *testing.T) {
	var cancelled bool
	p := newFull(&cancelled)
	p.family = demoFamily(levelSigned)
	c := serve(t, p)
	wantProblem(t, post(t, c, "embedSignatureTimestamp", stampBody), 422, "PARAMETER_UNSUPPORTED")
	wantProblem(t, post(t, c, "extendToLevel/cancel", scopedBody), 404, "OPERATION_NOT_TRACKED")
}

func TestCapabilityDoesNotServeUndeclaredLevels(t *testing.T) {
	c := serve(t, withArchive{basic: newBasic(levelSigned)})
	wantProblem(t, post(t, c, "embedArchiveTimestamp", stampBody), 422, "PARAMETER_UNSUPPORTED")
}

func TestMountsAllRoutes(t *testing.T) {
	h, err := NewHandler(newBasic(levelSigned))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	h.Mount(routerFunc(func(method, pattern string, _ http.HandlerFunc) { got = append(got, method+" "+pattern) }))
	want := []string{
		"GET /declaration", "GET /{operation}/attributes", "POST /validateProfile", "POST /computeDtbs",
		"POST /embedSignatureValue", "POST /computeSignatureTimestampImprint", "POST /embedSignatureTimestamp",
		"POST /computeArchiveTimestampImprint", "POST /embedArchiveTimestamp", "POST /extendToLevel",
		"POST /extendToLevel/status", "POST /extendToLevel/cancel",
	}
	for i := range want {
		want[i] = strings.Replace(want[i], " /", " "+base+"/", 1)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("routes = %v", got)
	}
}

type routerFunc func(method, pattern string, h http.HandlerFunc)

func (f routerFunc) Handle(method, pattern string, h http.HandlerFunc) { f(method, pattern, h) }

func TestDocumentModeRefusesAnEmptyTransfer(t *testing.T) {
	if _, err := documentMode("document", &mdl.DocumentTransfer{}); err == nil {
		t.Fatal("a document without a variant must be refused")
	}
}

func TestDetachedContentIsChecked(t *testing.T) {
	var cancelled bool
	c := serve(t, newFull(&cancelled))
	wantProblem(t, post(t, c, "extendToLevel", extendBody.with("detachedContent", digestDoc)), 422, "PARAMETER_UNSUPPORTED")
	wantProblem(t, post(t, c, "extendToLevel", extendBody.with("detachedContent", body{"transferMode": "inline", "document": ""})), 422, "VALIDATION_FAILED")
	if w := post(t, c, "extendToLevel", extendBody.with("detachedContent", inlineDoc)); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
