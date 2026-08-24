package cryptography_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Request bodies satisfying the request DTOs used by the eight attribute
// endpoints that are not already declared at file scope elsewhere in this
// package (tokenScopedBody and tokenProfileScopedBody are declared in
// routes_test.go and reused here as-is).
const (
	createKeyAttributesRequestBody = `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyUsages":` + oneKeyUsage + `,"keyRequestType":"secret"}`
	keyScopedRequestBody           = `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyUsages":` + oneKeyUsage + `,"keyMeta":` + oneMetadataAttribute + `}`
)

// attrRequest issues method against srv for path with an optional body
// (empty string for none — the GET tokens/attributes route has no request
// body) and returns the recorder.
func attrRequest(t *testing.T, srv http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// recognizableAttribute is a populated BaseAttributeDto fixture carrying name
// in its "name" field; see async_test.go's oneOf zero-value trap. One arm must
// be populated at each level, since BaseAttributeDto and BaseAttributeDtoV2 are
// both oneOf wrappers. CustomAttributeV2 is used because, unlike
// InfoAttributeV2, its Content field is omitempty, so the zero value marshals
// cleanly.
func recognizableAttribute(name string) mdl.BaseAttributeDto {
	return mdl.BaseAttributeDto{
		BaseAttributeDtoV2: &mdl.BaseAttributeDtoV2{
			CustomAttributeV2: &mdl.CustomAttributeV2{
				Name:        name,
				Type:        mdl.ATTRIBUTETYPE_CUSTOM,
				ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
				Properties:  mdl.CustomAttributeProperties{},
			},
		},
	}
}

// The eight attribute-endpoint stubs below are minimal: one field for the
// response, one for the error, each implementing exactly the one interface
// method its endpoint calls.

type stubTokenAttrs struct {
	resp []mdl.BaseAttributeDto
	err  error
}

func (s *stubTokenAttrs) TokenAttributes(ctx context.Context) ([]mdl.BaseAttributeDto, error) {
	return s.resp, s.err
}

type stubTokenProfileAttrs struct {
	resp []mdl.BaseAttributeDto
	err  error
}

func (s *stubTokenProfileAttrs) TokenProfileAttributes(ctx context.Context, req *mdl.TokenScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return s.resp, s.err
}

type stubCreateKeyAttrs struct {
	resp []mdl.BaseAttributeDto
	err  error
}

func (s *stubCreateKeyAttrs) CreateKeyAttributes(ctx context.Context, req *mdl.CreateKeyAttributesRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return s.resp, s.err
}

type stubEncryptAttrs struct {
	resp []mdl.BaseAttributeDto
	err  error
}

func (s *stubEncryptAttrs) EncryptAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return s.resp, s.err
}

type stubDecryptAttrs struct {
	resp []mdl.BaseAttributeDto
	err  error
}

func (s *stubDecryptAttrs) DecryptAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return s.resp, s.err
}

type stubSignAttrs struct {
	resp []mdl.BaseAttributeDto
	err  error
}

func (s *stubSignAttrs) SignAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return s.resp, s.err
}

type stubVerifyAttrs struct {
	resp []mdl.BaseAttributeDto
	err  error
}

func (s *stubVerifyAttrs) VerifyAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return s.resp, s.err
}

type stubRandomDataAttrs struct {
	resp []mdl.BaseAttributeDto
	err  error
}

func (s *stubRandomDataAttrs) RandomDataAttributes(ctx context.Context, req *mdl.TokenProfileScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return s.resp, s.err
}

// attrEndpointCase describes one of the eight attribute-schema endpoints:
// its route, a body satisfying the request DTO's required properties
// (validBody is "" for the GET route, which has no request body and
// therefore no decode branch), and how to register a stub returning a given
// response/error pair.
type attrEndpointCase struct {
	name      string
	method    string
	path      string
	validBody string
	hasDecode bool
	register  func(resp []mdl.BaseAttributeDto, err error) cryptography.Option
}

func attrEndpointCases() []attrEndpointCase {
	return []attrEndpointCase{
		{
			name:      "tokens/attributes",
			method:    http.MethodGet,
			path:      "/v2/cryptographyProvider/tokens/attributes",
			validBody: "",
			hasDecode: false,
			register: func(resp []mdl.BaseAttributeDto, err error) cryptography.Option {
				return cryptography.WithTokenAttributes(&stubTokenAttrs{resp: resp, err: err})
			},
		},
		{
			name:      "tokens/tokenProfile/attributes",
			method:    http.MethodPost,
			path:      "/v2/cryptographyProvider/tokens/tokenProfile/attributes",
			validBody: tokenScopedBody,
			hasDecode: true,
			register: func(resp []mdl.BaseAttributeDto, err error) cryptography.Option {
				return cryptography.WithTokenProfileAttributes(&stubTokenProfileAttrs{resp: resp, err: err})
			},
		},
		{
			name:      "keys/create/attributes",
			method:    http.MethodPost,
			path:      "/v2/cryptographyProvider/keys/create/attributes",
			validBody: createKeyAttributesRequestBody,
			hasDecode: true,
			register: func(resp []mdl.BaseAttributeDto, err error) cryptography.Option {
				return cryptography.WithCreateKeyAttributes(&stubCreateKeyAttrs{resp: resp, err: err})
			},
		},
		{
			name:      "operations/encrypt/attributes",
			method:    http.MethodPost,
			path:      "/v2/cryptographyProvider/operations/encrypt/attributes",
			validBody: keyScopedRequestBody,
			hasDecode: true,
			register: func(resp []mdl.BaseAttributeDto, err error) cryptography.Option {
				return cryptography.WithEncryptAttributes(&stubEncryptAttrs{resp: resp, err: err})
			},
		},
		{
			name:      "operations/decrypt/attributes",
			method:    http.MethodPost,
			path:      "/v2/cryptographyProvider/operations/decrypt/attributes",
			validBody: keyScopedRequestBody,
			hasDecode: true,
			register: func(resp []mdl.BaseAttributeDto, err error) cryptography.Option {
				return cryptography.WithDecryptAttributes(&stubDecryptAttrs{resp: resp, err: err})
			},
		},
		{
			name:      "operations/sign/attributes",
			method:    http.MethodPost,
			path:      "/v2/cryptographyProvider/operations/sign/attributes",
			validBody: keyScopedRequestBody,
			hasDecode: true,
			register: func(resp []mdl.BaseAttributeDto, err error) cryptography.Option {
				return cryptography.WithSignAttributes(&stubSignAttrs{resp: resp, err: err})
			},
		},
		{
			name:      "operations/verify/attributes",
			method:    http.MethodPost,
			path:      "/v2/cryptographyProvider/operations/verify/attributes",
			validBody: keyScopedRequestBody,
			hasDecode: true,
			register: func(resp []mdl.BaseAttributeDto, err error) cryptography.Option {
				return cryptography.WithVerifyAttributes(&stubVerifyAttrs{resp: resp, err: err})
			},
		},
		{
			name:      "operations/random/attributes",
			method:    http.MethodPost,
			path:      "/v2/cryptographyProvider/operations/random/attributes",
			validBody: tokenProfileScopedBody,
			hasDecode: true,
			register: func(resp []mdl.BaseAttributeDto, err error) cryptography.Option {
				return cryptography.WithRandomDataAttributes(&stubRandomDataAttrs{resp: resp, err: err})
			},
		},
	}
}

// --- Registered success path --------------------------------------------------
//
// Each case asserts the body decodes to exactly the one attribute the stub
// returned; see async_test.go's oneOf zero-value trap for why a status-only
// assertion is not enough.
func TestAttributeEndpointsReturnRegisteredProviderData(t *testing.T) {
	for _, tc := range attrEndpointCases() {
		t.Run(tc.name, func(t *testing.T) {
			want := "marker-" + tc.name
			opt := tc.register([]mdl.BaseAttributeDto{recognizableAttribute(want)}, nil)
			srv := newTestServer(t, &stubProvider{}, opt)

			rec := attrRequest(t, srv, tc.method, tc.path, tc.validBody)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			var got []map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal body: %v; body %s", err, rec.Body.String())
			}
			if len(got) != 1 {
				t.Fatalf("body = %s, want exactly one attribute", rec.Body.String())
			}
			if got[0]["name"] != want {
				t.Errorf("body = %s, want name=%q", rec.Body.String(), want)
			}
		})
	}
}

// --- Provider-error path ------------------------------------------------------

func TestAttributeEndpointsRenderProviderError(t *testing.T) {
	for _, tc := range attrEndpointCases() {
		t.Run(tc.name, func(t *testing.T) {
			opt := tc.register(nil, shared.Internal("INTERNAL_SERVER_ERROR", "boom"))
			srv := newTestServer(t, &stubProvider{}, opt)

			rec := attrRequest(t, srv, tc.method, tc.path, tc.validBody)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
			}
			var problem shared.ProblemDetail
			if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
				t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
			}
			if problem.ErrorCode != "INTERNAL_SERVER_ERROR" {
				t.Errorf("errorCode = %q, want INTERNAL_SERVER_ERROR; body %s", problem.ErrorCode, rec.Body.String())
			}
		})
	}
}

// --- Malformed-body path (shared.DecodeJSON error branch) --------------------
//
// `{}` fails required-property validation for all seven POST request DTOs
// used by these endpoints (TokenScopedRequestV2Dto,
// CreateKeyAttributesRequestV2Dto, KeyScopedRequestV2Dto and
// TokenProfileScopedRequestV2Dto all declare every property required, none
// omitempty), so one shared malformed body is legitimate here, not a weakened
// assertion forced to fit. The GET tokens/attributes route has no decode
// branch and is skipped.
func TestAttributeEndpointsRejectMalformedBody(t *testing.T) {
	for _, tc := range attrEndpointCases() {
		if !tc.hasDecode {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, &stubProvider{})

			rec := attrRequest(t, srv, tc.method, tc.path, `{}`)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body %s", rec.Code, rec.Body.String())
			}
			var problem shared.ProblemDetail
			if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
				t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
			}
			if problem.ErrorCode != "VALIDATION_FAILED" {
				t.Errorf("errorCode = %q, want VALIDATION_FAILED; body %s", problem.ErrorCode, rec.Body.String())
			}
		})
	}
}
