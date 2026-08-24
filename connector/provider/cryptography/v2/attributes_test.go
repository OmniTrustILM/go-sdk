package cryptography_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// newTestServer builds a Handler for p, mounts it on a shared.Connector, and
// returns the resulting http.Handler. Other test files in this package reuse
// this helper, so its signature is load-bearing beyond this file.
func newTestServer(t *testing.T, p cryptography.Provider, opts ...cryptography.Option) http.Handler {
	t.Helper()
	h, err := cryptography.NewHandler(p, opts...)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	c, err := shared.New(
		shared.WithInfo(shared.Info{ID: "a", Name: "a", Version: "0.0.1"}),
		shared.Register(h),
	)
	if err != nil {
		t.Fatalf("shared.New: %v", err)
	}
	return c.Handler()
}

// The SDK-wide convention: an attribute endpoint with no registered provider
// answers 200 with an empty array, never 404 and never null.
func TestUnregisteredAttributeEndpointsReturnEmptyArray(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	// Request bodies satisfy each DTO's generated required-property check
	// (an empty `{}` fails required-field validation before the handler ever
	// reaches the unregistered-provider path) and the contract's minItems: 1
	// on keyUsages and keyMeta, which validate.go's request guards enforce
	// ahead of the unregistered-provider path; the GET case ignores its body.
	const keyScopedBody = `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyUsages":` +
		oneKeyUsage + `,"keyMeta":` + oneMetadataAttribute + `}`
	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/v2/cryptographyProvider/tokens/attributes", `{}`},
		{http.MethodPost, "/v2/cryptographyProvider/tokens/tokenProfile/attributes", `{"tokenAttributes":[]}`},
		{http.MethodPost, "/v2/cryptographyProvider/keys/create/attributes", createKeyAttributesRequestBody},
		{http.MethodPost, "/v2/cryptographyProvider/operations/encrypt/attributes", keyScopedBody},
		{http.MethodPost, "/v2/cryptographyProvider/operations/decrypt/attributes", keyScopedBody},
		{http.MethodPost, "/v2/cryptographyProvider/operations/sign/attributes", keyScopedBody},
		{http.MethodPost, "/v2/cryptographyProvider/operations/verify/attributes", keyScopedBody},
		{http.MethodPost, "/v2/cryptographyProvider/operations/random/attributes", tokenProfileScopedBody},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			body := strings.NewReader(tc.body)
			req := httptest.NewRequest(tc.method, tc.path, body)
			rec := httptest.NewRecorder()

			srv.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
				t.Errorf("body = %s, want []", got)
			}
		})
	}
}

// TestOptionsRejectNilProviders asserts the nil-guard branch of every With*
// option that takes a sub-provider interface: NewHandler must reject a
// nil-valued option outright. Each With* here receives an untyped nil, which
// converts to a nil interface value that the guard catches — passing a typed
// nil pointer instead would be a non-nil interface and would defeat the
// guard for a reason unrelated to what this test checks.
func TestOptionsRejectNilProviders(t *testing.T) {
	cases := []struct {
		name string
		opt  cryptography.Option
	}{
		{"WithTokenAttributes", cryptography.WithTokenAttributes(nil)},
		{"WithTokenProfileAttributes", cryptography.WithTokenProfileAttributes(nil)},
		{"WithCreateKeyAttributes", cryptography.WithCreateKeyAttributes(nil)},
		{"WithEncryptAttributes", cryptography.WithEncryptAttributes(nil)},
		{"WithDecryptAttributes", cryptography.WithDecryptAttributes(nil)},
		{"WithSignAttributes", cryptography.WithSignAttributes(nil)},
		{"WithVerifyAttributes", cryptography.WithVerifyAttributes(nil)},
		{"WithRandomDataAttributes", cryptography.WithRandomDataAttributes(nil)},
		{"WithAsyncKeys", cryptography.WithAsyncKeys(nil)},
		{"WithAsyncSign", cryptography.WithAsyncSign(nil)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cryptography.NewHandler(&stubProvider{}, tc.opt); err == nil {
				t.Errorf("%s(nil) should error", tc.name)
			}
		})
	}
}
