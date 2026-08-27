package cryptography_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
)

// Every route emits exactly one connector event per request, after its
// response guards have run, so outcome is "ok" exactly when the status is
// below 400. The table drives all 24 routes through a bare provider — nil
// responses, so the guarded routes fail on ErrNilResponse — with both async
// sub-providers registered, so no route short-circuits on the 404 path.
func TestEveryRouteEmitsExactlyOneEventConsistentWithStatus(t *testing.T) {
	const keyScopedBody = `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyUsages":` +
		oneKeyUsage + `,"keyMeta":` + oneMetadataAttribute + `}`
	routes := []struct {
		method string
		path   string
		body   string
		event  string
	}{
		{http.MethodGet, "/v2/cryptographyProvider/tokens/attributes", ``, "list_token_attributes"},
		{http.MethodPost, "/v2/cryptographyProvider/tokens/tokenProfile/attributes", tokenScopedBody, "list_token_profile_attributes"},
		{http.MethodPost, "/v2/cryptographyProvider/keys/create/attributes", createKeyAttributesRequestBody, "list_create_key_attributes"},
		{http.MethodPost, "/v2/cryptographyProvider/operations/encrypt/attributes", keyScopedBody, "list_encrypt_attributes"},
		{http.MethodPost, "/v2/cryptographyProvider/operations/decrypt/attributes", keyScopedBody, "list_decrypt_attributes"},
		{http.MethodPost, "/v2/cryptographyProvider/operations/sign/attributes", keyScopedBody, "list_sign_attributes"},
		{http.MethodPost, "/v2/cryptographyProvider/operations/verify/attributes", keyScopedBody, "list_verify_attributes"},
		{http.MethodPost, "/v2/cryptographyProvider/operations/random/attributes", tokenProfileScopedBody, "list_random_data_attributes"},
		{http.MethodPost, "/v2/cryptographyProvider/tokens/status", tokenScopedBody, "token_status"},
		{http.MethodPost, "/v2/cryptographyProvider/tokens/tokenProfile/keyUsages", tokenScopedBody, "token_profile_key_usages"},
		{http.MethodPost, "/v2/cryptographyProvider/tokens/keyRequestTypes", tokenProfileScopedBody, "key_request_types"},
		{http.MethodPost, "/v2/cryptographyProvider/keys", createKeyBody("synchronous"), "create_key"},
		{http.MethodPost, "/v2/cryptographyProvider/keys/destroy", destroyKeyBody("synchronous"), "destroy_key"},
		{http.MethodPost, "/v2/cryptographyProvider/operations/sign", signDataBody("synchronous"), "sign_data"},
		{http.MethodPost, "/v2/cryptographyProvider/operations/encrypt", cipherDataBody, "encrypt_data"},
		{http.MethodPost, "/v2/cryptographyProvider/operations/decrypt", cipherDataBody, "decrypt_data"},
		{http.MethodPost, "/v2/cryptographyProvider/operations/verify", verifyDataBody, "verify_data"},
		{http.MethodPost, "/v2/cryptographyProvider/operations/random", randomDataBody, "random_data"},
		{http.MethodPost, "/v2/cryptographyProvider/keys/create/status", operationTrackingBody, "create_key_status"},
		{http.MethodPost, "/v2/cryptographyProvider/keys/create/cancel", operationTrackingBody, "cancel_create_key"},
		{http.MethodPost, "/v2/cryptographyProvider/keys/destroy/status", operationTrackingBody, "destroy_key_status"},
		{http.MethodPost, "/v2/cryptographyProvider/keys/destroy/cancel", operationTrackingBody, "cancel_destroy_key"},
		{http.MethodPost, "/v2/cryptographyProvider/operations/sign/status", operationTrackingBody, "sign_data_status"},
		{http.MethodPost, "/v2/cryptographyProvider/operations/sign/cancel", operationTrackingBody, "cancel_sign_data"},
	}
	if len(routes) != 24 {
		t.Fatalf("test bug: table has %d routes, need 24", len(routes))
	}

	for _, tc := range routes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			mc := &recordingMetrics{events: map[string]int{}}
			srv := newMeteredServer(t, &stubProvider{}, mc,
				cryptography.WithAsyncKeys(&stubAsyncKeys{}),
				cryptography.WithAsyncSign(&stubAsyncSign{}),
			)
			var req *http.Request
			if tc.body == "" {
				req = httptest.NewRequest(tc.method, tc.path, nil)
			} else {
				req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			}
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			total := 0
			for _, n := range mc.events {
				total += n
			}
			if total != 1 {
				t.Fatalf("events = %v, want exactly one", mc.events)
			}
			want := tc.event + "/error"
			if rec.Code < 400 {
				want = tc.event + "/ok"
			}
			if mc.events[want] != 1 {
				t.Errorf("status %d, events = %v, want %s", rec.Code, mc.events, want)
			}
		})
	}
}
