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

// Request bodies satisfying each DTO's generated required-property check and
// the contract's minItems: 1 on its batch lists (see
// TestUnregisteredAttributeEndpointsReturnEmptyArray in attributes_test.go for
// the same convention).
//
// CreateKeyRequestV2Dto requires: tokenAttributes, tokenProfileAttributes,
// keyUsages, keyRequestType, executionMode, keyCreationId,
// createKeyAttributes.
//
// DestroyKeyRequestV2Dto requires: tokenAttributes, tokenProfileAttributes,
// keyUsages, keyMeta, executionMode.
//
// SignDataRequestV2Dto requires: tokenAttributes, tokenProfileAttributes,
// keyUsages, keyMeta, executionMode, signatureAttributes, data.
func createKeyBody(executionMode string) string {
	return `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyUsages":` + oneKeyUsage +
		`,"keyRequestType":"secret","executionMode":"` + executionMode + `","keyCreationId":"k1","createKeyAttributes":[]}`
}

func destroyKeyBody(executionMode string) string {
	return `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyUsages":` + oneKeyUsage +
		`,"keyMeta":` + oneMetadataAttribute + `,"executionMode":"` + executionMode + `"}`
}

func signDataBody(executionMode string) string {
	return `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyUsages":` + oneKeyUsage +
		`,"keyMeta":` + oneMetadataAttribute + `,"executionMode":"` + executionMode +
		`","signatureAttributes":[],"data":[{"identifier":"d-1","data":"AA=="}]}`
}

// post issues a POST request with body against srv and returns the recorder.
func post(t *testing.T, srv http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// --- /keys (createKey) -------------------------------------------------------

// The oneOf zero-value trap, referenced by the fixtures below and in
// attribute_routes_test.go: a generated oneOf wrapper's zero value marshals to
// (nil, nil) because no variant is set, and shared.WriteJSON commits the status
// via w.WriteHeader before calling Encode. A fixture that leaves every variant
// nil therefore yields the expected status code with an empty body, and a
// status-only assertion passes over it. Every response fixture here populates
// one variant, and the tests assert the decoded body.

// secretKeyCreationResponse is a populated secret-arm fixture for
// KeyCreationResponse, shaped for a synchronous (200) result:
// validateKeyCreationShape requires the complete payload for the arm — both
// KeyData and KeyMeta — and no operationMeta.
func secretKeyCreationResponse() *mdl.KeyCreationResponse {
	return &mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			KeyData:        mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048),
			KeyMeta:        []mdl.MetadataAttribute{metadataAttributeFixture()},
		},
	}
}

// secretKeyCreationAcceptedResponse is secretKeyCreationResponse's
// asynchronous (202) counterpart: validateKeyCreationShape requires an
// accepted response to carry operationMeta and no payload, the opposite
// shape from the synchronous fixture above.
func secretKeyCreationAcceptedResponse() *mdl.KeyCreationResponse {
	return &mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			OperationMeta:  []mdl.MetadataAttribute{metadataAttributeFixture()},
		},
	}
}

// metadataAttributeFixture decodes oneMetadataAttribute, so a response that
// embeds it round-trips through the generated decoder.
func metadataAttributeFixture() mdl.MetadataAttribute {
	var elems []mdl.MetadataAttribute
	if err := json.Unmarshal([]byte(oneMetadataAttribute), &elems); err != nil || len(elems) != 1 {
		panic("metadataAttributeFixture: oneMetadataAttribute must decode to one element: " + err.Error())
	}
	return elems[0]
}

func TestCreateKeyRendersSyncAs200(t *testing.T) {
	p := &stubProvider{createKeyResp: secretKeyCreationResponse(), createKeyAccepted: false}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/keys", createKeyBody("synchronous"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	// Prove the oneOf wrapper serialized flat (the selected variant's fields
	// at top level) rather than nested under the Go field name — the
	// load-bearing wire-contract property a status-only assertion cannot see.
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v; body %s", err, rec.Body.String())
	}
	if got["keyRequestType"] != "secret" {
		t.Errorf("body = %s, want top-level keyRequestType=\"secret\"", rec.Body.String())
	}
	if _, nested := got["SecretKeyDataResponseV2Dto"]; nested {
		t.Errorf("body = %s, want no SecretKeyDataResponseV2Dto key (flat serialization only)", rec.Body.String())
	}
}

func TestCreateKeyRendersAcceptedAs202(t *testing.T) {
	p := &stubProvider{createKeyResp: secretKeyCreationAcceptedResponse(), createKeyAccepted: true}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/keys", createKeyBody("asynchronous"))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v; body %s", err, rec.Body.String())
	}
	if _, ok := got["operationMeta"]; !ok {
		t.Errorf("body = %s, want top-level operationMeta", rec.Body.String())
	}
	if _, ok := got["keyData"]; ok {
		t.Errorf("body = %s, want no keyData on an accepted response", rec.Body.String())
	}
}

func TestCreateKeyConflictRenders409WithResourceAlreadyExists(t *testing.T) {
	p := &stubProvider{createKeyErr: cryptography.ErrKeyCreationConflict}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/keys", createKeyBody("synchronous"))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != "RESOURCE_ALREADY_EXISTS" {
		t.Errorf("errorCode = %q, want RESOURCE_ALREADY_EXISTS; body %s", problem.ErrorCode, rec.Body.String())
	}
}

func TestCreateKeyRejectsNilProviderResponse(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	rec := post(t, srv, "/v2/cryptographyProvider/keys", createKeyBody("synchronous"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a nil provider response; body %s", rec.Code, rec.Body.String())
	}
}

// --- /keys/destroy (destroyKey) ----------------------------------------------

func TestDestroyKeyRendersSyncAs200AndAcceptedAs202(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     string
		accepted bool
		// resp is per-case: validateDestroyShape requires operationMeta on an
		// accepted response, but KeyOperationResponseV2Dto{} (no
		// operationMeta) is a valid synchronous response since it has no
		// payload field of its own to require.
		resp *mdl.KeyOperationResponseV2Dto
		want int
	}{
		{"synchronous", "synchronous", false, &mdl.KeyOperationResponseV2Dto{}, http.StatusOK},
		{"asynchronous", "asynchronous", true, &mdl.KeyOperationResponseV2Dto{OperationMeta: []mdl.MetadataAttribute{metadataAttributeFixture()}}, http.StatusAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &stubProvider{destroyKeyResp: tc.resp, destroyKeyAccepted: tc.accepted}
			srv := newTestServer(t, p)

			rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy", destroyKeyBody(tc.mode))

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.want, rec.Body.String())
			}
			var got mdl.KeyOperationResponseV2Dto
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode body: %v; body %q", err, rec.Body.String())
			}
			if len(got.OperationMeta) != len(tc.resp.OperationMeta) {
				t.Errorf("operationMeta has %d entries, want %d", len(got.OperationMeta), len(tc.resp.OperationMeta))
			}
		})
	}
}

func TestDestroyKeyMapsProviderErrorToProblem(t *testing.T) {
	p := &stubProvider{destroyKeyErr: cryptography.ErrKeyNotFound}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy", destroyKeyBody("synchronous"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != "RESOURCE_NOT_FOUND" {
		t.Errorf("errorCode = %q, want RESOURCE_NOT_FOUND; body %s", problem.ErrorCode, rec.Body.String())
	}
}

func TestDestroyKeyRejectsNilProviderResponse(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy", destroyKeyBody("synchronous"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a nil provider response; body %s", rec.Code, rec.Body.String())
	}
}

// --- /operations/sign (signData) ---------------------------------------------

func TestSignDataRendersSyncAs200AndAcceptedAs202(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     string
		accepted bool
		// resp is per-case: validateExecutionShape requires the opposite
		// shape for each arm — a synchronous result carries signatures and no
		// operationMeta, an accepted result carries operationMeta and no
		// signatures.
		resp *mdl.SignDataResponseV2Dto
		want int
	}{
		{"synchronous", "synchronous", false, &mdl.SignDataResponseV2Dto{Signatures: []mdl.SignatureDataV2Dto{{Identifier: "d-1", Data: "AA=="}}}, http.StatusOK},
		{"asynchronous", "asynchronous", true, &mdl.SignDataResponseV2Dto{OperationMeta: []mdl.MetadataAttribute{metadataAttributeFixture()}}, http.StatusAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &stubProvider{signDataResp: tc.resp, signDataAccepted: tc.accepted}
			srv := newTestServer(t, p)

			rec := post(t, srv, "/v2/cryptographyProvider/operations/sign", signDataBody(tc.mode))

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.want, rec.Body.String())
			}
			var got mdl.SignDataResponseV2Dto
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode body: %v; body %q", err, rec.Body.String())
			}
			if len(got.OperationMeta) != len(tc.resp.OperationMeta) || len(got.Signatures) != len(tc.resp.Signatures) {
				t.Errorf("body = %s, want the provider's operationMeta and signatures round-tripped", rec.Body.String())
			}
		})
	}
}

func TestSignDataMapsProviderErrorToProblem(t *testing.T) {
	p := &stubProvider{signDataErr: cryptography.ErrKeyNotFound}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign", signDataBody("synchronous"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != "RESOURCE_NOT_FOUND" {
		t.Errorf("errorCode = %q, want RESOURCE_NOT_FOUND; body %s", problem.ErrorCode, rec.Body.String())
	}
}

func TestSignDataRejectsNilProviderResponse(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign", signDataBody("synchronous"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a nil provider response; body %s", rec.Code, rec.Body.String())
	}
}

// --- Async status and cancel: stubs and support -------------------------------

// operationTrackingBody satisfies OperationTrackingRequestV2Dto's required
// operationMeta property. The spec sets minItems: 1 on it, so the array
// carries one element: validateNonEmptyBatch rejects an empty one with 422
// before the handler calls the sub-provider (see
// TestStatusAndCancelRoutesRejectEmptyOperationMeta).
const operationTrackingBody = `{"operationMeta":` + oneMetadataAttribute + `}`

// stubAsyncKeys implements cryptography.AsyncKeyProvider. Every method
// returns the configured response/error pair for its own operation,
// defaulting to zero values when unset.
type stubAsyncKeys struct {
	createStatus    *mdl.KeyCreationStatusResponse
	createStatusErr error

	cancelCreateErr error

	destroyStatus    *mdl.KeyDestructionStatusResponseV2Dto
	destroyStatusErr error

	cancelDestroyErr error
}

func (s *stubAsyncKeys) CreateKeyStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.KeyCreationStatusResponse, error) {
	return s.createStatus, s.createStatusErr
}

func (s *stubAsyncKeys) CancelCreateKey(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error {
	return s.cancelCreateErr
}

func (s *stubAsyncKeys) DestroyKeyStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.KeyDestructionStatusResponseV2Dto, error) {
	return s.destroyStatus, s.destroyStatusErr
}

func (s *stubAsyncKeys) CancelDestroyKey(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error {
	return s.cancelDestroyErr
}

// stubAsyncSign implements cryptography.AsyncSignProvider.
type stubAsyncSign struct {
	status    *mdl.SignOperationStatusResponseV2Dto
	statusErr error

	cancelErr error
}

func (s *stubAsyncSign) SignDataStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.SignOperationStatusResponseV2Dto, error) {
	return s.status, s.statusErr
}

func (s *stubAsyncSign) CancelSignData(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error {
	return s.cancelErr
}

// recordingRouter implements shared.Router by appending "METHOD pattern" to
// patterns for every Handle call, so tests can assert both the count and the
// exact set of mounted routes without spinning up an httptest server.
type recordingRouter struct {
	patterns []string
}

func (r *recordingRouter) Handle(method, pattern string, h http.HandlerFunc) {
	r.patterns = append(r.patterns, method+" "+pattern)
}

// secretKeyCreationStatusResponse is a populated secret-arm fixture for
// KeyCreationStatusResponse; see the oneOf zero-value trap above.
func secretKeyCreationStatusResponse() *mdl.KeyCreationStatusResponse {
	return &mdl.KeyCreationStatusResponse{
		SecretKeyOperationStatusResponseV2Dto: &mdl.SecretKeyOperationStatusResponseV2Dto{
			Status:         mdl.OPERATIONSTATUS_IN_PROGRESS,
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
		},
	}
}

// --- Gating: 404 problem document without the sub-interface ------------------

// The contract declares these endpoints' 404 as application/problem+json
// ("endpoint not found or not implemented"), so the body is asserted as well as
// the status: a bare ServeMux 404 would be text/plain.
func TestStatusAndCancelRoutesRender404ProblemWithoutSubInterfaces(t *testing.T) {
	srv := newTestServer(t, &stubProvider{}) // no WithAsyncKeys, no WithAsyncSign

	for _, path := range []string{
		"/v2/cryptographyProvider/keys/create/status",
		"/v2/cryptographyProvider/keys/create/cancel",
		"/v2/cryptographyProvider/keys/destroy/status",
		"/v2/cryptographyProvider/keys/destroy/cancel",
		"/v2/cryptographyProvider/operations/sign/status",
		"/v2/cryptographyProvider/operations/sign/cancel",
	} {
		t.Run(path, func(t *testing.T) {
			rec := post(t, srv, path, operationTrackingBody)

			assertProblem(t, rec, http.StatusNotFound, "OPERATION_NOT_SUPPORTED")
			if ct := rec.Header().Get("Content-Type"); ct != shared.ProblemContentType {
				t.Errorf("Content-Type = %q, want %q", ct, shared.ProblemContentType)
			}
		})
	}
}

// --- /keys/create/status ------------------------------------------------------

func TestCreateKeyStatusReturns200(t *testing.T) {
	a := &stubAsyncKeys{createStatus: secretKeyCreationStatusResponse()}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/create/status", operationTrackingBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	// Prove the oneOf wrapper serialized flat and non-empty — the load-bearing
	// wire-contract property a status-only assertion cannot see (see the
	// MarshalJSON trap noted on secretKeyCreationStatusResponse).
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v; body %s", err, rec.Body.String())
	}
	if got["status"] != "inProgress" {
		t.Errorf("body = %s, want top-level status=\"inProgress\"", rec.Body.String())
	}
	if got["keyRequestType"] != "secret" {
		t.Errorf("body = %s, want top-level keyRequestType=\"secret\"", rec.Body.String())
	}
}

func TestCreateKeyStatusMapsUnknownHandleTo404(t *testing.T) {
	a := &stubAsyncKeys{createStatusErr: cryptography.ErrOperationNotTracked}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/create/status", operationTrackingBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != "OPERATION_NOT_TRACKED" {
		t.Errorf("errorCode = %q, want OPERATION_NOT_TRACKED; body %s", problem.ErrorCode, rec.Body.String())
	}
}

func TestCreateKeyStatusRejectsNilProviderResponse(t *testing.T) {
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(&stubAsyncKeys{}))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/create/status", operationTrackingBody)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a nil provider response; body %s", rec.Code, rec.Body.String())
	}
}

// --- /keys/create/cancel -------------------------------------------------------

func TestCancelCreateKeyReturns204(t *testing.T) {
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(&stubAsyncKeys{}))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/create/cancel", operationTrackingBody)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %s, want empty for 204", rec.Body.String())
	}
}

func TestCancelCreateKeyMapsNotTrackedTo404(t *testing.T) {
	a := &stubAsyncKeys{cancelCreateErr: cryptography.ErrOperationNotTracked}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/create/cancel", operationTrackingBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != "OPERATION_NOT_TRACKED" {
		t.Errorf("errorCode = %q, want OPERATION_NOT_TRACKED; body %s", problem.ErrorCode, rec.Body.String())
	}
}

func TestCancelCreateKeyMapsRefusalTo422(t *testing.T) {
	a := &stubAsyncKeys{cancelCreateErr: cryptography.ErrCancelPastPointOfNoReturn}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/create/cancel", operationTrackingBody)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body %s", rec.Code, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != "OPERATION_PAST_POINT_OF_NO_RETURN" {
		t.Errorf("errorCode = %q, want OPERATION_PAST_POINT_OF_NO_RETURN; body %s", problem.ErrorCode, rec.Body.String())
	}
}

// --- /keys/destroy/status and /keys/destroy/cancel ----------------------------

func TestDestroyKeyStatusReturns200(t *testing.T) {
	a := &stubAsyncKeys{destroyStatus: &mdl.KeyDestructionStatusResponseV2Dto{Status: mdl.OPERATIONSTATUS_IN_PROGRESS}}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy/status", operationTrackingBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v; body %s", err, rec.Body.String())
	}
	if got["status"] != "inProgress" {
		t.Errorf("body = %s, want top-level status=\"inProgress\"", rec.Body.String())
	}
}

func TestDestroyKeyStatusMapsUnknownHandleTo404(t *testing.T) {
	a := &stubAsyncKeys{destroyStatusErr: cryptography.ErrOperationNotTracked}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy/status", operationTrackingBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != "OPERATION_NOT_TRACKED" {
		t.Errorf("errorCode = %q, want OPERATION_NOT_TRACKED; body %s", problem.ErrorCode, rec.Body.String())
	}
}

func TestDestroyKeyStatusRejectsNilProviderResponse(t *testing.T) {
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(&stubAsyncKeys{}))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy/status", operationTrackingBody)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a nil provider response; body %s", rec.Code, rec.Body.String())
	}
}

func TestCancelDestroyKeyReturns204(t *testing.T) {
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(&stubAsyncKeys{}))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy/cancel", operationTrackingBody)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %s, want empty for 204", rec.Body.String())
	}
}

func TestCancelDestroyKeyMapsNotTrackedTo404(t *testing.T) {
	a := &stubAsyncKeys{cancelDestroyErr: cryptography.ErrOperationNotTracked}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy/cancel", operationTrackingBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != "OPERATION_NOT_TRACKED" {
		t.Errorf("errorCode = %q, want OPERATION_NOT_TRACKED; body %s", problem.ErrorCode, rec.Body.String())
	}
}

func TestCancelDestroyKeyMapsRefusalTo422(t *testing.T) {
	a := &stubAsyncKeys{cancelDestroyErr: cryptography.ErrCancelPastPointOfNoReturn}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy/cancel", operationTrackingBody)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body %s", rec.Code, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != "OPERATION_PAST_POINT_OF_NO_RETURN" {
		t.Errorf("errorCode = %q, want OPERATION_PAST_POINT_OF_NO_RETURN; body %s", problem.ErrorCode, rec.Body.String())
	}
}

// --- /operations/sign/status and /operations/sign/cancel ----------------------

func TestSignDataStatusReturns200(t *testing.T) {
	// The spec sets minItems: 1 on items (see
	// TestSignDataStatusEmptyItemsRenders500 in validate_routes_test.go), so
	// this fixture must carry at least one shape-compliant item rather than
	// an empty slice.
	a := &stubAsyncSign{status: &mdl.SignOperationStatusResponseV2Dto{
		Items: []mdl.SignatureResultItemV2Dto{{Identifier: "a", Status: mdl.OPERATIONSTATUS_IN_PROGRESS}},
	}}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncSign(a))

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign/status", operationTrackingBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v; body %s", err, rec.Body.String())
	}
	if _, ok := got["items"]; !ok {
		t.Errorf("body = %s, want top-level \"items\"", rec.Body.String())
	}
}

func TestSignDataStatusMapsUnknownHandleTo404(t *testing.T) {
	a := &stubAsyncSign{statusErr: cryptography.ErrOperationNotTracked}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncSign(a))

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign/status", operationTrackingBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != "OPERATION_NOT_TRACKED" {
		t.Errorf("errorCode = %q, want OPERATION_NOT_TRACKED; body %s", problem.ErrorCode, rec.Body.String())
	}
}

func TestSignDataStatusRejectsNilProviderResponse(t *testing.T) {
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncSign(&stubAsyncSign{}))

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign/status", operationTrackingBody)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a nil provider response; body %s", rec.Code, rec.Body.String())
	}
}

func TestCancelSignDataReturns204(t *testing.T) {
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncSign(&stubAsyncSign{}))

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign/cancel", operationTrackingBody)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %s, want empty for 204", rec.Body.String())
	}
}

func TestCancelSignDataMapsNotTrackedTo404(t *testing.T) {
	a := &stubAsyncSign{cancelErr: cryptography.ErrOperationNotTracked}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncSign(a))

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign/cancel", operationTrackingBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != "OPERATION_NOT_TRACKED" {
		t.Errorf("errorCode = %q, want OPERATION_NOT_TRACKED; body %s", problem.ErrorCode, rec.Body.String())
	}
}

func TestCancelSignDataMapsRefusalTo422(t *testing.T) {
	a := &stubAsyncSign{cancelErr: cryptography.ErrCancelPastPointOfNoReturn}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncSign(a))

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign/cancel", operationTrackingBody)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body %s", rec.Code, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != "OPERATION_PAST_POINT_OF_NO_RETURN" {
		t.Errorf("errorCode = %q, want OPERATION_PAST_POINT_OF_NO_RETURN; body %s", problem.ErrorCode, rec.Body.String())
	}
}

// --- Decode failure: missing required operationMeta ---------------------------

// TestStatusAndCancelRoutesRejectMissingOperationMeta exercises the
// shared.DecodeJSON error branch that opens all six new handlers.
// OperationTrackingRequestV2Dto requires operationMeta, so posting `{}`
// fails the generated DTO's UnmarshalJSON before the handler ever calls the
// sub-provider; shared.DecodeJSON maps that to Invalid("VALIDATION_FAILED",
// ...) = 422 (see connector/shared/codec.go).
func TestStatusAndCancelRoutesRejectMissingOperationMeta(t *testing.T) {
	srv := newTestServer(t, &stubProvider{},
		cryptography.WithAsyncKeys(&stubAsyncKeys{}),
		cryptography.WithAsyncSign(&stubAsyncSign{}),
	)

	for _, path := range []string{
		"/v2/cryptographyProvider/keys/create/status",
		"/v2/cryptographyProvider/keys/create/cancel",
		"/v2/cryptographyProvider/keys/destroy/status",
		"/v2/cryptographyProvider/keys/destroy/cancel",
		"/v2/cryptographyProvider/operations/sign/status",
		"/v2/cryptographyProvider/operations/sign/cancel",
	} {
		t.Run(path, func(t *testing.T) {
			rec := post(t, srv, path, `{}`)

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

// --- Mount routes --------------------------------------------------------------

func TestMountRegistersAllTwentyFourRoutes(t *testing.T) {
	for name, opts := range map[string][]cryptography.Option{
		"without sub-interfaces": nil,
		"fully configured":       {cryptography.WithAsyncKeys(&stubAsyncKeys{}), cryptography.WithAsyncSign(&stubAsyncSign{})},
	} {
		t.Run(name, func(t *testing.T) {
			h, err := cryptography.NewHandler(&stubProvider{}, opts...)
			if err != nil {
				t.Fatalf("NewHandler: %v", err)
			}

			rec := &recordingRouter{}
			h.Mount(rec)

			assertMountedExactly(t, rec.patterns)
		})
	}
}

func assertMountedExactly(t *testing.T, patterns []string) {
	t.Helper()
	if len(patterns) != 24 {
		t.Fatalf("mounted %d routes, want 24: %v", len(patterns), patterns)
	}

	want := map[string]bool{
		"GET /v2/cryptographyProvider/tokens/attributes":               true,
		"POST /v2/cryptographyProvider/tokens/tokenProfile/attributes": true,
		"POST /v2/cryptographyProvider/keys/create/attributes":         true,
		"POST /v2/cryptographyProvider/operations/encrypt/attributes":  true,
		"POST /v2/cryptographyProvider/operations/decrypt/attributes":  true,
		"POST /v2/cryptographyProvider/operations/sign/attributes":     true,
		"POST /v2/cryptographyProvider/operations/verify/attributes":   true,
		"POST /v2/cryptographyProvider/operations/random/attributes":   true,
		"POST /v2/cryptographyProvider/tokens/status":                  true,
		"POST /v2/cryptographyProvider/tokens/tokenProfile/keyUsages":  true,
		"POST /v2/cryptographyProvider/tokens/keyRequestTypes":         true,
		"POST /v2/cryptographyProvider/keys":                           true,
		"POST /v2/cryptographyProvider/keys/destroy":                   true,
		"POST /v2/cryptographyProvider/operations/sign":                true,
		"POST /v2/cryptographyProvider/operations/encrypt":             true,
		"POST /v2/cryptographyProvider/operations/decrypt":             true,
		"POST /v2/cryptographyProvider/operations/verify":              true,
		"POST /v2/cryptographyProvider/operations/random":              true,
		"POST /v2/cryptographyProvider/keys/create/status":             true,
		"POST /v2/cryptographyProvider/keys/create/cancel":             true,
		"POST /v2/cryptographyProvider/keys/destroy/status":            true,
		"POST /v2/cryptographyProvider/keys/destroy/cancel":            true,
		"POST /v2/cryptographyProvider/operations/sign/status":         true,
		"POST /v2/cryptographyProvider/operations/sign/cancel":         true,
	}
	if len(want) != 24 {
		t.Fatalf("test bug: want set has %d entries, need 24", len(want))
	}
	for _, p := range patterns {
		if strings.ContainsAny(p, "{}") {
			t.Errorf("pattern %q contains a wildcard; v2 has no path parameters", p)
		}
		if !want[p] {
			t.Errorf("mounted unexpected pattern %q", p)
		}
		delete(want, p)
	}
	for missing := range want {
		t.Errorf("pattern %q was not mounted", missing)
	}
}
