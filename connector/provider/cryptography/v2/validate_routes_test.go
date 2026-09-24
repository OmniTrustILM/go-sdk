package cryptography_test

// Black-box HTTP-level tests proving validate.go's guards are wired into the
// route handlers in routes.go. See validate_test.go (package cryptography,
// not cryptography_test) for exhaustive branch coverage of the guard
// functions themselves, including validateExecutionMode's branches that are
// not reachable through the HTTP surface at all.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// assertProblem asserts rec's status code and decodes its body into
// shared.ProblemDetail, asserting errorCode. Used by every test in this
// file so a rejection is proven to carry a real problem document — not a
// half-written success payload, and not a 500 from ErrNilResponse or a
// panic landing on the right status code by coincidence — rather than only
// asserting the status survived.
func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantErrorCode string) shared.ProblemDetail {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, wantStatus, rec.Body.String())
	}
	var problem shared.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshal problem body: %v; body %s", err, rec.Body.String())
	}
	if problem.ErrorCode != wantErrorCode {
		t.Errorf("errorCode = %q, want %q; body %s", problem.ErrorCode, wantErrorCode, rec.Body.String())
	}
	return problem
}

// Leading scope every operation request body carries. The one keyMeta entry
// lets a body pass the earlier guards and reach the rule under test.
const (
	tokenScopedPrefix = `{"tokenAttributes":[],"tokenProfileAttributes":[]`
	keyScopedPrefix   = tokenScopedPrefix + `,"keyMeta":` + oneMetadataAttribute
)

// assertDetail asserts the problem document's human-readable detail.
// shared.ProblemDetail models it as *string (the field is optional in RFC
// 9457), so a nil detail is a failure in its own right: a guard whose message
// never reached the body would otherwise look like a match.
func assertDetail(t *testing.T, problem shared.ProblemDetail, want string) {
	t.Helper()
	if problem.Detail == nil {
		t.Fatalf("detail = nil, want %q", want)
	}
	if *problem.Detail != want {
		t.Errorf("detail = %q, want %q", *problem.Detail, want)
	}
}

// --- Request side: unique identifiers within a batch -------------------------

func TestSignRejectsDuplicateIdentifiersInABatch(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign",
		keyScopedPrefix+`,"executionMode":"synchronous","signatureAttributes":[],"data":[{"identifier":"a","data":"AA=="},{"identifier":"a","data":"BB=="}]}`)

	assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
}

func TestEncryptDataRejectsDuplicateIdentifiersInABatch(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	rec := post(t, srv, "/v2/cryptographyProvider/operations/encrypt",
		keyScopedPrefix+`,"cipherAttributes":[],"cipherData":[{"identifier":"a","data":"AA=="},{"identifier":"a","data":"BB=="}]}`)

	assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
}

func TestDecryptDataRejectsDuplicateIdentifiersInABatch(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	rec := post(t, srv, "/v2/cryptographyProvider/operations/decrypt",
		keyScopedPrefix+`,"cipherAttributes":[],"cipherData":[{"identifier":"a","data":"AA=="},{"identifier":"a","data":"BB=="}]}`)

	assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
}

func TestVerifyDataRejectsDuplicateIdentifiersInDataBatch(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	rec := post(t, srv, "/v2/cryptographyProvider/operations/verify",
		keyScopedPrefix+`,"signatureAttributes":[],"data":[{"identifier":"a","data":"AA=="},{"identifier":"a","data":"BB=="}],"signatures":[{"identifier":"a","data":"AA=="}]}`)

	assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
}

func TestVerifyDataRejectsDuplicateIdentifiersInSignaturesBatch(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	rec := post(t, srv, "/v2/cryptographyProvider/operations/verify",
		keyScopedPrefix+`,"signatureAttributes":[],"data":[{"identifier":"a","data":"AA=="}],"signatures":[{"identifier":"s","data":"AA=="},{"identifier":"s","data":"BB=="}]}`)

	assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
}

func TestVerifyDataRejectsMismatchedIdentifiers(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	rec := post(t, srv, "/v2/cryptographyProvider/operations/verify",
		keyScopedPrefix+`,"signatureAttributes":[],"data":[{"identifier":"a","data":"AA=="}],"signatures":[{"identifier":"b","data":"AA=="}]}`)

	assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
}

// --- Request side: minItems: 1 on the batch lists -----------------------------

// TestRoutesRejectEmptyBatchLists proves the spec's minItems: 1 is enforced on
// the way IN, on every request array that declares it. Each body is otherwise
// contract-compliant, so the named empty list is the only violation, and each
// case asserts the detail message names that list — a 422 alone would not
// prove the intended rule fired rather than a neighbouring one.
//
// Without these guards an empty batch reached the provider and the response it
// produced then failed the response-side guards, turning a client's malformed
// request into a 500 that accused the connector (asyncSignWithNoData below is
// exactly that case).
func TestRoutesRejectEmptyBatchLists(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		body       string
		wantDetail string
	}{
		{
			"sign without data", "/v2/cryptographyProvider/operations/sign",
			keyScopedPrefix + `,"executionMode":"synchronous","signatureAttributes":[],"data":[]}`,
			"data must not be empty",
		},
		{
			"sign without keyMeta", "/v2/cryptographyProvider/operations/sign",
			tokenScopedPrefix + `,"keyMeta":[],"executionMode":"synchronous","signatureAttributes":[],"data":[{"identifier":"a","data":"AA=="}]}`,
			"keyMeta must not be empty",
		},
		{
			"encrypt without cipherData", "/v2/cryptographyProvider/operations/encrypt",
			keyScopedPrefix + `,"cipherAttributes":[],"cipherData":[]}`,
			"cipherData must not be empty",
		},
		{
			"decrypt without cipherData", "/v2/cryptographyProvider/operations/decrypt",
			keyScopedPrefix + `,"cipherAttributes":[],"cipherData":[]}`,
			"cipherData must not be empty",
		},
		{
			"verify without data", "/v2/cryptographyProvider/operations/verify",
			keyScopedPrefix + `,"signatureAttributes":[],"data":[],"signatures":[{"identifier":"a","data":"AA=="}]}`,
			"data must not be empty",
		},
		{
			"verify without signatures", "/v2/cryptographyProvider/operations/verify",
			keyScopedPrefix + `,"signatureAttributes":[],"data":[{"identifier":"a","data":"AA=="}],"signatures":[]}`,
			"signatures must not be empty",
		},
		{
			"destroy without keyMeta", "/v2/cryptographyProvider/keys/destroy",
			tokenScopedPrefix + `,"keyMeta":[],"executionMode":"synchronous"}`,
			"keyMeta must not be empty",
		},
		{
			"encrypt attributes without keyMeta", "/v2/cryptographyProvider/operations/encrypt/attributes",
			tokenScopedPrefix + `,"keyMeta":[]}`,
			"keyMeta must not be empty",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, &stubProvider{})

			rec := post(t, srv, tc.path, tc.body)

			problem := assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
			assertDetail(t, problem, tc.wantDetail)
		})
	}
}

func TestKeyScopedRoutesRejectEmptyKeyMeta(t *testing.T) {
	for _, route := range tokenProfileScopedRoutes {
		if !strings.Contains(route.body, oneMetadataAttribute) {
			continue
		}
		t.Run(route.path, func(t *testing.T) {
			body := strings.Replace(route.body, oneMetadataAttribute, "[]", 1)

			rec := post(t, newTestServer(t, &stubProvider{}), route.path, body)

			problem := assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
			assertDetail(t, problem, "keyMeta must not be empty")
		})
	}
}

// An asynchronous sign with "data":[] must be refused at the boundary with
// 422, not accepted with 202: an accepted empty batch surfaces later as a 500
// "items must not be empty" from the status call, blaming the connector for a
// body the SDK should have rejected.
func TestAsyncSignWithEmptyDataIsRejectedAtTheBoundary(t *testing.T) {
	srv := newTestServer(t, &stubProvider{
		signDataResp: &mdl.SignDataResponseV2Dto{
			OperationMeta: []mdl.MetadataAttribute{metadataAttributeFixture()},
		},
		signDataAccepted: true,
	}, cryptography.WithAsyncSign(&stubAsyncSign{}))

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign",
		keyScopedPrefix+`,"executionMode":"asynchronous","signatureAttributes":[],"data":[]}`)

	problem := assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
	assertDetail(t, problem, "data must not be empty")
	// The provider must not have been reached at all: no operation may have
	// been tracked for a request that never validated.
	if strings.Contains(rec.Body.String(), "operationMeta") {
		t.Errorf("body = %s, must not carry a tracking handle for a rejected request", rec.Body.String())
	}
}

// TestStatusAndCancelRoutesRejectEmptyOperationMeta covers the operationMeta
// minItems: 1 list, on the DTO all six status/cancel routes decode.
func TestStatusAndCancelRoutesRejectEmptyOperationMeta(t *testing.T) {
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
			rec := post(t, srv, path, `{"operationMeta":[]}`)

			problem := assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
			assertDetail(t, problem, "operationMeta must not be empty")
		})
	}
}

// --- Request side: token-profile key usages -----------------------------------

// tokenProfileScopedRoutes holds every route whose request extends the
// token-profile scope. wantStatus is tokenNotFoundProvider's answer: 404 from
// a provider route, 200 from an unregistered attribute route.
var tokenProfileScopedRoutes = []struct {
	path       string
	body       string
	wantStatus int
}{
	{"/v2/cryptographyProvider/tokens/keyRequestTypes", tokenProfileScopedBody, http.StatusNotFound},
	{"/v2/cryptographyProvider/operations/random/attributes", tokenProfileScopedBody, http.StatusOK},
	{"/v2/cryptographyProvider/operations/encrypt/attributes", keyScopedRequestBody, http.StatusOK},
	{"/v2/cryptographyProvider/operations/decrypt/attributes", keyScopedRequestBody, http.StatusOK},
	{"/v2/cryptographyProvider/operations/sign/attributes", keyScopedRequestBody, http.StatusOK},
	{"/v2/cryptographyProvider/operations/verify/attributes", keyScopedRequestBody, http.StatusOK},
	{"/v2/cryptographyProvider/operations/encrypt", cipherDataBody, http.StatusNotFound},
	{"/v2/cryptographyProvider/operations/decrypt", cipherDataBody, http.StatusNotFound},
	{"/v2/cryptographyProvider/keys/create/attributes", createKeyAttributesRequestBody, http.StatusOK},
	{"/v2/cryptographyProvider/keys", createKeyBody("synchronous"), http.StatusNotFound},
	{"/v2/cryptographyProvider/keys/destroy", destroyKeyBody("synchronous"), http.StatusNotFound},
	{"/v2/cryptographyProvider/operations/sign", signDataBody("synchronous"), http.StatusNotFound},
	{"/v2/cryptographyProvider/operations/verify", verifyDataBody, http.StatusNotFound},
	{"/v2/cryptographyProvider/operations/random", randomDataBody, http.StatusNotFound},
}

// tokenNotFoundProvider fails every token-profile-scoped call with
// ErrTokenNotFound. A 404 therefore proves the request reached the provider.
func tokenNotFoundProvider() *stubProvider {
	err := cryptography.ErrTokenNotFound
	return &stubProvider{
		keyRequestTypesErr: err,
		createKeyErr:       err,
		destroyKeyErr:      err,
		signDataErr:        err,
		verifyDataErr:      err,
		encryptDataErr:     err,
		decryptDataErr:     err,
		randomDataErr:      err,
	}
}

func TestRoutesAcceptRequestsWithoutKeyUsages(t *testing.T) {
	for _, route := range tokenProfileScopedRoutes {
		t.Run(route.path, func(t *testing.T) {
			rec := post(t, newTestServer(t, tokenNotFoundProvider()), route.path, route.body)

			if rec.Code != route.wantStatus {
				t.Errorf("status = %d, want %d; body %s", rec.Code, route.wantStatus, rec.Body.String())
			}
		})
	}
}

// Token-profile key usages are Core policy. The request DTOs reject them as
// an unknown property.
func TestRoutesRejectRequestsCarryingKeyUsages(t *testing.T) {
	for _, route := range tokenProfileScopedRoutes {
		t.Run(route.path, func(t *testing.T) {
			body := strings.Replace(route.body, "{", `{"keyUsages":["sign"],`, 1)

			rec := post(t, newTestServer(t, tokenNotFoundProvider()), route.path, body)

			assertProblem(t, rec, http.StatusBadRequest, "INVALID_JSON")
		})
	}
}

// --- Request side: keyCreationId ----------------------------------------------

func TestCreateKeyRejectsBlankKeyCreationId(t *testing.T) {
	srv := newTestServer(t, &stubProvider{createKeyResp: secretKeyCreationResponse()})

	rec := post(t, srv, "/v2/cryptographyProvider/keys",
		tokenScopedPrefix+`,"keyRequestType":"secret","executionMode":"synchronous","keyCreationId":"   ","createKeyAttributes":[]}`)

	assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
}

func TestCreateKeyRejectsKeyCreationIdOver256Chars(t *testing.T) {
	srv := newTestServer(t, &stubProvider{createKeyResp: secretKeyCreationResponse()})

	rec := post(t, srv, "/v2/cryptographyProvider/keys",
		tokenScopedPrefix+`,"keyRequestType":"secret","executionMode":"synchronous","keyCreationId":"`+strings.Repeat("a", 257)+`","createKeyAttributes":[]}`)

	assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
}

// --- Request side: random data length -----------------------------------------

func TestRandomDataRejectsInvalidLength(t *testing.T) {
	for _, length := range []int{0, -1, 1048577} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			srv := newTestServer(t, &stubProvider{randomData: &mdl.RandomDataResponseV2Dto{}})

			body := tokenScopedPrefix + `,"length":` +
				strconv.Itoa(length) + `,"operationAttributes":[]}`
			rec := post(t, srv, "/v2/cryptographyProvider/operations/random", body)

			assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
		})
	}
}

// --- Response side: a malformed 202/200 is a provider bug, never a client
// error, and must never reach Core -------------------------------------------

func TestAcceptedResponseWithoutOperationMetaRenders500(t *testing.T) {
	p := &stubProvider{
		signDataResp:     &mdl.SignDataResponseV2Dto{}, // no OperationMeta
		signDataAccepted: true,
	}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign",
		keyScopedPrefix+`,"executionMode":"asynchronous","signatureAttributes":[],"data":[{"identifier":"a","data":"AA=="}]}`)

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: sign data accepted for asynchronous execution must carry operationMeta")
}

func TestSynchronousResponseCarryingOperationMetaRenders500(t *testing.T) {
	p := &stubProvider{
		signDataResp: &mdl.SignDataResponseV2Dto{
			OperationMeta: []mdl.MetadataAttribute{metadataAttributeFixture()},
		},
		signDataAccepted: false,
	}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign",
		keyScopedPrefix+`,"executionMode":"synchronous","signatureAttributes":[],"data":[{"identifier":"a","data":"AA=="}]}`)

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: sign data completed synchronously must not carry operationMeta")
}

func TestSynchronousSignResponseMissingSignaturesRenders500(t *testing.T) {
	p := &stubProvider{signDataResp: &mdl.SignDataResponseV2Dto{}, signDataAccepted: false}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign",
		keyScopedPrefix+`,"executionMode":"synchronous","signatureAttributes":[],"data":[{"identifier":"a","data":"AA=="}]}`)

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: sign data completed synchronously must carry a result payload")
}

func TestAcceptedSignResponseCarryingSignaturesRenders500(t *testing.T) {
	p := &stubProvider{
		signDataResp: &mdl.SignDataResponseV2Dto{
			OperationMeta: []mdl.MetadataAttribute{metadataAttributeFixture()},
			Signatures:    []mdl.SignatureDataV2Dto{{Identifier: "a", Data: "AA=="}},
		},
		signDataAccepted: true,
	}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign",
		keyScopedPrefix+`,"executionMode":"asynchronous","signatureAttributes":[],"data":[{"identifier":"a","data":"AA=="}]}`)

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: sign data accepted for asynchronous execution must not carry a result payload")
	// The failure mode the guard exists to prevent: the leftover signature
	// must never leak into the body Core sees.
	if strings.Contains(rec.Body.String(), "signatures") {
		t.Errorf("body = %s, must not carry the rejected signatures payload", rec.Body.String())
	}
}

func TestCreateKeyAcceptedResponseWithoutOperationMetaRenders500(t *testing.T) {
	p := &stubProvider{
		createKeyResp: &mdl.KeyCreationResponse{
			SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_SECRET},
		},
		createKeyAccepted: true,
	}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/keys", createKeyBody("asynchronous"))

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: key creation accepted for asynchronous execution must carry operationMeta")
}

func TestCreateKeySynchronousResponseWithPartialPayloadRenders500(t *testing.T) {
	p := &stubProvider{
		createKeyResp: &mdl.KeyCreationResponse{
			SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
				KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
				KeyData:        mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048), // KeyMeta missing: partial payload
			},
		},
		createKeyAccepted: false,
	}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/keys", createKeyBody("synchronous"))

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: key creation completed synchronously must carry a result payload")
}

func TestDestroyKeyAcceptedResponseWithoutOperationMetaRenders500(t *testing.T) {
	p := &stubProvider{destroyKeyResp: &mdl.KeyOperationResponseV2Dto{}, destroyKeyAccepted: true}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy", destroyKeyBody("asynchronous"))

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: key destruction accepted for asynchronous execution must carry operationMeta")
}

func TestDestroyKeySynchronousResponseCarryingOperationMetaRenders500(t *testing.T) {
	p := &stubProvider{
		destroyKeyResp:     &mdl.KeyOperationResponseV2Dto{OperationMeta: []mdl.MetadataAttribute{metadataAttributeFixture()}},
		destroyKeyAccepted: false,
	}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy", destroyKeyBody("synchronous"))

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: key destruction completed synchronously must not carry operationMeta")
}

// TestCreateKeyResponseWithoutKeyRequestTypeRenders500 proves the oneOf
// discriminator is checked on the way out. keyRequestType has no omitempty in
// the generated struct, so an unset one is serialized as "" — not a member of
// the KeyRequestType enum, leaving Core unable to resolve the variant of an
// otherwise well-formed 200.
func TestCreateKeyResponseWithoutKeyRequestTypeRenders500(t *testing.T) {
	p := &stubProvider{
		createKeyResp: &mdl.KeyCreationResponse{
			SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
				// Complete payload, absent discriminator.
				KeyData: mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048),
				KeyMeta: []mdl.MetadataAttribute{metadataAttributeFixture()},
			},
		},
	}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/keys", createKeyBody("synchronous"))

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: keyRequestType is required on the populated key data variant")
}

// TestCreateKeyResponseWithMismatchedKeyRequestTypeRenders500 is the other
// half of the same rule: a discriminator naming the arm that is not populated
// is as unresolvable as an absent one.
func TestCreateKeyResponseWithMismatchedKeyRequestTypeRenders500(t *testing.T) {
	p := &stubProvider{
		createKeyResp: &mdl.KeyCreationResponse{
			SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
				KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR, // names the other arm
				KeyData:        mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048),
				KeyMeta:        []mdl.MetadataAttribute{metadataAttributeFixture()},
			},
		},
	}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/keys", createKeyBody("synchronous"))

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: keyRequestType must match the populated key data variant")
}

// TestCreateKeyStatusResponseWithMismatchedKeyRequestTypeRenders500 pins the
// same guard on the status arms, which carry the same required discriminator.
func TestCreateKeyStatusResponseWithMismatchedKeyRequestTypeRenders500(t *testing.T) {
	a := &stubAsyncKeys{
		createStatus: &mdl.KeyCreationStatusResponse{
			KeyPairOperationStatusResponseV2Dto: &mdl.KeyPairOperationStatusResponseV2Dto{
				KeyRequestType: mdl.KEYREQUESTTYPE_SECRET, // names the other arm
				Status:         mdl.OPERATIONSTATUS_IN_PROGRESS,
			},
		},
	}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/create/status", operationTrackingBody)

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: keyRequestType must match the populated key data variant")
}

// --- Response side: status shape (reason iff failed/cancelled, result iff
// completed) ------------------------------------------------------------------

func TestSignStatusItemMissingReasonForFailedRenders500(t *testing.T) {
	a := &stubAsyncSign{
		status: &mdl.SignOperationStatusResponseV2Dto{
			Items: []mdl.SignatureResultItemV2Dto{
				{Identifier: "d1", Status: mdl.OPERATIONSTATUS_FAILED}, // no Reason
			},
		},
	}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncSign(a))

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign/status", operationTrackingBody)

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: reason is required when status is failed or cancelled")
}

func TestCreateKeyStatusMissingReasonForFailedRenders500(t *testing.T) {
	a := &stubAsyncKeys{
		createStatus: &mdl.KeyCreationStatusResponse{
			SecretKeyOperationStatusResponseV2Dto: &mdl.SecretKeyOperationStatusResponseV2Dto{
				Status:         mdl.OPERATIONSTATUS_FAILED, // no Reason
				KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			},
		},
	}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/create/status", operationTrackingBody)

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: reason is required when status is failed or cancelled")
}

// TestDestroyKeyStatusCompletedRenders200 proves that a completed
// asynchronous key destruction is renderable at all.
// KeyDestructionStatusResponseV2Dto has no result field (see the comment on
// destroyKeyStatus in routes.go), so the "result present iff completed" rule
// that validateStatusShape applies for DTOs with a real result field must not
// be applied here: applied to this DTO it would reject every completed
// destroy as missing a result, and no compliant connector could report one.
// destroyKeyStatus therefore calls validateStatusReason instead.
func TestDestroyKeyStatusCompletedRenders200(t *testing.T) {
	a := &stubAsyncKeys{
		destroyStatus: &mdl.KeyDestructionStatusResponseV2Dto{Status: mdl.OPERATIONSTATUS_COMPLETED},
	}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy/status", operationTrackingBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v; body %s", err, rec.Body.String())
	}
	if got["status"] != "completed" {
		t.Errorf("body = %s, want top-level status=\"completed\"", rec.Body.String())
	}
}

// TestDestroyKeyStatusFailedWithReasonRenders200 proves the reason rules do
// still hold through the wire path: a failed destroy with a non-blank reason
// is compliant and must render 200.
func TestDestroyKeyStatusFailedWithReasonRenders200(t *testing.T) {
	reason := "token removed"
	a := &stubAsyncKeys{
		destroyStatus: &mdl.KeyDestructionStatusResponseV2Dto{
			Status: mdl.OPERATIONSTATUS_FAILED,
			Reason: &reason,
		},
	}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy/status", operationTrackingBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v; body %s", err, rec.Body.String())
	}
	if got["status"] != "failed" {
		t.Errorf("body = %s, want top-level status=\"failed\"", rec.Body.String())
	}
	if got["reason"] != reason {
		t.Errorf("body = %s, want top-level reason=%q", rec.Body.String(), reason)
	}
}

// TestDestroyKeyStatusCompletedWithReasonRenders500 proves the
// reason-must-be-absent-when-completed rule still applies to the DTO with no
// result field: a completed destroy carrying a reason is a contract
// violation.
func TestDestroyKeyStatusCompletedWithReasonRenders500(t *testing.T) {
	reason := "should not be here"
	a := &stubAsyncKeys{
		destroyStatus: &mdl.KeyDestructionStatusResponseV2Dto{
			Status: mdl.OPERATIONSTATUS_COMPLETED,
			Reason: &reason,
		},
	}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy/status", operationTrackingBody)

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: reason must be absent unless status is failed or cancelled")
}

// TestSignDataStatusEmptyItemsRenders500 proves the spec's minItems: 1 on
// SignOperationStatusResponseV2Dto.items is enforced: an empty items array
// skips the per-item validation loop entirely (the loop body never runs), so
// only an explicit emptiness check can catch it.
func TestSignDataStatusEmptyItemsRenders500(t *testing.T) {
	a := &stubAsyncSign{
		status: &mdl.SignOperationStatusResponseV2Dto{Items: []mdl.SignatureResultItemV2Dto{}},
	}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncSign(a))

	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign/status", operationTrackingBody)

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: items must not be empty")
}

func TestDestroyKeyStatusMissingReasonForFailedRenders500(t *testing.T) {
	a := &stubAsyncKeys{
		destroyStatus: &mdl.KeyDestructionStatusResponseV2Dto{
			Status: mdl.OPERATIONSTATUS_FAILED, // no Reason
		},
	}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(a))

	rec := post(t, srv, "/v2/cryptographyProvider/keys/destroy/status", operationTrackingBody)

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: reason is required when status is failed or cancelled")
}

// --- Response side: the caller-selected mode must survive the round trip ------

// TestSynchronousRequestReportedAcceptedRenders500 proves the mode guard is
// wired into all three caller-selected-mode routes. Each stub returns a
// response that is perfectly well formed *for a 202*, so the mode mismatch is
// the only violation and a 500 here cannot be another guard firing. Without
// this the SDK would answer a synchronous request with a 202 tracking handle
// its caller never agreed to poll.
func TestSynchronousRequestReportedAcceptedRenders500(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		body       string
		provider   *stubProvider
		wantDetail string
	}{
		{
			name:       "createKey",
			path:       "/v2/cryptographyProvider/keys",
			body:       createKeyBody("synchronous"),
			provider:   &stubProvider{createKeyResp: secretKeyCreationAcceptedResponse(), createKeyAccepted: true},
			wantDetail: "provider response violates the contract: key creation requested synchronously must not be accepted for asynchronous execution",
		},
		{
			name: "destroyKey",
			path: "/v2/cryptographyProvider/keys/destroy",
			body: destroyKeyBody("synchronous"),
			provider: &stubProvider{
				destroyKeyResp:     &mdl.KeyOperationResponseV2Dto{OperationMeta: []mdl.MetadataAttribute{metadataAttributeFixture()}},
				destroyKeyAccepted: true,
			},
			wantDetail: "provider response violates the contract: key destruction requested synchronously must not be accepted for asynchronous execution",
		},
		{
			name: "signData",
			path: "/v2/cryptographyProvider/operations/sign",
			body: signDataBody("synchronous"),
			provider: &stubProvider{
				signDataResp:     &mdl.SignDataResponseV2Dto{OperationMeta: []mdl.MetadataAttribute{metadataAttributeFixture()}},
				signDataAccepted: true,
			},
			wantDetail: "provider response violates the contract: sign data requested synchronously must not be accepted for asynchronous execution",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, tc.provider)

			rec := post(t, srv, tc.path, tc.body)

			problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
			assertDetail(t, problem, tc.wantDetail)
		})
	}
}

// TestAsynchronousRequestCompletedInlineRejected pins the second direction of
// the mode guard. Core requires HTTP 202 for an asynchronous request, so a
// connector answering one inline produces a response Core rejects; the SDK
// reports it here as a provider bug instead. A connector that cannot execute
// asynchronously declines the mode by leaving the asynchronous feature flag
// unadvertised, so Core never selects it.
func TestAsynchronousRequestCompletedInlineRejected(t *testing.T) {
	p := &stubProvider{createKeyResp: secretKeyCreationResponse(), createKeyAccepted: false}
	srv := newTestServer(t, p)

	rec := post(t, srv, "/v2/cryptographyProvider/keys", createKeyBody("asynchronous"))

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: key creation requested asynchronously must be accepted for asynchronous execution")
}
