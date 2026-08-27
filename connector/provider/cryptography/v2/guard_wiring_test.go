package cryptography_test

// Route-level tests pinning each response-side guard to its call site in
// routes.go: every fixture below is well formed except for the one field the
// guard checks, and the test asserts the guard's own detail so that removing
// the call, or comparing the request against itself, fails a test.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const violates = "provider response violates the contract: "

// assertShapeViolation asserts a 500 problem whose detail names the guard.
func assertShapeViolation(t *testing.T, rec *httptest.ResponseRecorder, msg string) {
	t.Helper()
	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, violates+msg)
}

// keyPairCreationResponse is a complete key-pair arm shaped for a synchronous
// 200. Tests mutate one fragment.
func keyPairCreationResponse(mutate func(*mdl.KeyPairDataResponseV2Dto)) *mdl.KeyCreationResponse {
	v := &mdl.KeyPairDataResponseV2Dto{
		KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR,
		KeyPairMeta:    []mdl.MetadataAttribute{metadataAttributeFixture()},
		PublicKeyData: &mdl.PublicKeyDataResponseV2Dto{
			KeyMeta: []mdl.MetadataAttribute{metadataAttributeFixture()},
			KeyData: *mdl.NewPublicKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048, "AA=="),
		},
		PrivateKeyData: &mdl.PrivateKeyDataResponseV2Dto{
			KeyMeta: []mdl.MetadataAttribute{metadataAttributeFixture()},
			KeyData: *mdl.NewPrivateKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048),
		},
	}
	mutate(v)
	return &mdl.KeyCreationResponse{KeyPairDataResponseV2Dto: v}
}

func keyPairCreateKeyBody(executionMode string) string {
	return strings.Replace(createKeyBody(executionMode), `"keyRequestType":"secret"`, `"keyRequestType":"keyPair"`, 1)
}

// --- Identifier correlation: response compared against the request ------------

func TestSignResponseIdentifiersMustMatchRequest(t *testing.T) {
	p := &stubProvider{signDataResp: &mdl.SignDataResponseV2Dto{
		Signatures: []mdl.SignatureDataV2Dto{{Identifier: "WRONG", Data: "AA=="}},
	}}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/operations/sign", signDataBody("synchronous"))
	assertShapeViolation(t, rec, "sign data response identifiers must match the request identifiers")
}

func TestEncryptResponseIdentifiersMustMatchRequest(t *testing.T) {
	p := &stubProvider{encryptData: &mdl.EncryptDataResponseV2Dto{
		EncryptedData: []mdl.CipherDataV2Dto{{Identifier: "WRONG", Data: "AA=="}},
	}}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/operations/encrypt", cipherDataBody)
	assertShapeViolation(t, rec, "encrypt data response identifiers must match the request identifiers")
}

func TestDecryptResponseIdentifiersMustMatchRequest(t *testing.T) {
	p := &stubProvider{decryptData: &mdl.DecryptDataResponseV2Dto{
		DecryptedData: []mdl.CipherDataV2Dto{{Identifier: "WRONG", Data: "AA=="}},
	}}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/operations/decrypt", cipherDataBody)
	assertShapeViolation(t, rec, "decrypt data response identifiers must match the request identifiers")
}

func TestVerifyResponseIdentifiersMustMatchRequest(t *testing.T) {
	p := &stubProvider{verifyData: &mdl.VerifyDataResponseV2Dto{
		Verifications: []mdl.VerificationResponseItemV2Dto{{Identifier: "WRONG", Result: true}},
	}}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/operations/verify", verifyDataBody)
	assertShapeViolation(t, rec, "verify data response identifiers must match the request identifiers")
}

func TestEncryptResponseEntriesMustCarryData(t *testing.T) {
	p := &stubProvider{encryptData: &mdl.EncryptDataResponseV2Dto{
		EncryptedData: []mdl.CipherDataV2Dto{{Identifier: "c-1"}},
	}}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/operations/encrypt", cipherDataBody)
	assertShapeViolation(t, rec, "encrypt data response entries must not carry empty data")
}

// --- Random data: decoded length against the request ---------------------------

func TestRandomDataResponseLengthMustMatchRequest(t *testing.T) {
	p := &stubProvider{randomData: &mdl.RandomDataResponseV2Dto{Data: "AAA="}} // 2 bytes, 1 requested
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/operations/random", randomDataBody)
	assertShapeViolation(t, rec, "random data length must match the requested length")
}

func TestRandomDataResponseMustBeBase64(t *testing.T) {
	p := &stubProvider{randomData: &mdl.RandomDataResponseV2Dto{Data: "not base64 !"}}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/operations/random", randomDataBody)
	assertShapeViolation(t, rec, "random data must be valid base64")
}

// --- Sign status: identifiers across the batch ---------------------------------

func TestSignStatusResponseIdentifiersMustBeUnique(t *testing.T) {
	sig := "AA=="
	p := &stubAsyncSign{status: &mdl.SignOperationStatusResponseV2Dto{Items: []mdl.SignatureResultItemV2Dto{
		{Identifier: "d-1", Status: mdl.OPERATIONSTATUS_COMPLETED, Signature: &sig},
		{Identifier: "d-1", Status: mdl.OPERATIONSTATUS_COMPLETED, Signature: &sig},
	}}}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncSign(p))
	rec := post(t, srv, "/v2/cryptographyProvider/operations/sign/status", operationTrackingBody)
	assertShapeViolation(t, rec, "sign status response identifiers must be unique")
}

// --- Key creation: requested type, key-pair arm, descriptors --------------------

func TestCreateKeyResponseMustAnswerTheRequestedKeyRequestType(t *testing.T) {
	// A complete, self-consistent key pair answering a request for a secret key.
	p := &stubProvider{createKeyResp: keyPairCreationResponse(func(*mdl.KeyPairDataResponseV2Dto) {})}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/keys", createKeyBody("synchronous"))
	assertShapeViolation(t, rec, "keyRequestType must match the requested key request type")
}

func TestCreateKeyRendersCompleteKeyPairAs200(t *testing.T) {
	p := &stubProvider{createKeyResp: keyPairCreationResponse(func(*mdl.KeyPairDataResponseV2Dto) {})}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/keys", keyPairCreateKeyBody("synchronous"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got mdl.KeyPairDataResponseV2Dto
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v; body %s", err, rec.Body.String())
	}
	if got.PublicKeyData == nil || got.PublicKeyData.KeyData.PublicKeySpki != "AA==" {
		t.Errorf("publicKeyData not round-tripped; body %s", rec.Body.String())
	}
}

func TestCreateKeyKeyPairResponseGuards(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*mdl.KeyPairDataResponseV2Dto)
		want   string
	}{
		{"publicKeySpki missing", func(v *mdl.KeyPairDataResponseV2Dto) { v.PublicKeyData.KeyData.PublicKeySpki = "" },
			"publicKeyData.keyData must carry publicKeySpki"},
		{"lengths disagree", func(v *mdl.KeyPairDataResponseV2Dto) { v.PrivateKeyData.KeyData.Length = 4096 },
			"public and private key lengths must match"},
		{"private keyMeta missing", func(v *mdl.KeyPairDataResponseV2Dto) { v.PrivateKeyData.KeyMeta = nil },
			"key creation completed synchronously must carry a result payload"},
		{"public descriptor carries the private type", func(v *mdl.KeyPairDataResponseV2Dto) { v.PublicKeyData.KeyData.Type = "Private" },
			"publicKeyData.keyData must carry key type Public"},
		{"zero-value keyPairMeta element", func(v *mdl.KeyPairDataResponseV2Dto) { v.KeyPairMeta = []mdl.MetadataAttribute{{}} },
			"keyPairMeta entries must populate exactly one metadata attribute variant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &stubProvider{createKeyResp: keyPairCreationResponse(tc.mutate)}
			rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/keys", keyPairCreateKeyBody("synchronous"))
			assertShapeViolation(t, rec, tc.want)
		})
	}
}

func TestCreateKeySecretDescriptorMustCarryThePinnedType(t *testing.T) {
	resp := secretKeyCreationResponse()
	resp.SecretKeyDataResponseV2Dto.KeyData.Type = "Public"
	p := &stubProvider{createKeyResp: resp}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/keys", createKeyBody("synchronous"))
	assertShapeViolation(t, rec, "keyData must carry key type Secret")
}

func TestCreateKeyStatusCompletedKeyPairResultIsChecked(t *testing.T) {
	result := keyPairCreationResponse(func(v *mdl.KeyPairDataResponseV2Dto) { v.PublicKeyData.KeyData.PublicKeySpki = "" })
	p := &stubAsyncKeys{createStatus: &mdl.KeyCreationStatusResponse{
		KeyPairOperationStatusResponseV2Dto: &mdl.KeyPairOperationStatusResponseV2Dto{
			Status:         mdl.OPERATIONSTATUS_COMPLETED,
			KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR,
			Result:         result.KeyPairDataResponseV2Dto,
		},
	}}
	srv := newTestServer(t, &stubProvider{}, cryptography.WithAsyncKeys(p))
	rec := post(t, srv, "/v2/cryptographyProvider/keys/create/status", operationTrackingBody)
	assertShapeViolation(t, rec, "publicKeyData.keyData must carry publicKeySpki")
}

// --- The oneOf zero-value trap on 202 -------------------------------------------

func TestAcceptedResponsesRejectZeroValueOperationMetaElement(t *testing.T) {
	empty := []mdl.MetadataAttribute{{}}
	cases := []struct {
		name, path, body string
		provider         *stubProvider
	}{
		{"createKey", "/v2/cryptographyProvider/keys", createKeyBody("asynchronous"), &stubProvider{
			createKeyResp:     &mdl.KeyCreationResponse{SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_SECRET, OperationMeta: empty}},
			createKeyAccepted: true}},
		{"destroyKey", "/v2/cryptographyProvider/keys/destroy", destroyKeyBody("asynchronous"), &stubProvider{
			destroyKeyResp: &mdl.KeyOperationResponseV2Dto{OperationMeta: empty}, destroyKeyAccepted: true}},
		{"signData", "/v2/cryptographyProvider/operations/sign", signDataBody("asynchronous"), &stubProvider{
			signDataResp: &mdl.SignDataResponseV2Dto{OperationMeta: empty}, signDataAccepted: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(t, newTestServer(t, tc.provider), tc.path, tc.body)
			assertShapeViolation(t, rec, "operationMeta entries must populate exactly one metadata attribute variant")
		})
	}
}

// --- Enum-valued responses -------------------------------------------------------

func TestTokenStatusResponseMustCarryAKnownStatus(t *testing.T) {
	p := &stubProvider{tokenStatus: &mdl.TokenStatusResponseV2Dto{}} // Status ""
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/tokens/status", tokenScopedBody)
	assertShapeViolation(t, rec, "token status must be a known token status")
}

func TestTokenProfileKeyUsagesMustBeKnownValues(t *testing.T) {
	p := &stubProvider{tokenProfileKeyUsages: []mdl.KeyUsage{"bogus"}}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/tokens/tokenProfile/keyUsages", tokenScopedBody)
	assertShapeViolation(t, rec, "key usages must contain only known values")
}

func TestKeyRequestTypesMustBeKnownValues(t *testing.T) {
	p := &stubProvider{keyRequestTypes: []mdl.KeyRequestType{"x"}}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/tokens/keyRequestTypes", tokenProfileScopedBody)
	assertShapeViolation(t, rec, "key request types must contain only known values")
}

// --- Request side: the verify identifier-set rule is exact on its own ----------

func TestVerifyDataRejectsDuplicateSignatureIdentifiersCoveringTheDataSet(t *testing.T) {
	body := keyScopedPrefix + `,"signatureAttributes":[],"data":[{"identifier":"a","data":"AA=="},{"identifier":"b","data":"AA=="}],"signatures":[{"identifier":"a","data":"AA=="},{"identifier":"a","data":"AA=="}]}`
	rec := post(t, newTestServer(t, &stubProvider{}), "/v2/cryptographyProvider/operations/verify", body)
	problem := assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
	assertDetail(t, problem, "signatures identifiers must be unique within a batch")
}

// --- Metrics: a response-shape violation is an error outcome -------------------

type recordingMetrics struct{ events map[string]int }

func (m *recordingMetrics) Handler() http.Handler                             { return http.NotFoundHandler() }
func (m *recordingMetrics) ObserveRequest(string, string, int, time.Duration) {}
func (m *recordingMetrics) InFlightInc(string)                                {}
func (m *recordingMetrics) InFlightDec(string)                                {}
func (m *recordingMetrics) IncConnectorEvent(event, outcome string)           { m.events[event+"/"+outcome]++ }

func TestResponseShapeViolationIsCountedAsErrorOutcome(t *testing.T) {
	mc := &recordingMetrics{events: map[string]int{}}
	h, err := cryptography.NewHandler(&stubProvider{createKeyResp: secretKeyCreationResponse(), createKeyAccepted: false})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	c, err := shared.New(
		shared.WithInfo(shared.Info{ID: "a", Name: "a", Version: "0.0.1"}),
		shared.WithMetrics(mc),
		shared.Register(h),
	)
	if err != nil {
		t.Fatalf("shared.New: %v", err)
	}

	rec := post(t, c.Handler(), "/v2/cryptographyProvider/keys", createKeyBody("asynchronous"))

	assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	if mc.events["create_key/error"] != 1 || mc.events["create_key/ok"] != 0 {
		t.Errorf("events = %v, want exactly one create_key/error and no create_key/ok", mc.events)
	}
}
