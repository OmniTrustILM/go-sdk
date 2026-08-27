package cryptography_test

// Route-level tests pinning each response-side guard to its call site in
// routes.go: every fixture below is well formed except for the one field the
// guard checks, and the test asserts the guard's own detail so that removing
// the call, or comparing the request against itself, fails a test.

import (
	"encoding/json"
	"math"
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

func TestDecryptResponseEntriesMustCarryData(t *testing.T) {
	p := &stubProvider{decryptData: &mdl.DecryptDataResponseV2Dto{
		DecryptedData: []mdl.CipherDataV2Dto{{Identifier: "c-1"}},
	}}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/operations/decrypt", cipherDataBody)
	assertShapeViolation(t, rec, "decrypt data response entries must not carry empty data")
}

func TestSignResponseEntriesMustCarryData(t *testing.T) {
	p := &stubProvider{signDataResp: &mdl.SignDataResponseV2Dto{
		Signatures: []mdl.SignatureDataV2Dto{{Identifier: "d-1"}},
	}}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/operations/sign", signDataBody("synchronous"))
	assertShapeViolation(t, rec, "sign data response entries must not carry empty data")
}

// --- Encodability: the probe behind every 2xx body -----------------------------

// unencodableMetadata is a metadata element that passes
// validateMetadataElements (one arm set) yet fails to encode: its content[]
// holds an unset BaseAttributeContentDtoV2, a oneOf wrapper whose generated
// MarshalJSON returns (nil, nil).
func unencodableMetadata() mdl.MetadataAttribute {
	m := metadataAttributeFixture()
	if m.MetadataAttributeV2 == nil {
		panic("unencodableMetadata: oneMetadataAttribute must decode to the V2 arm")
	}
	m.MetadataAttributeV2.Content = []mdl.BaseAttributeContentDtoV2{{}}
	return m
}

// A response that passes every field-level guard but cannot be encoded is
// rejected as a 500 before the event is emitted and the status committed —
// on the 202 paths, the 200 path, and for a value no shape rule can reach.
func TestUnencodableResponseIsRejectedBeforeCommit(t *testing.T) {
	nan := metadataAttributeFixture()
	nan.MetadataAttributeV2.AdditionalProperties = map[string]interface{}{"bad": math.NaN()}

	cases := []struct {
		name  string
		p     *stubProvider
		path  string
		body  string
		event string
	}{
		{"destroyKey 202 operationMeta content", &stubProvider{destroyKeyAccepted: true, destroyKeyResp: &mdl.KeyOperationResponseV2Dto{
			OperationMeta: []mdl.MetadataAttribute{unencodableMetadata()},
		}}, "/v2/cryptographyProvider/keys/destroy", destroyKeyBody("asynchronous"), "destroy_key"},
		{"signData 202 operationMeta content", &stubProvider{signDataAccepted: true, signDataResp: &mdl.SignDataResponseV2Dto{
			OperationMeta: []mdl.MetadataAttribute{unencodableMetadata()},
		}}, "/v2/cryptographyProvider/operations/sign", signDataBody("asynchronous"), "sign_data"},
		{"createKey 202 operationMeta content", &stubProvider{createKeyAccepted: true, createKeyResp: &mdl.KeyCreationResponse{
			SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
				KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
				OperationMeta:  []mdl.MetadataAttribute{unencodableMetadata()},
			},
		}}, "/v2/cryptographyProvider/keys", createKeyBody("asynchronous"), "create_key"},
		{"createKey 200 keyMeta content", &stubProvider{createKeyResp: &mdl.KeyCreationResponse{
			SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
				KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
				KeyData:        mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048),
				KeyMeta:        []mdl.MetadataAttribute{unencodableMetadata()},
			},
		}}, "/v2/cryptographyProvider/keys", createKeyBody("synchronous"), "create_key"},
		{"destroyKey 202 additionalProperties NaN", &stubProvider{destroyKeyAccepted: true, destroyKeyResp: &mdl.KeyOperationResponseV2Dto{
			OperationMeta: []mdl.MetadataAttribute{nan},
		}}, "/v2/cryptographyProvider/keys/destroy", destroyKeyBody("asynchronous"), "destroy_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc := &recordingMetrics{events: map[string]int{}}
			rec := post(t, newMeteredServer(t, tc.p, mc), tc.path, tc.body)

			assertShapeViolation(t, rec, "response cannot be encoded as JSON")
			if mc.events[tc.event+"/error"] != 1 || mc.events[tc.event+"/ok"] != 0 {
				t.Errorf("events = %v, want exactly one %s/error and no %s/ok", mc.events, tc.event, tc.event)
			}
		})
	}
}

// The key descriptors' own metadata lists are enumerated too, with the precise
// message rather than the probe's generic one.
func TestCreateKeyKeyDataMetadataElementsMustPopulateOneVariant(t *testing.T) {
	keyData := mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048)
	keyData.Metadata = []mdl.MetadataAttribute{{}}
	p := &stubProvider{createKeyResp: &mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			KeyData:        keyData,
			KeyMeta:        []mdl.MetadataAttribute{metadataAttributeFixture()},
		},
	}}
	rec := post(t, newTestServer(t, p), "/v2/cryptographyProvider/keys", createKeyBody("synchronous"))
	assertShapeViolation(t, rec, "keyData.metadata entries must populate exactly one metadata attribute variant")
}

// The attribute lists have no other shape rule, so the probe is their only
// guard against an unset BaseAttributeDto wrapper.
func TestUnencodableAttributeListIsRejectedBeforeCommit(t *testing.T) {
	srv := newTestServer(t, &stubProvider{}, cryptography.WithTokenAttributes(&stubTokenAttrs{resp: []mdl.BaseAttributeDto{{}}}))
	req := httptest.NewRequest(http.MethodGet, "/v2/cryptographyProvider/tokens/attributes", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assertShapeViolation(t, rec, "response cannot be encoded as JSON")
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

// newMeteredServer is newTestServer with mc recording connector events.
func newMeteredServer(t *testing.T, p cryptography.Provider, mc *recordingMetrics, opts ...cryptography.Option) http.Handler {
	t.Helper()
	h, err := cryptography.NewHandler(p, opts...)
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
	return c.Handler()
}

func (m *recordingMetrics) Handler() http.Handler                             { return http.NotFoundHandler() }
func (m *recordingMetrics) ObserveRequest(string, string, int, time.Duration) {}
func (m *recordingMetrics) InFlightInc(string)                                {}
func (m *recordingMetrics) InFlightDec(string)                                {}
func (m *recordingMetrics) IncConnectorEvent(event, outcome string)           { m.events[event+"/"+outcome]++ }

func TestResponseShapeViolationIsCountedAsErrorOutcome(t *testing.T) {
	mc := &recordingMetrics{events: map[string]int{}}
	srv := newMeteredServer(t, &stubProvider{createKeyResp: secretKeyCreationResponse(), createKeyAccepted: false}, mc)

	rec := post(t, srv, "/v2/cryptographyProvider/keys", createKeyBody("asynchronous"))

	assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	if mc.events["create_key/error"] != 1 || mc.events["create_key/ok"] != 0 {
		t.Errorf("events = %v, want exactly one create_key/error and no create_key/ok", mc.events)
	}
}
