package cryptography_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
)

const (
	importKeyPath          = "/v2/cryptographyProvider/keys/import"
	importableKeyTypesPath = "/v2/cryptographyProvider/keys/import/keyTypes"
	importKeyAttrsPath     = "/v2/cryptographyProvider/keys/import/attributes"
	importKeyResultPath    = "/v2/cryptographyProvider/keys/import/result"
	importKeyStatusPath    = "/v2/cryptographyProvider/keys/import/status"
	importKeyCancelPath    = "/v2/cryptographyProvider/keys/import/cancel"

	// An envelope within the pinned profile, made by OpenSSL 3.5. The routes
	// check its protection; none of these tests opens it.
	inProfileEnvelope = "MIH1MGAGCSqGSIb3DQEFDTBTMDIGCSqGSIb3DQEFDDAlBBCCdQZrT+tPCaXnHkdV2MbPAgMBhqAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEF5CvgXm9cZ1TfHrhNkxz4QEgZD09zLsdfg5O1H0BLWFMd4E2E1v8vLQ5He16MKbFdvoC3eJkTbGUG6s2+wbKoQ/zDYO925zVZF9K5zeZh2hNsSzUIvKtdZhU+Di4/WKWR0L4SiXWsq2ttweajXHAGisb/pz3nF06EgvK6qygEEjiUfJX+XM5TSzJs7+NULXUBWSCB/iYfbAo2mdWVb3MSC5aX0="

	keyReferenceFixture         = "0f8c3a4e-8d8e-4c8a-9d6b-2a6b3c1d4e5f"
	importKeyAttributesBody     = `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyRequestType":"secret"}`
	importKeyResultBody         = `{"tokenAttributes":[],"keyImportId":"import-1"}`
	keyImportNotSupportedDetail = "key import is not implemented by this connector"
)

// importKeyFields are the import request's fields in order, each with the
// value a valid synchronous secret-key import carries.
var importKeyFields = [][2]string{
	{"tokenAttributes", `[]`},
	{"tokenProfileAttributes", `[]`},
	{"keyImportId", `"import-1"`},
	{"keyReference", `"` + keyReferenceFixture + `"`},
	{"executionMode", `"synchronous"`},
	{"keyRequestType", `"secret"`},
	{"importKeyAttributes", `[]`},
	{"material", `{"encryptedPrivateKeyInfo":"` + inProfileEnvelope + `"}`},
	{"passphrase", `"transport phrase"`},
	{"exportable", `false`},
}

// importKeyBody renders a valid import request with the given fields
// replaced by raw JSON values.
func importKeyBody(overrides map[string]string) string {
	fields := make([]string, len(importKeyFields))
	for i, field := range importKeyFields {
		value := field[1]
		if override, ok := overrides[field[0]]; ok {
			value = override
		}
		fields[i] = `"` + field[0] + `":` + value
	}
	return "{" + strings.Join(fields, ",") + "}"
}

func asynchronousImport() map[string]string {
	return map[string]string{"executionMode": `"asynchronous"`}
}

func newImportServer(t *testing.T, imports *stubKeyImport, opts ...cryptography.Option) http.Handler {
	t.Helper()
	return newTestServer(t, &stubProvider{}, append([]cryptography.Option{cryptography.WithKeyImport(imports)}, opts...)...)
}

// --- /keys/import ---------------------------------------------------------------

func TestImportKeyRendersSyncAs200(t *testing.T) {
	imports := &stubKeyImport{importResp: secretKeyCreationResponse()}
	srv := newImportServer(t, imports)

	rec := post(t, srv, importKeyPath, importKeyBody(nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got mdl.KeyCreationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.SecretKeyDataResponseV2Dto == nil {
		t.Fatalf("body = %s, want the secret-key result: %v", rec.Body.String(), err)
	}
	if imports.imported == nil || imports.imported.Passphrase != "transport phrase" || imports.imported.KeyReference != keyReferenceFixture {
		t.Errorf("provider received %+v, want the decoded request", imports.imported)
	}
}

func TestImportKeyRendersAcceptedAs202(t *testing.T) {
	srv := newImportServer(t, &stubKeyImport{importResp: secretKeyCreationAcceptedResponse(), importAccepted: true})

	rec := post(t, srv, importKeyPath, importKeyBody(asynchronousImport()))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	var got mdl.KeyCreationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.SecretKeyDataResponseV2Dto == nil ||
		len(got.SecretKeyDataResponseV2Dto.OperationMeta) != 1 {
		t.Fatalf("body = %s, want the tracking handle: %v", rec.Body.String(), err)
	}
}

func TestImportKeyRendersTheProvidersRefusals(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{cryptography.ErrKeyImportConflict, http.StatusConflict, "RESOURCE_ALREADY_EXISTS"},
		{cryptography.ErrKeyTypeNotImportable, http.StatusUnprocessableEntity, "KEY_TYPE_NOT_IMPORTABLE"},
		{cryptography.ErrKeyMaterialMismatch, http.StatusUnprocessableEntity, "KEY_MATERIAL_MISMATCH"},
		{cryptography.ErrKeyDecryptionFailed, http.StatusUnprocessableEntity, "KEY_DECRYPTION_FAILED"},
		{cryptography.ErrExportableNotSupported, http.StatusUnprocessableEntity, "EXPORTABLE_NOT_SUPPORTED"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			srv := newImportServer(t, &stubKeyImport{importErr: tc.err})

			assertProblem(t, post(t, srv, importKeyPath, importKeyBody(nil)), tc.status, tc.code)
		})
	}
}

func TestImportKeyRejectsNilProviderResponse(t *testing.T) {
	srv := newImportServer(t, &stubKeyImport{})

	assertProblem(t, post(t, srv, importKeyPath, importKeyBody(nil)), http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
}

func TestImportKeyRejectsAnInvalidRequestBeforeTheProviderRuns(t *testing.T) {
	notDER := `{"encryptedPrivateKeyInfo":"` + base64.StdEncoding.EncodeToString([]byte("not an envelope")) + `"}`
	cases := []struct {
		name      string
		overrides map[string]string
		status    int
		code      string
		detail    string
	}{
		{"blank keyImportId", map[string]string{"keyImportId": `"   "`}, http.StatusUnprocessableEntity, "VALIDATION_FAILED",
			"keyImportId is required and must not be blank"},
		{"long keyImportId", map[string]string{"keyImportId": `"` + strings.Repeat("é", 257) + `"`}, http.StatusUnprocessableEntity,
			"VALIDATION_FAILED", "keyImportId must not exceed 256 characters"},
		{"blank keyReference", map[string]string{"keyReference": `""`}, http.StatusUnprocessableEntity, "VALIDATION_FAILED",
			"keyReference is required"},
		{"keyReference that is no UUID", map[string]string{"keyReference": `"not-a-uuid"`}, http.StatusUnprocessableEntity,
			"VALIDATION_FAILED", "keyReference must be a canonical UUID"},
		{"keyReference with a trailing character", map[string]string{"keyReference": `"` + keyReferenceFixture + `0"`},
			http.StatusUnprocessableEntity, "VALIDATION_FAILED", "keyReference must be a canonical UUID"},
		{"blank passphrase", map[string]string{"passphrase": `"  "`}, http.StatusUnprocessableEntity, "VALIDATION_FAILED",
			"passphrase is required"},
		{"material that is not base64", map[string]string{"material": `{"encryptedPrivateKeyInfo":"not base64!"}`},
			http.StatusBadRequest, "BAD_REQUEST", "material.encryptedPrivateKeyInfo must be base64"},
		{"material outside the profile", map[string]string{"material": notDER}, http.StatusUnprocessableEntity, "VALIDATION_FAILED",
			"encryptedPrivateKeyInfo must contain a DER-encoded PKCS#8 EncryptedPrivateKeyInfo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			imports := &stubKeyImport{importResp: secretKeyCreationResponse()}
			srv := newImportServer(t, imports)

			problem := assertProblem(t, post(t, srv, importKeyPath, importKeyBody(tc.overrides)), tc.status, tc.code)
			assertDetail(t, problem, tc.detail)
			if imports.imported != nil {
				t.Error("the provider ran for a request the handler refuses")
			}
		})
	}
}

func TestImportKeyRejectsAResponseOutsideTheContract(t *testing.T) {
	incomplete := secretKeyCreationResponse()
	incomplete.SecretKeyDataResponseV2Dto.KeyData = nil
	cases := []struct {
		name      string
		overrides map[string]string
		resp      *mdl.KeyCreationResponse
		accepted  bool
		detail    string
	}{
		{"accepted when asked to run synchronously", nil, secretKeyCreationAcceptedResponse(), true,
			"key import requested synchronously must not be accepted for asynchronous execution"},
		{"completed when asked to run asynchronously", asynchronousImport(), secretKeyCreationResponse(), false,
			"key import requested asynchronously must be accepted for asynchronous execution"},
		{"an incomplete result", nil, incomplete, false, "key import completed synchronously must carry a result payload"},
		{"accepted without a tracking handle", asynchronousImport(), &mdl.KeyCreationResponse{
			SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_SECRET},
		}, true, "key import accepted for asynchronous execution must carry operationMeta"},
		{"another key request type", nil, keyPairCreationResponse(func(*mdl.KeyPairDataResponseV2Dto) {}), false,
			"keyRequestType must match the requested key request type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newImportServer(t, &stubKeyImport{importResp: tc.resp, importAccepted: tc.accepted})

			assertShapeViolation(t, post(t, srv, importKeyPath, importKeyBody(tc.overrides)), tc.detail)
		})
	}
}

// --- /keys/import/keyTypes --------------------------------------------------------

func TestImportableKeyTypesReturnsTheDeclarations(t *testing.T) {
	srv := newImportServer(t, &stubKeyImport{keyTypes: []mdl.ImportableKeyTypeV2Dto{
		{KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR, Algorithms: []mdl.KeyAlgorithm{mdl.KEYALGORITHM_RSA, mdl.KEYALGORITHM_ECDSA}},
	}})

	rec := post(t, srv, importableKeyTypesPath, tokenProfileScopedBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	assertJSONEqual(t, rec.Body.Bytes(), `[{"keyRequestType":"keyPair","algorithms":["RSA","ECDSA"]}]`)
}

func TestImportableKeyTypesNormalizesNilToEmptyArray(t *testing.T) {
	srv := newImportServer(t, &stubKeyImport{})

	rec := post(t, srv, importableKeyTypesPath, tokenProfileScopedBody)

	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("got %d %s, want 200 []", rec.Code, rec.Body.String())
	}
}

func TestImportableKeyTypesRejectsDeclarationsOutsideTheContract(t *testing.T) {
	pair := func(algorithms ...mdl.KeyAlgorithm) mdl.ImportableKeyTypeV2Dto {
		return mdl.ImportableKeyTypeV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR, Algorithms: algorithms}
	}
	cases := []struct {
		name     string
		keyTypes []mdl.ImportableKeyTypeV2Dto
		detail   string
	}{
		{"a key type twice", []mdl.ImportableKeyTypeV2Dto{pair(mdl.KEYALGORITHM_RSA), pair(mdl.KEYALGORITHM_ECDSA)},
			"importable key types must declare each key request type once"},
		{"an unknown key type", []mdl.ImportableKeyTypeV2Dto{{KeyRequestType: "quantum", Algorithms: []mdl.KeyAlgorithm{mdl.KEYALGORITHM_RSA}}},
			"importable key types must name known key request types"},
		{"no algorithms", []mdl.ImportableKeyTypeV2Dto{pair()}, "importable key types must declare at least one algorithm per key type"},
		{"an algorithm twice", []mdl.ImportableKeyTypeV2Dto{pair(mdl.KEYALGORITHM_RSA, mdl.KEYALGORITHM_RSA)},
			"importable key types must not repeat an algorithm"},
		{"the Unknown algorithm", []mdl.ImportableKeyTypeV2Dto{pair(mdl.KEYALGORITHM_UNKNOWN)},
			"importable key types must declare known algorithms other than Unknown"},
		{"an algorithm outside the contract", []mdl.ImportableKeyTypeV2Dto{pair("Nope")},
			"importable key types must declare known algorithms other than Unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newImportServer(t, &stubKeyImport{keyTypes: tc.keyTypes})

			assertShapeViolation(t, post(t, srv, importableKeyTypesPath, tokenProfileScopedBody), tc.detail)
		})
	}
}

// --- /keys/import/attributes ------------------------------------------------------

func TestImportKeyAttributesServesTheRegisteredSchema(t *testing.T) {
	srv := newTestServer(t, &stubProvider{}, cryptography.WithImportKeyAttributes(&stubTransferAttributes{
		importAttrs: []mdl.BaseAttributeDto{cryptography.KeyExportableDefinition()},
	}))

	rec := post(t, srv, importKeyAttrsPath, importKeyAttributesBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got []mdl.BaseAttributeDto
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 1 {
		t.Fatalf("body = %s, want one definition: %v", rec.Body.String(), err)
	}
}

// --- /keys/import/result ----------------------------------------------------------

func TestImportKeyResultReturnsTheRecordedState(t *testing.T) {
	srv := newImportServer(t, &stubKeyImport{result: secretKeyCreationStatusResponse()})

	rec := post(t, srv, importKeyResultPath, importKeyResultBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got mdl.KeyCreationStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.SecretKeyOperationStatusResponseV2Dto == nil {
		t.Fatalf("body = %s, want the recorded state: %v", rec.Body.String(), err)
	}
}

func TestImportKeyResultRendersAnImportNeverAcceptedAs404(t *testing.T) {
	srv := newImportServer(t, &stubKeyImport{resultErr: cryptography.ErrOperationNotTracked})

	assertProblem(t, post(t, srv, importKeyResultPath, importKeyResultBody), http.StatusNotFound, "OPERATION_NOT_TRACKED")
}

func TestImportKeyResultRejectsABlankKeyImportId(t *testing.T) {
	srv := newImportServer(t, &stubKeyImport{result: secretKeyCreationStatusResponse()})

	problem := assertProblem(t, post(t, srv, importKeyResultPath, `{"tokenAttributes":[],"keyImportId":" "}`),
		http.StatusUnprocessableEntity, "VALIDATION_FAILED")
	assertDetail(t, problem, "keyImportId is required and must not be blank")
}

func TestImportKeyResultChecksTheResultOfACompletedImport(t *testing.T) {
	completed := &mdl.KeyCreationStatusResponse{
		SecretKeyOperationStatusResponseV2Dto: &mdl.SecretKeyOperationStatusResponseV2Dto{
			Status:         mdl.OPERATIONSTATUS_COMPLETED,
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			Result:         &mdl.SecretKeyDataResponseV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_SECRET},
		},
	}
	srv := newImportServer(t, &stubKeyImport{result: completed})

	assertShapeViolation(t, post(t, srv, importKeyResultPath, importKeyResultBody),
		"completed key import result must carry a result payload")
}

// --- /keys/import/status and /keys/import/cancel ------------------------------------

func TestImportKeyStatusAndCancelServeTheAsyncProvider(t *testing.T) {
	srv := newImportServer(t, &stubKeyImport{}, cryptography.WithAsyncKeyImport(&stubAsyncKeyImport{status: secretKeyCreationStatusResponse()}))

	if rec := post(t, srv, importKeyStatusPath, operationTrackingBody); rec.Code != http.StatusOK {
		t.Errorf("status route = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if rec := post(t, srv, importKeyCancelPath, operationTrackingBody); rec.Code != http.StatusNoContent {
		t.Errorf("cancel route = %d, want 204; body %s", rec.Code, rec.Body.String())
	}
}

func TestCancelImportKeyRendersTheProvidersRefusals(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{cryptography.ErrCancelPastPointOfNoReturn, http.StatusUnprocessableEntity, "OPERATION_PAST_POINT_OF_NO_RETURN"},
		{cryptography.ErrOperationNotTracked, http.StatusNotFound, "OPERATION_NOT_TRACKED"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			srv := newImportServer(t, &stubKeyImport{}, cryptography.WithAsyncKeyImport(&stubAsyncKeyImport{cancelErr: tc.err}))

			assertProblem(t, post(t, srv, importKeyCancelPath, operationTrackingBody), tc.status, tc.code)
		})
	}
}

func TestImportKeyStatusChecksTheStatusShape(t *testing.T) {
	inconsistent := secretKeyCreationStatusResponse()
	inconsistent.SecretKeyOperationStatusResponseV2Dto.KeyRequestType = mdl.KEYREQUESTTYPE_KEY_PAIR
	srv := newImportServer(t, &stubKeyImport{}, cryptography.WithAsyncKeyImport(&stubAsyncKeyImport{status: inconsistent}))

	assertProblem(t, post(t, srv, importKeyStatusPath, operationTrackingBody), http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
}

// --- Without the providers ----------------------------------------------------------

func TestImportRoutesRender404WithoutTheirProviders(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})
	cases := []struct {
		path, body, detail string
	}{
		{importKeyPath, importKeyBody(nil), keyImportNotSupportedDetail},
		{importableKeyTypesPath, tokenProfileScopedBody, keyImportNotSupportedDetail},
		{importKeyResultPath, importKeyResultBody, keyImportNotSupportedDetail},
		{importKeyStatusPath, operationTrackingBody, "asynchronous execution is not implemented by this connector"},
		{importKeyCancelPath, operationTrackingBody, "asynchronous execution is not implemented by this connector"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			problem := assertProblem(t, post(t, srv, tc.path, tc.body), http.StatusNotFound, "OPERATION_NOT_SUPPORTED")
			assertDetail(t, problem, tc.detail)
		})
	}
}

func TestImportKeyAttributesWithoutAProviderReturnEmptyArray(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	rec := post(t, srv, importKeyAttrsPath, importKeyAttributesBody)

	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("got %d %s, want 200 []", rec.Code, rec.Body.String())
	}
}

func TestImportRoutesRejectAnUnreadableBody(t *testing.T) {
	srv := newImportServer(t, &stubKeyImport{})
	for _, path := range []string{importKeyPath, importableKeyTypesPath, importKeyAttrsPath, importKeyResultPath} {
		t.Run(path, func(t *testing.T) {
			assertProblem(t, post(t, srv, path, `{`), http.StatusBadRequest, "INVALID_JSON")
		})
	}
}

func TestImportKeyAttributesRendersTheProvidersError(t *testing.T) {
	srv := newTestServer(t, &stubProvider{}, cryptography.WithImportKeyAttributes(&stubTransferAttributes{err: cryptography.ErrTokenNotFound}))

	assertProblem(t, post(t, srv, importKeyAttrsPath, importKeyAttributesBody), http.StatusNotFound, "RESOURCE_NOT_FOUND")
}

func TestImportableKeyTypesRendersTheProvidersError(t *testing.T) {
	srv := newImportServer(t, &stubKeyImport{keyTypesErr: cryptography.ErrTokenNotFound})

	assertProblem(t, post(t, srv, importableKeyTypesPath, tokenProfileScopedBody), http.StatusNotFound, "RESOURCE_NOT_FOUND")
}
