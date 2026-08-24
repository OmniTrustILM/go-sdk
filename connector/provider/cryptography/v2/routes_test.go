package cryptography_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
)

// Request bodies satisfying each DTO's generated required-property check and
// the contract's minItems/uniqueItems constraints on its batch lists (see
// TestUnregisteredAttributeEndpointsReturnEmptyArray in attributes_test.go for
// the same convention on the attribute-schema DTOs).
const (
	// oneKeyUsage and oneMetadataAttribute are the smallest values that
	// satisfy the spec's minItems: 1 on keyUsages and on the metadata batches
	// (keyMeta, operationMeta): validateKeyUsages and validateNonEmptyBatch
	// reject an empty one with 422 before the provider is called, so a body
	// meant to reach the provider cannot leave them empty. oneMetadataAttribute
	// carries every property MetadataAttributeV2 requires, and version 2 so
	// the discriminator-aware decoder picks that arm.
	oneKeyUsage          = `["sign"]`
	oneMetadataAttribute = `[{"uuid":"m-1","name":"handle","version":2,"type":"meta","contentType":"string","properties":{"label":"handle","visible":true}}]`

	tokenScopedBody        = `{"tokenAttributes":[]}`
	tokenProfileScopedBody = `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyUsages":` + oneKeyUsage + `}`
	cipherDataBody         = `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyUsages":` + oneKeyUsage + `,"keyMeta":` + oneMetadataAttribute + `,"cipherAttributes":[],"cipherData":[{"identifier":"c-1","data":"AA=="}]}`
	verifyDataBody         = `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyUsages":` + oneKeyUsage + `,"keyMeta":` + oneMetadataAttribute + `,"signatureAttributes":[],"data":[{"identifier":"d-1","data":"AA=="}],"signatures":[{"identifier":"d-1","data":"BB=="}]}`
	// length is 1, not 0: validateRandomDataLength rejects a non-positive
	// length before the provider is called.
	randomDataBody = `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyUsages":` + oneKeyUsage + `,"length":1,"operationAttributes":[]}`
)

// --- /tokens/status -----------------------------------------------------------

func TestTokenStatusReturns200WithProviderPayload(t *testing.T) {
	want := "Connected"
	p := &stubProvider{tokenStatus: &mdl.TokenStatusResponseV2Dto{Status: mdl.TokenStatusV2(want)}}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/tokens/status", strings.NewReader(tokenScopedBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got mdl.TokenStatusResponseV2Dto
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(got.Status) != want {
		t.Errorf("Status = %q, want %q", got.Status, want)
	}
}

func TestTokenStatusMapsProviderErrorToProblem(t *testing.T) {
	p := &stubProvider{tokenStatusErr: cryptography.ErrTokenNotFound}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/tokens/status", strings.NewReader(tokenScopedBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

func TestTokenStatusRejectsNilProviderResponse(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/tokens/status", strings.NewReader(tokenScopedBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a nil provider response; body %s", rec.Code, rec.Body.String())
	}
}

// --- /tokens/tokenProfile/keyUsages --------------------------------------------

func TestTokenProfileKeyUsagesReturns200WithProviderPayload(t *testing.T) {
	p := &stubProvider{tokenProfileKeyUsages: []mdl.KeyUsage{mdl.KEYUSAGE_SIGN, mdl.KEYUSAGE_VERIFY}}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/tokens/tokenProfile/keyUsages", strings.NewReader(tokenScopedBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got []mdl.KeyUsage
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 2 || got[0] != mdl.KEYUSAGE_SIGN || got[1] != mdl.KEYUSAGE_VERIFY {
		t.Errorf("got %v, want [sign verify]", got)
	}
}

func TestTokenProfileKeyUsagesNormalizesNilToEmptyArray(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/tokens/tokenProfile/keyUsages", strings.NewReader(tokenScopedBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("body = %s, want []", got)
	}
}

func TestTokenProfileKeyUsagesMapsProviderErrorToProblem(t *testing.T) {
	p := &stubProvider{tokenProfileKeyUsagesErr: cryptography.ErrTokenNotFound}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/tokens/tokenProfile/keyUsages", strings.NewReader(tokenScopedBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}

// --- /tokens/keyRequestTypes ---------------------------------------------------

func TestKeyRequestTypesReturns200WithProviderPayload(t *testing.T) {
	p := &stubProvider{keyRequestTypes: []mdl.KeyRequestType{mdl.KEYREQUESTTYPE_SECRET}}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/tokens/keyRequestTypes", strings.NewReader(tokenProfileScopedBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got []mdl.KeyRequestType
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 || got[0] != mdl.KEYREQUESTTYPE_SECRET {
		t.Errorf("got %v, want [secret]", got)
	}
}

func TestKeyRequestTypesNormalizesNilToEmptyArray(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/tokens/keyRequestTypes", strings.NewReader(tokenProfileScopedBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("body = %s, want []", got)
	}
}

func TestKeyRequestTypesMapsProviderErrorToProblem(t *testing.T) {
	p := &stubProvider{keyRequestTypesErr: cryptography.ErrTokenNotFound}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/tokens/keyRequestTypes", strings.NewReader(tokenProfileScopedBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}

// --- /operations/encrypt -------------------------------------------------------

func TestEncryptDataReturns200WithProviderPayload(t *testing.T) {
	p := &stubProvider{encryptData: &mdl.EncryptDataResponseV2Dto{
		EncryptedData: []mdl.CipherDataV2Dto{{Identifier: "c-1", Data: "AA=="}},
	}}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/operations/encrypt", strings.NewReader(cipherDataBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got mdl.EncryptDataResponseV2Dto
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The stub's payload must survive to the wire; see async_test.go's oneOf
	// zero-value trap.
	if len(got.EncryptedData) != 1 || got.EncryptedData[0].Identifier != "c-1" || got.EncryptedData[0].Data != "AA==" {
		t.Errorf("EncryptedData = %+v, want the stub's single item", got.EncryptedData)
	}
}

func TestEncryptDataRejectsNilProviderResponse(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/operations/encrypt", strings.NewReader(cipherDataBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a nil provider response; body %s", rec.Code, rec.Body.String())
	}
}

func TestEncryptDataMapsProviderErrorToProblem(t *testing.T) {
	p := &stubProvider{encryptDataErr: cryptography.ErrKeyNotFound}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/operations/encrypt", strings.NewReader(cipherDataBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}

// --- /operations/decrypt -------------------------------------------------------

func TestDecryptDataReturns200WithProviderPayload(t *testing.T) {
	p := &stubProvider{decryptData: &mdl.DecryptDataResponseV2Dto{
		DecryptedData: []mdl.CipherDataV2Dto{{Identifier: "c-1", Data: "BB=="}},
	}}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/operations/decrypt", strings.NewReader(cipherDataBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got mdl.DecryptDataResponseV2Dto
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// See TestEncryptDataReturns200WithProviderPayload on why the payload,
	// not just the status, has to be asserted.
	if len(got.DecryptedData) != 1 || got.DecryptedData[0].Identifier != "c-1" || got.DecryptedData[0].Data != "BB==" {
		t.Errorf("DecryptedData = %+v, want the stub's single item", got.DecryptedData)
	}
}

func TestDecryptDataRejectsNilProviderResponse(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/operations/decrypt", strings.NewReader(cipherDataBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a nil provider response; body %s", rec.Code, rec.Body.String())
	}
}

func TestDecryptDataMapsProviderErrorToProblem(t *testing.T) {
	p := &stubProvider{decryptDataErr: cryptography.ErrKeyNotFound}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/operations/decrypt", strings.NewReader(cipherDataBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}

// --- /operations/verify ---------------------------------------------------------

func TestVerifyDataReturns200WithProviderPayload(t *testing.T) {
	p := &stubProvider{verifyData: &mdl.VerifyDataResponseV2Dto{
		Verifications: []mdl.VerificationResponseItemV2Dto{{Identifier: "d-1", Result: true}},
	}}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/operations/verify", strings.NewReader(verifyDataBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got mdl.VerifyDataResponseV2Dto
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// See TestEncryptDataReturns200WithProviderPayload on why the payload,
	// not just the status, has to be asserted.
	if len(got.Verifications) != 1 || got.Verifications[0].Identifier != "d-1" || !got.Verifications[0].Result {
		t.Errorf("Verifications = %+v, want the stub's single passing item", got.Verifications)
	}
}

func TestVerifyDataRejectsNilProviderResponse(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/operations/verify", strings.NewReader(verifyDataBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a nil provider response; body %s", rec.Code, rec.Body.String())
	}
}

func TestVerifyDataMapsProviderErrorToProblem(t *testing.T) {
	p := &stubProvider{verifyDataErr: cryptography.ErrKeyNotFound}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/operations/verify", strings.NewReader(verifyDataBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}

// --- /operations/random ---------------------------------------------------------

func TestRandomDataReturns200WithProviderPayload(t *testing.T) {
	// randomDataBody requests one byte, so the fixture must decode to one byte.
	want := "AA=="
	p := &stubProvider{randomData: &mdl.RandomDataResponseV2Dto{Data: want}}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/operations/random", strings.NewReader(randomDataBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got mdl.RandomDataResponseV2Dto
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Data != want {
		t.Errorf("Data = %q, want %q", got.Data, want)
	}
}

func TestRandomDataRejectsNilProviderResponse(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/operations/random", strings.NewReader(randomDataBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a nil provider response; body %s", rec.Code, rec.Body.String())
	}
}

func TestRandomDataMapsProviderErrorToProblem(t *testing.T) {
	p := &stubProvider{randomDataErr: cryptography.ErrTokenNotFound}
	srv := newTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/v2/cryptographyProvider/operations/random", strings.NewReader(randomDataBody))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}
