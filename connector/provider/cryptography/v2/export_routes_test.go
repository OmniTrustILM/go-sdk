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
	exportKeyPath               = "/v2/cryptographyProvider/keys/export"
	exportableKeyTypesPath      = "/v2/cryptographyProvider/keys/export/keyTypes"
	exportKeyAttrsPath          = "/v2/cryptographyProvider/keys/export/attributes"
	keyExportNotSupportedDetail = "key export is not implemented by this connector"

	// omitField drops a field from a rendered request.
	omitField = "\x00omit"
)

// exportKeyFields are the export request's fields in order, each with the
// value a valid key-pair export carries.
var exportKeyFields = [][2]string{
	{"tokenAttributes", `[]`},
	{"tokenProfileAttributes", `[]`},
	{"keyMeta", oneMetadataAttribute},
	{"keyRequestType", `"keyPair"`},
	{"keyReference", `"` + keyReferenceFixture + `"`},
	{"exportKeyAttributes", `[]`},
	{"passphrase", `"export phrase"`},
}

// exportKeyBody renders a valid export request with the given fields
// replaced by raw JSON values, or dropped with omitField.
func exportKeyBody(overrides map[string]string) string {
	var fields []string
	for _, field := range exportKeyFields {
		value := field[1]
		if override, ok := overrides[field[0]]; ok {
			value = override
		}
		if value != omitField {
			fields = append(fields, `"`+field[0]+`":`+value)
		}
	}
	return "{" + strings.Join(fields, ",") + "}"
}

func secretExport() map[string]string {
	return map[string]string{"keyRequestType": `"secret"`}
}

func publicKeyExport() *mdl.ExportKeyResponseV2Dto {
	reference := keyReferenceFixture
	return &mdl.ExportKeyResponseV2Dto{
		Material:     mdl.EncryptedKeyMaterialV2Dto{EncryptedPrivateKeyInfo: inProfileEnvelope},
		KeyReference: &reference,
		KeyData:      mdl.PublicKeyDataV2DtoAsKeyDataV2(mdl.NewPublicKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048, "AA==")),
	}
}

func secretKeyExport() *mdl.ExportKeyResponseV2Dto {
	export := publicKeyExport()
	export.KeyData = mdl.SecretKeyDataV2DtoAsKeyDataV2(mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_AES, 256))
	return export
}

func newExportServer(t *testing.T, exports *stubKeyExport) http.Handler {
	t.Helper()
	return newTestServer(t, &stubProvider{}, cryptography.WithKeyExport(exports))
}

// --- /keys/export -------------------------------------------------------------------

func TestExportKeyReturnsTheProtectedKey(t *testing.T) {
	cases := map[string]struct {
		overrides map[string]string
		export    *mdl.ExportKeyResponseV2Dto
		keyType   string
	}{
		"a key pair":   {nil, publicKeyExport(), "Public"},
		"a secret key": {secretExport(), secretKeyExport(), "Secret"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			exports := &stubKeyExport{export: tc.export}
			srv := newExportServer(t, exports)

			rec := post(t, srv, exportKeyPath, exportKeyBody(tc.overrides))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			var got struct {
				Material     mdl.EncryptedKeyMaterialV2Dto `json:"material"`
				KeyReference string                        `json:"keyReference"`
				KeyData      struct {
					Type string `json:"type"`
				} `json:"keyData"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode body %s: %v", rec.Body.String(), err)
			}
			if got.Material.EncryptedPrivateKeyInfo != inProfileEnvelope || got.KeyReference != keyReferenceFixture || got.KeyData.Type != tc.keyType {
				t.Errorf("body = %s, want the envelope, the reference and a %s descriptor", rec.Body.String(), tc.keyType)
			}
			if exports.exported == nil || exports.exported.Passphrase != "export phrase" {
				t.Errorf("provider received %+v, want the decoded request", exports.exported)
			}
		})
	}
}

func TestExportKeyWithoutAKeyReferenceAnswersWithoutOne(t *testing.T) {
	export := publicKeyExport()
	export.KeyReference = nil
	srv := newExportServer(t, &stubKeyExport{export: export})

	rec := post(t, srv, exportKeyPath, exportKeyBody(map[string]string{"keyReference": omitField}))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
}

func TestExportKeyRendersTheProvidersRefusals(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{cryptography.ErrKeyNotExportable, http.StatusUnprocessableEntity, "KEY_NOT_EXPORTABLE"},
		{cryptography.ErrKeyTypeNotExportable, http.StatusUnprocessableEntity, "KEY_TYPE_NOT_EXPORTABLE"},
		{cryptography.ErrKeyMaterialMismatch, http.StatusUnprocessableEntity, "KEY_MATERIAL_MISMATCH"},
		{cryptography.ErrKeyNotFound, http.StatusNotFound, "RESOURCE_NOT_FOUND"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			srv := newExportServer(t, &stubKeyExport{exportErr: tc.err})

			assertProblem(t, post(t, srv, exportKeyPath, exportKeyBody(nil)), tc.status, tc.code)
		})
	}
}

func TestExportKeyRejectsNilProviderResponse(t *testing.T) {
	srv := newExportServer(t, &stubKeyExport{})

	assertProblem(t, post(t, srv, exportKeyPath, exportKeyBody(nil)), http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
}

func TestExportKeyRejectsAnInvalidRequestBeforeTheProviderRuns(t *testing.T) {
	cases := []struct {
		name      string
		overrides map[string]string
		detail    string
	}{
		{"no keyMeta", map[string]string{"keyMeta": `[]`}, "keyMeta must not be empty"},
		{"keyReference that is no UUID", map[string]string{"keyReference": `"not-a-uuid"`}, "keyReference must be a canonical UUID"},
		{"empty keyReference", map[string]string{"keyReference": `""`}, "keyReference must be a canonical UUID"},
		{"blank passphrase", map[string]string{"passphrase": `" "`}, "passphrase is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exports := &stubKeyExport{export: publicKeyExport()}
			srv := newExportServer(t, exports)

			problem := assertProblem(t, post(t, srv, exportKeyPath, exportKeyBody(tc.overrides)), http.StatusUnprocessableEntity, "VALIDATION_FAILED")
			assertDetail(t, problem, tc.detail)
			if exports.exported != nil {
				t.Error("the provider ran for a request the handler refuses")
			}
		})
	}
}

func TestExportKeyRejectsAResponseOutsideTheContract(t *testing.T) {
	notDER := base64.StdEncoding.EncodeToString([]byte("not an envelope"))
	other := "1b4e28ba-2fa1-11d2-883f-0016d3cca427x"
	cases := []struct {
		name      string
		overrides map[string]string
		mutate    func(*mdl.ExportKeyResponseV2Dto)
		detail    string
	}{
		{"material that is not base64", nil, func(e *mdl.ExportKeyResponseV2Dto) { e.Material.EncryptedPrivateKeyInfo = "not base64!" },
			"material must be base64"},
		{"material outside the profile", nil, func(e *mdl.ExportKeyResponseV2Dto) { e.Material.EncryptedPrivateKeyInfo = notDER },
			"encryptedPrivateKeyInfo must contain a DER-encoded PKCS#8 EncryptedPrivateKeyInfo"},
		{"a private-key descriptor", nil, func(e *mdl.ExportKeyResponseV2Dto) {
			e.KeyData = mdl.PrivateKeyDataV2DtoAsKeyDataV2(mdl.NewPrivateKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048))
		}, "keyData must describe either a public key or a secret key"},
		{"no descriptor", nil, func(e *mdl.ExportKeyResponseV2Dto) { e.KeyData = mdl.KeyDataV2{} }, "keyData must describe the exported key"},
		{"two descriptors", nil, func(e *mdl.ExportKeyResponseV2Dto) {
			e.KeyData.SecretKeyDataV2Dto = mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_AES, 256)
		}, "keyData must describe the exported key once"},
		{"a secret key for a key pair", nil, func(e *mdl.ExportKeyResponseV2Dto) {
			e.KeyData = mdl.SecretKeyDataV2DtoAsKeyDataV2(mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_AES, 256))
		}, "keyData must describe a key pair by its public key"},
		{"a public key for a secret key", secretExport(), func(*mdl.ExportKeyResponseV2Dto) {}, "keyData must describe a secret key"},
		{"a public key without its SPKI", nil, func(e *mdl.ExportKeyResponseV2Dto) { e.KeyData.PublicKeyDataV2Dto.PublicKeySpki = "" },
			"keyData must carry publicKeySpki"},
		{"an unknown algorithm", nil, func(e *mdl.ExportKeyResponseV2Dto) { e.KeyData.PublicKeyDataV2Dto.Algorithm = "Nope" },
			"keyData must carry a known key algorithm"},
		{"a keyReference the request did not carry", map[string]string{"keyReference": omitField}, func(*mdl.ExportKeyResponseV2Dto) {},
			"keyReference must be absent when the request carried none"},
		{"a keyReference that is no UUID", nil, func(e *mdl.ExportKeyResponseV2Dto) { e.KeyReference = &other },
			"keyReference must be a canonical UUID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			export := publicKeyExport()
			tc.mutate(export)
			srv := newExportServer(t, &stubKeyExport{export: export})

			assertShapeViolation(t, post(t, srv, exportKeyPath, exportKeyBody(tc.overrides)), tc.detail)
		})
	}
}

// --- /keys/export/keyTypes and /keys/export/attributes ---------------------------------

func TestExportableKeyTypesReturnsTheDeclarations(t *testing.T) {
	srv := newExportServer(t, &stubKeyExport{keyTypes: []mdl.ExportableKeyTypeV2Dto{
		{KeyRequestType: mdl.KEYREQUESTTYPE_SECRET, Algorithms: []mdl.KeyAlgorithm{mdl.KEYALGORITHM_AES}},
	}})

	rec := post(t, srv, exportableKeyTypesPath, tokenProfileScopedBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	assertJSONEqual(t, rec.Body.Bytes(), `[{"keyRequestType":"secret","algorithms":["AES"]}]`)
}

func TestExportableKeyTypesRejectsDeclarationsOutsideTheContract(t *testing.T) {
	srv := newExportServer(t, &stubKeyExport{keyTypes: []mdl.ExportableKeyTypeV2Dto{
		{KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR, Algorithms: []mdl.KeyAlgorithm{mdl.KEYALGORITHM_UNKNOWN}},
	}})

	assertShapeViolation(t, post(t, srv, exportableKeyTypesPath, tokenProfileScopedBody),
		"exportable key types must declare known algorithms other than Unknown")
}

func TestExportableKeyTypesRendersTheProvidersError(t *testing.T) {
	srv := newExportServer(t, &stubKeyExport{keyTypesErr: cryptography.ErrTokenNotFound})

	assertProblem(t, post(t, srv, exportableKeyTypesPath, tokenProfileScopedBody), http.StatusNotFound, "RESOURCE_NOT_FOUND")
}

func TestExportKeyAttributesServesTheRegisteredSchema(t *testing.T) {
	srv := newTestServer(t, &stubProvider{}, cryptography.WithExportKeyAttributes(&stubTransferAttributes{
		exportAttrs: []mdl.BaseAttributeDto{cryptography.KeyExportableDefinition()},
	}))

	rec := post(t, srv, exportKeyAttrsPath, keyScopedRequestBody)

	var got []mdl.BaseAttributeDto
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || len(got) != 1 {
		t.Fatalf("got %d %s, want 200 with one definition", rec.Code, rec.Body.String())
	}
}

func TestExportKeyAttributesRendersTheProvidersError(t *testing.T) {
	srv := newTestServer(t, &stubProvider{}, cryptography.WithExportKeyAttributes(&stubTransferAttributes{err: cryptography.ErrKeyNotFound}))

	assertProblem(t, post(t, srv, exportKeyAttrsPath, keyScopedRequestBody), http.StatusNotFound, "RESOURCE_NOT_FOUND")
}

func TestExportKeyAttributesRejectsEmptyKeyMeta(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	problem := assertProblem(t, post(t, srv, exportKeyAttrsPath, `{"tokenAttributes":[],"tokenProfileAttributes":[],"keyMeta":[]}`),
		http.StatusUnprocessableEntity, "VALIDATION_FAILED")
	assertDetail(t, problem, "keyMeta must not be empty")
}

// --- Without the providers and with unreadable bodies -------------------------------------

func TestExportRoutesRender404WithoutTheirProvider(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})
	for _, tc := range []struct{ path, body string }{
		{exportKeyPath, exportKeyBody(nil)},
		{exportableKeyTypesPath, tokenProfileScopedBody},
	} {
		t.Run(tc.path, func(t *testing.T) {
			problem := assertProblem(t, post(t, srv, tc.path, tc.body), http.StatusNotFound, "OPERATION_NOT_SUPPORTED")
			assertDetail(t, problem, keyExportNotSupportedDetail)
		})
	}
}

func TestExportKeyAttributesWithoutAProviderReturnEmptyArray(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	rec := post(t, srv, exportKeyAttrsPath, keyScopedRequestBody)

	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("got %d %s, want 200 []", rec.Code, rec.Body.String())
	}
}

func TestExportRoutesRejectAnUnreadableBody(t *testing.T) {
	srv := newExportServer(t, &stubKeyExport{})
	for _, path := range []string{exportKeyPath, exportableKeyTypesPath, exportKeyAttrsPath} {
		t.Run(path, func(t *testing.T) {
			assertProblem(t, post(t, srv, path, `{`), http.StatusBadRequest, "INVALID_JSON")
		})
	}
}
