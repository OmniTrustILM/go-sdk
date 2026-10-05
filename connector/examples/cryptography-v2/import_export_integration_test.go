package main_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const (
	pathImportKeyTypes = cryptoBase + "/keys/import/keyTypes"
	pathImportKey      = cryptoBase + "/keys/import"
	pathImportResult   = cryptoBase + "/keys/import/result"
	pathImportStatus   = cryptoBase + "/keys/import/status"
	pathImportCancel   = cryptoBase + "/keys/import/cancel"
	pathExportKeyTypes = cryptoBase + "/keys/export/keyTypes"
	pathExportKey      = cryptoBase + "/keys/export"

	transportPhrase = "transport phrase"
	exportPhrase    = "export phrase"
)

// protected is a key as Core sends it to an import: its PKCS#8 under a
// passphrase generated for the request.
type protected struct {
	pkcs8    []byte
	spki     string
	material mdl.EncryptedKeyMaterialV2Dto
}

func protect(t *testing.T, key any) protected {
	t.Helper()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	material, err := cryptography.ProtectKeyMaterial(pkcs8, transportPhrase)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	var public any
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		public = &k.PublicKey
	case *rsa.PrivateKey:
		public = &k.PublicKey
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	return protected{pkcs8: pkcs8, spki: base64.StdEncoding.EncodeToString(spki), material: material}
}

func p256Key(t *testing.T) protected {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return protect(t, key)
}

func importRequest(mode mdl.OperationExecutionMode, importID string, key protected, exportable bool) mdl.ImportKeyRequestV2Dto {
	return mdl.ImportKeyRequestV2Dto{
		TokenAttributes:        noAttrs,
		TokenProfileAttributes: noAttrs,
		KeyImportId:            importID,
		KeyReference:           "0f8c3a4e-8d8e-4c8a-9d6b-2a6b3c1d4e5f",
		ExecutionMode:          mode,
		KeyRequestType:         mdl.KEYREQUESTTYPE_KEY_PAIR,
		ImportKeyAttributes:    noAttrs,
		Material:               key.material,
		Passphrase:             transportPhrase,
		Exportable:             exportable,
	}
}

func exportRequest(reqType mdl.KeyRequestType, keyMeta []mdl.MetadataAttribute, keyReference *string) mdl.ExportKeyRequestV2Dto {
	return mdl.ExportKeyRequestV2Dto{
		TokenAttributes:        noAttrs,
		TokenProfileAttributes: noAttrs,
		KeyMeta:                keyMeta,
		KeyRequestType:         reqType,
		KeyReference:           keyReference,
		ExportKeyAttributes:    noAttrs,
		Passphrase:             exportPhrase,
	}
}

// importSync imports key and returns the key pair's result, failing the test
// on anything but 200.
func importSync(t *testing.T, h *itest.Harness, req mdl.ImportKeyRequestV2Dto) *mdl.KeyPairDataResponseV2Dto {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathImportKey, Body: req})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var out mdl.KeyCreationResponse
	resp.JSON(t, &out)
	if out.KeyPairDataResponseV2Dto == nil || out.KeyPairDataResponseV2Dto.PublicKeyData == nil {
		t.Fatalf("import answered %s, want a key pair", resp.Body)
	}
	return out.KeyPairDataResponseV2Dto
}

// exportedKey exports the key keyMeta names and opens the envelope it comes in.
func exportedKey(t *testing.T, h *itest.Harness, req mdl.ExportKeyRequestV2Dto) ([]byte, mdl.ExportKeyResponseV2Dto) {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathExportKey, Body: req})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var out mdl.ExportKeyResponseV2Dto
	resp.JSON(t, &out)
	pkcs8, err := cryptography.OpenKeyMaterial(out.Material, exportPhrase)
	if err != nil {
		t.Fatalf("open the exported envelope: %v", err)
	}
	return pkcs8, out
}

func TestCryptographyV2AdvertisesKeyImportAndExport(t *testing.T) {
	h := startCrypto(t, nil)

	var info shared.V2InfoResponse
	if status := h.GetJSON(t, http.MethodGet, "/v2/info", nil, &info); status != http.StatusOK {
		t.Fatalf("/v2/info = %d, want 200", status)
	}
	idx := slices.IndexFunc(info.Interfaces, func(i shared.InterfaceInfo) bool { return i.Code == "cryptography" })
	if idx < 0 || !slices.Contains(info.Interfaces[idx].Features, "keyImport") || !slices.Contains(info.Interfaces[idx].Features, "keyExport") {
		t.Fatalf("/v2/info interfaces = %+v, want cryptography with keyImport and keyExport", info.Interfaces)
	}
	scope := mdl.TokenProfileScopedRequestV2Dto{TokenAttributes: noAttrs, TokenProfileAttributes: noAttrs}
	for _, path := range []string{pathImportKeyTypes, pathExportKeyTypes} {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: path, Body: scope})
		if itest.AssertStatus(t, resp, http.StatusOK) && !bytes.Equal(bytes.TrimSpace(resp.Body), []byte(`[{"algorithms":["ECDSA"],"keyRequestType":"keyPair"}]`)) {
			t.Errorf("%s = %s, want ECDSA key pairs", path, resp.Body)
		}
	}
}

func TestCryptographyV2KeyImport(t *testing.T) {
	h := startCrypto(t, nil)

	t.Run("an imported key signs and exports as it came in", func(t *testing.T) {
		key := p256Key(t)
		pair := importSync(t, h, importRequest(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, uuid.NewString(), key, true))
		if pair.PublicKeyData.KeyData.PublicKeySpki != key.spki {
			t.Errorf("publicKeySpki = %s, want the imported key's", pair.PublicKeyData.KeyData.PublicKeySpki)
		}
		sign := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSign, Body: signRequest(
			mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, pair.PrivateKeyData.KeyMeta, []mdl.SignatureDataV2Dto{{Identifier: "d-1", Data: b64("data")}},
		)})
		itest.AssertStatus(t, sign, http.StatusOK)

		reference := "0f8c3a4e-8d8e-4c8a-9d6b-2a6b3c1d4e5f"
		pkcs8, out := exportedKey(t, h, exportRequest(mdl.KEYREQUESTTYPE_KEY_PAIR, pair.PrivateKeyData.KeyMeta, &reference))
		if !bytes.Equal(pkcs8, key.pkcs8) {
			t.Error("the exported key is not the imported one")
		}
		if out.KeyReference == nil || *out.KeyReference != reference {
			t.Errorf("keyReference = %v, want %s echoed", out.KeyReference, reference)
		}
		if out.KeyData.PublicKeyDataV2Dto == nil || out.KeyData.PublicKeyDataV2Dto.PublicKeySpki != key.spki {
			t.Errorf("keyData = %+v, want the imported public key", out.KeyData)
		}
	})

	t.Run("a replay with the key re-protected answers as the first import", func(t *testing.T) {
		key := p256Key(t)
		importID := uuid.NewString()
		first := importSync(t, h, importRequest(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, importID, key, false))

		again := key
		reprotected, err := cryptography.ProtectKeyMaterial(key.pkcs8, "another transport phrase")
		if err != nil {
			t.Fatalf("protect again: %v", err)
		}
		again.material = reprotected
		replay := importRequest(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, importID, again, false)
		replay.Passphrase = "another transport phrase"
		replayed := importSync(t, h, replay)
		if metaUUID(t, replayed.KeyPairMeta) != metaUUID(t, first.KeyPairMeta) {
			t.Error("the replay registered a second key")
		}

		for name, req := range map[string]mdl.ImportKeyRequestV2Dto{
			"other terms": importRequest(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, importID, key, true),
			"another key": importRequest(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, importID, p256Key(t), false),
		} {
			conflict := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathImportKey, Body: req})
			if conflict.Status != http.StatusConflict {
				t.Errorf("a reuse with %s answered %d, want 409", name, conflict.Status)
			}
			itest.AssertProblem(t, conflict, http.StatusConflict, "RESOURCE_ALREADY_EXISTS")
		}

		var result mdl.KeyCreationStatusResponse
		status := h.GetJSON(t, http.MethodPost, pathImportResult, mdl.ImportKeyResultRequestV2Dto{TokenAttributes: noAttrs, KeyImportId: importID}, &result)
		if status != http.StatusOK || result.KeyPairOperationStatusResponseV2Dto == nil ||
			result.KeyPairOperationStatusResponseV2Dto.Status != mdl.OPERATIONSTATUS_COMPLETED {
			t.Errorf("result = %d %+v, want the completed import", status, result)
		}
		unknown := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathImportResult,
			Body: mdl.ImportKeyResultRequestV2Dto{TokenAttributes: noAttrs, KeyImportId: uuid.NewString()}})
		itest.AssertProblem(t, unknown, http.StatusNotFound, "OPERATION_NOT_TRACKED")
	})

	t.Run("refusals", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
		wrongPhrase := importRequest(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, uuid.NewString(), p256Key(t), false)
		wrongPhrase.Passphrase = "another phrase"
		secret := importRequest(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, uuid.NewString(), p256Key(t), false)
		secret.KeyRequestType = mdl.KEYREQUESTTYPE_SECRET
		cases := map[string]struct {
			req  mdl.ImportKeyRequestV2Dto
			code string
		}{
			"a passphrase that does not open it": {wrongPhrase, "KEY_DECRYPTION_FAILED"},
			"an RSA key":                         {importRequest(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, uuid.NewString(), protect(t, rsaKey), false), "KEY_TYPE_NOT_IMPORTABLE"},
			"a secret key":                       {secret, "KEY_TYPE_NOT_IMPORTABLE"},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathImportKey, Body: tc.req})
				itest.AssertProblem(t, resp, http.StatusUnprocessableEntity, tc.code)
			})
		}
	})

	t.Run("an asynchronous import completes and is past cancelling", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathImportKey,
			Body: importRequest(mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS, uuid.NewString(), p256Key(t), false)})
		if !itest.AssertStatus(t, resp, http.StatusAccepted) {
			t.FailNow()
		}
		var accepted mdl.KeyCreationResponse
		resp.JSON(t, &accepted)
		handle := accepted.KeyPairDataResponseV2Dto.OperationMeta
		pollAsyncOperation(t, "import", func() (bool, bool) {
			var st mdl.KeyCreationStatusResponse
			if status := h.GetJSON(t, http.MethodPost, pathImportStatus, trackingRequest(handle), &st); status != http.StatusOK {
				t.Fatalf("import status = %d, want 200", status)
			}
			current := st.KeyPairOperationStatusResponseV2Dto.Status
			return current == mdl.OPERATIONSTATUS_IN_PROGRESS, current == mdl.OPERATIONSTATUS_COMPLETED
		})
		cancel := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathImportCancel, Body: trackingRequest(handle)})
		itest.AssertProblem(t, cancel, http.StatusUnprocessableEntity, "OPERATION_PAST_POINT_OF_NO_RETURN")
	})
}

func TestCryptographyV2KeyExport(t *testing.T) {
	h := startCrypto(t, nil)

	createPair := func(t *testing.T, exportable bool) *mdl.KeyPairDataResponseV2Dto {
		t.Helper()
		req := createKeyRequest(mdl.KEYREQUESTTYPE_KEY_PAIR, mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, uuid.NewString())
		req.CreateKeyAttributes = append(req.CreateKeyAttributes, cryptography.KeyExportableSelection(exportable))
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKeys, Body: req})
		if !itest.AssertStatus(t, resp, http.StatusOK) {
			t.FailNow()
		}
		var out mdl.KeyCreationResponse
		resp.JSON(t, &out)
		return out.KeyPairDataResponseV2Dto
	}

	t.Run("a key created exportable exports its own private key", func(t *testing.T) {
		pair := createPair(t, true)
		pkcs8, out := exportedKey(t, h, exportRequest(mdl.KEYREQUESTTYPE_KEY_PAIR, pair.PrivateKeyData.KeyMeta, nil))
		key, err := x509.ParsePKCS8PrivateKey(pkcs8)
		if err != nil {
			t.Fatalf("parse the exported key: %v", err)
		}
		spki, err := x509.MarshalPKIXPublicKey(&key.(*ecdsa.PrivateKey).PublicKey)
		if err != nil {
			t.Fatalf("marshal SPKI: %v", err)
		}
		if got := base64.StdEncoding.EncodeToString(spki); got != pair.PublicKeyData.KeyData.PublicKeySpki {
			t.Error("the exported private key does not belong to the created public key")
		}
		if out.KeyReference != nil {
			t.Errorf("keyReference = %s, want none for a request without one", *out.KeyReference)
		}
	})

	t.Run("a secret key cannot be created exportable", func(t *testing.T) {
		req := createKeyRequest(mdl.KEYREQUESTTYPE_SECRET, mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, uuid.NewString())
		req.CreateKeyAttributes = []mdl.RequestAttribute{cryptography.KeyExportableSelection(true)}
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKeys, Body: req})
		itest.AssertProblem(t, resp, http.StatusUnprocessableEntity, "EXPORTABLE_NOT_SUPPORTED")
	})

	t.Run("an RSA pair cannot be created exportable", func(t *testing.T) {
		req := rsaPairRequest()
		req.CreateKeyAttributes = append(req.CreateKeyAttributes, cryptography.KeyExportableSelection(true))
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKeys, Body: req})
		itest.AssertProblem(t, resp, http.StatusUnprocessableEntity, "EXPORTABLE_NOT_SUPPORTED")
	})

	t.Run("refusals", func(t *testing.T) {
		secretMeta, _ := createKeySync(t, h, mdl.KEYREQUESTTYPE_SECRET)
		rsaMeta := createRSAPair(t, h)
		notExportable := createPair(t, false)
		imported := importSync(t, h, importRequest(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, uuid.NewString(), p256Key(t), false))
		cases := map[string]struct {
			req  mdl.ExportKeyRequestV2Dto
			code string
		}{
			"a key created without the intent":  {exportRequest(mdl.KEYREQUESTTYPE_KEY_PAIR, notExportable.PrivateKeyData.KeyMeta, nil), "KEY_NOT_EXPORTABLE"},
			"a key imported without the intent": {exportRequest(mdl.KEYREQUESTTYPE_KEY_PAIR, imported.PrivateKeyData.KeyMeta, nil), "KEY_NOT_EXPORTABLE"},
			"a secret key":                      {exportRequest(mdl.KEYREQUESTTYPE_SECRET, secretMeta, nil), "KEY_TYPE_NOT_EXPORTABLE"},
			"a secret key named as a key pair":  {exportRequest(mdl.KEYREQUESTTYPE_KEY_PAIR, secretMeta, nil), "KEY_MATERIAL_MISMATCH"},
			"an RSA pair":                       {exportRequest(mdl.KEYREQUESTTYPE_KEY_PAIR, rsaMeta, nil), "KEY_TYPE_NOT_EXPORTABLE"},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathExportKey, Body: tc.req})
				itest.AssertProblem(t, resp, http.StatusUnprocessableEntity, tc.code)
			})
		}
	})
}
