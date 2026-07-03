package main_test

// Integration tests for the cryptography-v1 example (in-memory token + key
// store; placeholder crypto ops), driven over the public HTTP interface via
// the shared testcontainers harness. Requests/responses use the generated
// connector/model/cryptography/v1 types. Skips with no Docker or under -short.
//
// cryptography-v1 is a v1-family connector: info at GET /v1, health at
// GET /v1/health, v1 ErrorMessageDto envelope — so error paths use
// itest.AssertV1Error.
//
// The store seeds nothing and requires no external service: every test that
// needs a token/key creates it first and drives the lifecycle from there.
// Crypto operations return placeholder bytes (sign) or pass the input through
// unchanged (encrypt/decrypt) — the scope here is wiring/contract verification,
// so the assertions check response shape and identifier/pass-through echoing
// rather than real cryptography.

import (
	"net/http"
	"slices"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v1"
)

const (
	fgCryptography = string(mdl.FUNCTIONGROUPCODE_CRYPTOGRAPHY_PROVIDER) // "cryptographyProvider"
	cryptoKind     = "softHsm"                                           // default CRYPTOGRAPHY_KIND

	base       = "/v1/cryptographyProvider"
	pathTokens = base + "/tokens"

	// samplePayload is base64("hello"); the placeholder crypto ops treat their
	// input as opaque base64, so any valid base64 string works.
	samplePayload = "aGVsbG8="
)

func startCrypto(t *testing.T) *itest.Harness {
	t.Helper()
	return itest.Start(t, itest.Example{
		Path:       "connector/examples/cryptography-v1",
		HealthPath: "/v1/health",
	})
}

// hasEndpoint reports whether the function group advertises an endpoint with
// the given method and context.
func hasEndpoint(g mdl.InfoResponse, method, context string) bool {
	for _, e := range g.EndPoints {
		if e.Method == method && e.Context == context {
			return true
		}
	}
	return false
}

// createToken creates a token instance of the default kind and returns its
// server-generated uuid, failing the test on any error.
func createToken(t *testing.T, h *itest.Harness, name string) string {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathTokens, Body: mdl.TokenInstanceRequestDto{
		Name: name, Kind: cryptoKind, Attributes: []mdl.RequestAttribute{},
	}})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow() // avoid decoding an error envelope into the success DTO
	}
	var tok mdl.TokenInstanceDto
	resp.JSON(t, &tok)
	if tok.Uuid == "" {
		t.Fatalf("createToken(%q) returned no uuid: %s", name, resp.Body)
	}
	return tok.Uuid
}

// keyView captures the KeyDataResponseDto fields the tests assert on. The full
// generated KeyDataResponseDto cannot be unmarshalled here: its KeyData.Value is
// a non-discriminated oneOf (KeyDataValue) whose variants Eprki/Prki/Raw/Spki
// all carry a bare `value` field and collide, so the generated match-counting
// decoder rejects the server's {"value":"..."} body ("matches more than one
// schema in oneOf"). This is a documented model limitation (see
// tools/fixoneof knownUnpatchable), independent of the example — so response
// shape is verified via this focused view.
type keyView struct {
	Uuid        string  `json:"uuid"`
	Name        string  `json:"name"`
	Association *string `json:"association"`
	KeyData     struct {
		Type string `json:"type"`
	} `json:"keyData"`
}

// keyPairView is the createKeyPair response, both arms as keyView.
type keyPairView struct {
	PublicKeyData  keyView `json:"publicKeyData"`
	PrivateKeyData keyView `json:"privateKeyData"`
}

// createSecretKey creates a secret key on the token and returns the response.
func createSecretKey(t *testing.T, h *itest.Harness, tokenID string) keyView {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathTokens + "/" + tokenID + "/keys/secret", Body: mdl.CreateKeyRequestDto{
		TokenProfileAttributes: []mdl.RequestAttribute{},
		CreateKeyAttributes:    []mdl.RequestAttribute{},
	}})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var key keyView
	resp.JSON(t, &key)
	if key.Uuid == "" {
		t.Fatalf("createSecretKey returned no uuid: %s", resp.Body)
	}
	return key
}

// --- /v1 info + health -----------------------------------------------------

func TestCryptographyV1InfoAndHealth(t *testing.T) {
	h := startCrypto(t)

	h.AssertHealthy(t, "/v1/health")

	// Decode into the generated InfoResponse model (the exact /v1
	// listSupportedFunctions element shape) for free schema enforcement.
	var groups []mdl.InfoResponse
	if status := h.GetJSON(t, http.MethodGet, "/v1", nil, &groups); status != http.StatusOK {
		t.Fatalf("GET /v1 = %d, want 200", status)
	}

	idx := slices.IndexFunc(groups, func(g mdl.InfoResponse) bool { return string(g.FunctionGroupCode) == fgCryptography })
	if idx < 0 {
		t.Fatalf("/v1 missing %q function group: %+v", fgCryptography, groups)
	}
	crypto := groups[idx]
	if !slices.Contains(crypto.Kinds, cryptoKind) {
		t.Errorf("%s kinds = %v, want to contain %q", fgCryptography, crypto.Kinds, cryptoKind)
	}

	// Assert the full advertised endpoint set: the provider's own routes plus
	// the shared checkHealth + listSupportedFunctions wired via
	// WithExtraEndpoints. A handler that stopped advertising one (while its
	// route still worked) would be caught here. {uuid}/{keyUuid}/{kind} are
	// the literal template tokens the function group publishes.
	for _, want := range []struct{ method, context string }{
		{http.MethodGet, "/v1"},        // listSupportedFunctions (extra)
		{http.MethodGet, "/v1/health"}, // checkHealth (extra)
		// token instance management
		{http.MethodGet, pathTokens},
		{http.MethodPost, pathTokens},
		{http.MethodGet, pathTokens + "/{uuid}"},
		{http.MethodPost, pathTokens + "/{uuid}"},
		{http.MethodDelete, pathTokens + "/{uuid}"},
		{http.MethodGet, pathTokens + "/{uuid}/status"},
		{http.MethodPatch, pathTokens + "/{uuid}/activate"},
		{http.MethodPatch, pathTokens + "/{uuid}/deactivate"},
		// key management
		{http.MethodGet, pathTokens + "/{uuid}/keys"},
		{http.MethodGet, pathTokens + "/{uuid}/keys/{keyUuid}"},
		{http.MethodDelete, pathTokens + "/{uuid}/keys/{keyUuid}"},
		{http.MethodPost, pathTokens + "/{uuid}/keys/secret"},
		{http.MethodPost, pathTokens + "/{uuid}/keys/pair"},
		{http.MethodPost, pathTokens + "/{uuid}/keys/random"},
		// crypto operations
		{http.MethodPost, pathTokens + "/{uuid}/keys/{keyUuid}/sign"},
		{http.MethodPost, pathTokens + "/{uuid}/keys/{keyUuid}/verify"},
		{http.MethodPost, pathTokens + "/{uuid}/keys/{keyUuid}/encrypt"},
		{http.MethodPost, pathTokens + "/{uuid}/keys/{keyUuid}/decrypt"},
		// attribute endpoints (softHsm kind + per-instance)
		{http.MethodGet, base + "/{kind}/attributes"},
		{http.MethodPost, base + "/{kind}/attributes/validate"},
		{http.MethodGet, pathTokens + "/{uuid}/tokenProfile/attributes"},
		{http.MethodPost, pathTokens + "/{uuid}/tokenProfile/attributes/validate"},
		{http.MethodGet, pathTokens + "/{uuid}/activate/attributes"},
		{http.MethodPost, pathTokens + "/{uuid}/activate/attributes/validate"},
		{http.MethodGet, pathTokens + "/{uuid}/keys/secret/attributes"},
		{http.MethodPost, pathTokens + "/{uuid}/keys/secret/attributes/validate"},
		{http.MethodGet, pathTokens + "/{uuid}/keys/pair/attributes"},
		{http.MethodPost, pathTokens + "/{uuid}/keys/pair/attributes/validate"},
		{http.MethodGet, pathTokens + "/{uuid}/keys/random/attributes"},
		{http.MethodPost, pathTokens + "/{uuid}/keys/random/attributes/validate"},
	} {
		if !hasEndpoint(crypto, want.method, want.context) {
			t.Errorf("%s endPoints missing %s %s: %+v", fgCryptography, want.method, want.context, crypto.EndPoints)
		}
	}

	h.AssertLogsConform(t)
}

// --- token instance lifecycle ----------------------------------------------

func TestCryptographyV1TokenLifecycle(t *testing.T) {
	h := startCrypto(t)

	// List starts empty (store seeds nothing) but is always a JSON array.
	list := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathTokens})
	itest.AssertStatus(t, list, http.StatusOK)
	var tokens []mdl.TokenInstanceDto
	list.JSON(t, &tokens)
	if tokens == nil {
		t.Errorf("listTokenInstances returned null, want a JSON array")
	}

	id := createToken(t, h, "tok-1")

	// The created token now appears in the list.
	list = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathTokens})
	itest.AssertStatus(t, list, http.StatusOK)
	list.JSON(t, &tokens)
	if !slices.ContainsFunc(tokens, func(x mdl.TokenInstanceDto) bool { return x.Uuid == id }) {
		t.Errorf("created token %s not in list: %+v", id, tokens)
	}

	// Get by uuid.
	itest.AssertStatus(t, h.Do(t, itest.Request{Method: http.MethodGet, Path: pathTokens + "/" + id}), http.StatusOK)

	// assertTokenStatus checks GET /tokens/{uuid}/status reports the want state.
	assertTokenStatus := func(want mdl.TokenInstanceStatus) {
		t.Helper()
		resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathTokens + "/" + id + "/status"})
		if !itest.AssertStatus(t, resp, http.StatusOK) {
			return
		}
		var st mdl.TokenInstanceStatusDto
		resp.JSON(t, &st)
		if st.Status != want {
			t.Errorf("token status = %q, want %q", st.Status, want)
		}
	}

	// New tokens start Deactivated.
	assertTokenStatus(mdl.TOKENINSTANCESTATUS_DEACTIVATED)

	// Activate -> 204, then status Activated. The activate body is a
	// []RequestAttribute (activation attributes); empty is valid here.
	act := h.Do(t, itest.Request{Method: http.MethodPatch, Path: pathTokens + "/" + id + "/activate", Body: []mdl.RequestAttribute{}})
	itest.AssertStatus(t, act, http.StatusNoContent)
	assertTokenStatus(mdl.TOKENINSTANCESTATUS_ACTIVATED)

	// Deactivate -> 204, then status Deactivated.
	deact := h.Do(t, itest.Request{Method: http.MethodPatch, Path: pathTokens + "/" + id + "/deactivate"})
	itest.AssertStatus(t, deact, http.StatusNoContent)
	assertTokenStatus(mdl.TOKENINSTANCESTATUS_DEACTIVATED)

	// Update, then read the token back to confirm the rename actually applied
	// (a handler that returned 200 without storing the change would be caught).
	upd := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathTokens + "/" + id, Body: mdl.TokenInstanceRequestDto{
		Name: "tok-1-renamed", Kind: cryptoKind, Attributes: []mdl.RequestAttribute{},
	}})
	itest.AssertStatus(t, upd, http.StatusOK)
	reget := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathTokens + "/" + id})
	if itest.AssertStatus(t, reget, http.StatusOK) {
		var updated mdl.TokenInstanceDto
		reget.JSON(t, &updated)
		if updated.Name != "tok-1-renamed" {
			t.Errorf("after update, token name = %q, want %q", updated.Name, "tok-1-renamed")
		}
	}

	// Remove -> 204, then get -> 404.
	del := h.Do(t, itest.Request{Method: http.MethodDelete, Path: pathTokens + "/" + id})
	itest.AssertStatus(t, del, http.StatusNoContent)

	gone := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathTokens + "/" + id})
	itest.AssertV1Error(t, gone, http.StatusNotFound)
}

// --- key lifecycle ---------------------------------------------------------

func TestCryptographyV1KeyLifecycle(t *testing.T) {
	h := startCrypto(t)
	id := createToken(t, h, "keys-tok")

	// Secret key -> 200 with a Secret key type.
	secKey := createSecretKey(t, h, id)
	if secKey.KeyData.Type != string(mdl.KEYTYPE_SECRET) {
		t.Errorf("secret key type = %q, want %q", secKey.KeyData.Type, mdl.KEYTYPE_SECRET)
	}

	// Key pair -> 200 with both public + private keys populated.
	pair := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathTokens + "/" + id + "/keys/pair", Body: mdl.CreateKeyRequestDto{
		TokenProfileAttributes: []mdl.RequestAttribute{},
		CreateKeyAttributes:    []mdl.RequestAttribute{},
	}})
	if !itest.AssertStatus(t, pair, http.StatusOK) {
		t.FailNow()
	}
	var kp keyPairView
	pair.JSON(t, &kp)
	if kp.PublicKeyData.Uuid == "" || kp.PrivateKeyData.Uuid == "" {
		t.Fatalf("createKeyPair missing key uuids: %s", pair.Body)
	}
	// The two arms carry distinct key types...
	if kp.PublicKeyData.KeyData.Type != string(mdl.KEYTYPE_PUBLIC) {
		t.Errorf("public arm type = %q, want %q", kp.PublicKeyData.KeyData.Type, mdl.KEYTYPE_PUBLIC)
	}
	if kp.PrivateKeyData.KeyData.Type != string(mdl.KEYTYPE_PRIVATE) {
		t.Errorf("private arm type = %q, want %q", kp.PrivateKeyData.KeyData.Type, mdl.KEYTYPE_PRIVATE)
	}
	// ...and a shared, non-empty association UUID links them.
	if kp.PublicKeyData.Association == nil || kp.PrivateKeyData.Association == nil {
		t.Fatalf("key pair missing association: %s", pair.Body)
	}
	if *kp.PublicKeyData.Association == "" || *kp.PublicKeyData.Association != *kp.PrivateKeyData.Association {
		t.Errorf("key pair association mismatch: public=%q private=%q", *kp.PublicKeyData.Association, *kp.PrivateKeyData.Association)
	}

	// Random data -> 200, non-empty base64 payload.
	rnd := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathTokens + "/" + id + "/keys/random", Body: mdl.RandomDataRequestDto{Length: 16}})
	if !itest.AssertStatus(t, rnd, http.StatusOK) {
		t.FailNow()
	}
	var rd mdl.RandomDataResponseDto
	rnd.JSON(t, &rd)
	if rd.Data == "" {
		t.Errorf("randomData returned empty data")
	}

	// List keys: the secret key and both pair keys are present.
	lk := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathTokens + "/" + id + "/keys"})
	itest.AssertStatus(t, lk, http.StatusOK)
	var keys []keyView
	lk.JSON(t, &keys)
	if keys == nil {
		t.Errorf("listKeys returned null, want a JSON array")
	}
	for _, want := range []string{secKey.Uuid, kp.PublicKeyData.Uuid, kp.PrivateKeyData.Uuid} {
		if !slices.ContainsFunc(keys, func(k keyView) bool { return k.Uuid == want }) {
			t.Errorf("listKeys missing key %s: %+v", want, keys)
		}
	}

	// Get the secret key by uuid.
	itest.AssertStatus(t, h.Do(t, itest.Request{Method: http.MethodGet, Path: pathTokens + "/" + id + "/keys/" + secKey.Uuid}), http.StatusOK)

	// Destroy -> 204, then get -> 404.
	dk := h.Do(t, itest.Request{Method: http.MethodDelete, Path: pathTokens + "/" + id + "/keys/" + secKey.Uuid})
	itest.AssertStatus(t, dk, http.StatusNoContent)
	goneKey := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathTokens + "/" + id + "/keys/" + secKey.Uuid})
	itest.AssertV1Error(t, goneKey, http.StatusNotFound)
}

// --- placeholder crypto operations -----------------------------------------

func TestCryptographyV1CryptoOps(t *testing.T) {
	h := startCrypto(t)
	id := createToken(t, h, "crypto-tok")
	key := createSecretKey(t, h, id)
	keyBase := pathTokens + "/" + id + "/keys/" + key.Uuid
	ident := "item-1"

	// Sign: one signature per input item, echoing the identifier, with
	// non-empty (placeholder) signature data.
	sign := h.Do(t, itest.Request{Method: http.MethodPost, Path: keyBase + "/sign", Body: mdl.SignDataRequestDto{
		SignatureAttributes: []mdl.RequestAttribute{},
		Data:                []mdl.SignatureRequestData{{Data: samplePayload, Identifier: &ident}},
	}})
	if !itest.AssertStatus(t, sign, http.StatusOK) {
		t.FailNow()
	}
	var signResp mdl.SignDataResponseDto
	sign.JSON(t, &signResp)
	if len(signResp.Signatures) != 1 {
		t.Fatalf("sign returned %d signatures, want 1: %s", len(signResp.Signatures), sign.Body)
	}
	if got := signResp.Signatures[0]; got.Identifier == nil || *got.Identifier != ident {
		t.Errorf("sign did not echo identifier %q: %+v", ident, got)
	} else if got.Data == "" {
		t.Errorf("sign returned empty signature data")
	}

	// Verify: placeholder always reports true, one result per input signature.
	verify := h.Do(t, itest.Request{Method: http.MethodPost, Path: keyBase + "/verify", Body: mdl.VerifyDataRequestDto{
		SignatureAttributes: []mdl.RequestAttribute{},
		Data:                []mdl.SignatureRequestData{{Data: samplePayload, Identifier: &ident}},
		Signatures:          []mdl.SignatureRequestData{{Data: signResp.Signatures[0].Data, Identifier: &ident}},
	}})
	if !itest.AssertStatus(t, verify, http.StatusOK) {
		t.FailNow()
	}
	var verifyResp mdl.VerifyDataResponseDto
	verify.JSON(t, &verifyResp)
	if len(verifyResp.Verifications) != 1 || !verifyResp.Verifications[0].Result {
		t.Errorf("verify result unexpected: %+v", verifyResp.Verifications)
	}

	// Encrypt then decrypt: placeholder pass-through (output data == input).
	enc := h.Do(t, itest.Request{Method: http.MethodPost, Path: keyBase + "/encrypt", Body: mdl.CipherDataRequestDto{
		CipherAttributes: []mdl.RequestAttribute{},
		CipherData:       []mdl.CipherRequestData{{Data: samplePayload, Identifier: &ident}},
	}})
	if !itest.AssertStatus(t, enc, http.StatusOK) {
		t.FailNow()
	}
	var encResp mdl.EncryptDataResponseDto
	enc.JSON(t, &encResp)
	if len(encResp.EncryptedData) != 1 || encResp.EncryptedData[0].Data != samplePayload {
		t.Fatalf("encrypt pass-through mismatch: %+v", encResp.EncryptedData)
	}

	dec := h.Do(t, itest.Request{Method: http.MethodPost, Path: keyBase + "/decrypt", Body: mdl.CipherDataRequestDto{
		CipherAttributes: []mdl.RequestAttribute{},
		CipherData:       []mdl.CipherRequestData{{Data: encResp.EncryptedData[0].Data, Identifier: &ident}},
	}})
	if !itest.AssertStatus(t, dec, http.StatusOK) {
		t.FailNow()
	}
	var decResp mdl.DecryptDataResponseDto
	dec.JSON(t, &decResp)
	if len(decResp.DecryptedData) != 1 || decResp.DecryptedData[0].Data != samplePayload {
		t.Errorf("decrypt pass-through mismatch: %+v", decResp.DecryptedData)
	}
}

// --- attribute endpoints (softHsm kind) ------------------------------------

func TestCryptographyV1Attributes(t *testing.T) {
	h := startCrypto(t)

	// Per-kind attribute schema for softHsm -> 200, a JSON array (never null).
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: base + "/" + cryptoKind + "/attributes"})
	itest.AssertStatus(t, resp, http.StatusOK)
	var attrs []any
	resp.JSON(t, &attrs)
	if attrs == nil {
		t.Errorf("%s/attributes returned null, want a JSON array", cryptoKind)
	}

	// Validate attributes (no provider wired -> 200 for the generic-kind route).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: base + "/" + cryptoKind + "/attributes/validate", Body: []mdl.RequestAttribute{}})
	itest.AssertStatus(t, resp, http.StatusOK)
}

// --- error paths -----------------------------------------------------------

func TestCryptographyV1Errors(t *testing.T) {
	h := startCrypto(t)

	// Empty name ("name":"", present but blank) hits the store's guard ->
	// 400 with the v1 {message} envelope.
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathTokens, Body: mdl.TokenInstanceRequestDto{
		Name: "", Kind: cryptoKind, Attributes: []mdl.RequestAttribute{},
	}})
	itest.AssertV1Error(t, resp, http.StatusBadRequest)

	// Absent required "name" key takes the decoder path: the generated
	// TokenInstanceRequestDto rejects the missing required field -> 422 with
	// the v1 []string validation body (not the {message} envelope).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathTokens, Body: map[string]any{"kind": cryptoKind, "attributes": []any{}}})
	if itest.AssertStatus(t, resp, http.StatusUnprocessableEntity) {
		// Only decode on the expected status: a wrong-status body is often a
		// different shape (e.g. the {message} envelope), and decoding it into
		// []string would t.Fatalf and mask the original status mismatch.
		var vErrs []string
		resp.JSON(t, &vErrs)
		if len(vErrs) == 0 {
			t.Errorf("absent-name 422 body = %s, want a non-empty []string", resp.Body)
		}
	}

	unknown := "00000000-0000-0000-0000-000000000000"

	// Unknown token -> 404.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathTokens + "/" + unknown})
	itest.AssertV1Error(t, resp, http.StatusNotFound)

	// Unknown key on a real token -> 404.
	id := createToken(t, h, "err-tok")
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathTokens + "/" + id + "/keys/" + unknown})
	itest.AssertV1Error(t, resp, http.StatusNotFound)
}
