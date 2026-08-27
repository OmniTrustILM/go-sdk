package main_test

// Integration tests for the cryptography-v2 example, driven over the public
// HTTP interface via the shared testcontainers harness. Skips with no Docker
// or under -short.
//
// Every operation is a POST scoped entirely by its request body, except
// GET .../tokens/attributes. A key's or operation's durable handle is the
// uuid of a single MetadataAttribute the store returns, echoed back unchanged
// (see store.go).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const cryptoBase = "/v2/cryptographyProvider"

// Route paths.
const (
	pathTokenAttrs        = cryptoBase + "/tokens/attributes"
	pathTokenProfileAttrs = cryptoBase + "/tokens/tokenProfile/attributes"
	pathCreateKeyAttrs    = cryptoBase + "/keys/create/attributes"
	pathEncryptAttrs      = cryptoBase + "/operations/encrypt/attributes"
	pathDecryptAttrs      = cryptoBase + "/operations/decrypt/attributes"
	pathSignAttrs         = cryptoBase + "/operations/sign/attributes"
	pathVerifyAttrs       = cryptoBase + "/operations/verify/attributes"
	pathRandomAttrs       = cryptoBase + "/operations/random/attributes"

	pathKeys       = cryptoBase + "/keys"
	pathDestroyKey = cryptoBase + "/keys/destroy"

	pathSign    = cryptoBase + "/operations/sign"
	pathEncrypt = cryptoBase + "/operations/encrypt"
	pathDecrypt = cryptoBase + "/operations/decrypt"
	pathVerify  = cryptoBase + "/operations/verify"
	pathRandom  = cryptoBase + "/operations/random"

	pathCreateKeyStatus  = cryptoBase + "/keys/create/status"
	pathCreateKeyCancel  = cryptoBase + "/keys/create/cancel"
	pathDestroyKeyStatus = cryptoBase + "/keys/destroy/status"
	pathDestroyKeyCancel = cryptoBase + "/keys/destroy/cancel"
	pathSignStatus       = cryptoBase + "/operations/sign/status"
	pathSignCancel       = cryptoBase + "/operations/sign/cancel"
)

// pollDeadline generously exceeds every asyncDelay these tests configure, so
// polling to completion is not flaky on a loaded CI host. pollInterval keeps
// the loop from hammering the container.
const (
	pollDeadline = 5 * time.Second
	pollInterval = 50 * time.Millisecond
)

var (
	noAttrs = []mdl.RequestAttribute{}
	// oneUsage is not empty: the contract marks keyUsages minItems: 1, and
	// the SDK rejects a violation with 422 before the store is called.
	oneUsage = []mdl.KeyUsage{mdl.KEYUSAGE_SIGN}
)

func startCrypto(t *testing.T, extraEnv map[string]string) *itest.Harness {
	t.Helper()
	itest.RequireDocker(t)
	return itest.Start(t, itest.Example{
		Path: "connector/examples/cryptography-v2",
		Env:  extraEnv,
	})
}

// --- request builders -------------------------------------------------------

func createKeyRequest(reqType mdl.KeyRequestType, mode mdl.OperationExecutionMode, creationID string) mdl.CreateKeyRequestV2Dto {
	return mdl.CreateKeyRequestV2Dto{
		TokenAttributes:        noAttrs,
		TokenProfileAttributes: noAttrs,
		KeyUsages:              oneUsage,
		KeyRequestType:         reqType,
		ExecutionMode:          mode,
		KeyCreationId:          creationID,
		CreateKeyAttributes:    noAttrs,
	}
}

func destroyKeyRequest(mode mdl.OperationExecutionMode, keyMeta []mdl.MetadataAttribute) mdl.DestroyKeyRequestV2Dto {
	return mdl.DestroyKeyRequestV2Dto{
		TokenAttributes:        noAttrs,
		TokenProfileAttributes: noAttrs,
		KeyUsages:              oneUsage,
		KeyMeta:                keyMeta,
		ExecutionMode:          mode,
	}
}

func signRequest(mode mdl.OperationExecutionMode, keyMeta []mdl.MetadataAttribute, data []mdl.SignatureDataV2Dto) mdl.SignDataRequestV2Dto {
	return mdl.SignDataRequestV2Dto{
		TokenAttributes:        noAttrs,
		TokenProfileAttributes: noAttrs,
		KeyUsages:              oneUsage,
		KeyMeta:                keyMeta,
		ExecutionMode:          mode,
		SignatureAttributes:    noAttrs,
		Data:                   data,
	}
}

func verifyRequest(keyMeta []mdl.MetadataAttribute, data, sigs []mdl.SignatureDataV2Dto) mdl.VerifyDataRequestV2Dto {
	return mdl.VerifyDataRequestV2Dto{
		TokenAttributes:        noAttrs,
		TokenProfileAttributes: noAttrs,
		KeyUsages:              oneUsage,
		KeyMeta:                keyMeta,
		SignatureAttributes:    noAttrs,
		Data:                   data,
		Signatures:             sigs,
	}
}

func cipherRequest(keyMeta []mdl.MetadataAttribute, data []mdl.CipherDataV2Dto) mdl.CipherDataRequestV2Dto {
	return mdl.CipherDataRequestV2Dto{
		TokenAttributes:        noAttrs,
		TokenProfileAttributes: noAttrs,
		KeyUsages:              oneUsage,
		KeyMeta:                keyMeta,
		CipherAttributes:       noAttrs,
		CipherData:             data,
	}
}

func randomRequest(length int32) mdl.RandomDataRequestV2Dto {
	return mdl.RandomDataRequestV2Dto{
		TokenAttributes:        noAttrs,
		TokenProfileAttributes: noAttrs,
		KeyUsages:              oneUsage,
		Length:                 length,
		OperationAttributes:    noAttrs,
	}
}

func trackingRequest(meta []mdl.MetadataAttribute) mdl.OperationTrackingRequestV2Dto {
	return mdl.OperationTrackingRequestV2Dto{OperationMeta: meta}
}

// metaAttribute builds a well-formed MetadataAttribute carrying uuid. The
// contract marks keyMeta and operationMeta minItems: 1, so even an endpoint
// that ignores the handle needs a real one.
func metaAttribute(uuid, name, label string) []mdl.MetadataAttribute {
	return []mdl.MetadataAttribute{{MetadataAttributeV2: &mdl.MetadataAttributeV2{
		Uuid:        uuid,
		Name:        name,
		Version:     2,
		Type:        mdl.ATTRIBUTETYPE_META,
		ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
		Properties:  mdl.MetadataAttributeProperties{Label: label, Visible: true},
	}}}
}

// unknownOperationMeta builds a well-formed MetadataAttribute carrying a
// handle the store never issued, for the "unknown handle" negative cases.
func unknownOperationMeta() []mdl.MetadataAttribute {
	return metaAttribute(uuid.NewString(), "neverIssued", "never issued")
}

// --- response helpers --------------------------------------------------------

// metaUUID extracts the handle carried by a MetadataAttribute slice, failing
// the test if none of the elements carries a populated variant with a
// non-empty uuid.
func metaUUID(t *testing.T, meta []mdl.MetadataAttribute) string {
	t.Helper()
	for _, m := range meta {
		if m.MetadataAttributeV2 != nil && m.MetadataAttributeV2.Uuid != "" {
			return m.MetadataAttributeV2.Uuid
		}
		if m.MetadataAttributeV3 != nil && m.MetadataAttributeV3.Uuid != "" {
			return m.MetadataAttributeV3.Uuid
		}
	}
	t.Fatalf("no MetadataAttribute with a populated uuid: %+v", meta)
	return ""
}

// keyMetaOf extracts the key(-pair) handle from a createKey response,
// selecting the oneOf variant by reqType.
func keyMetaOf(t *testing.T, reqType mdl.KeyRequestType, out *mdl.KeyCreationResponse) []mdl.MetadataAttribute {
	t.Helper()
	if reqType == mdl.KEYREQUESTTYPE_KEY_PAIR {
		if out.KeyPairDataResponseV2Dto == nil {
			t.Fatalf("createKey(keyPair) response carries no KeyPairDataResponseV2Dto variant: %+v", out)
		}
		return out.KeyPairDataResponseV2Dto.KeyPairMeta
	}
	if out.SecretKeyDataResponseV2Dto == nil {
		t.Fatalf("createKey(secret) response carries no SecretKeyDataResponseV2Dto variant: %+v", out)
	}
	return out.SecretKeyDataResponseV2Dto.KeyMeta
}

// acceptedCreateMeta extracts the tracking handle from an accepted
// asynchronous createKey response, selecting the variant by reqType.
func acceptedCreateMeta(t *testing.T, reqType mdl.KeyRequestType, out *mdl.KeyCreationResponse) []mdl.MetadataAttribute {
	t.Helper()
	var meta []mdl.MetadataAttribute
	if reqType == mdl.KEYREQUESTTYPE_KEY_PAIR {
		if out.KeyPairDataResponseV2Dto == nil {
			t.Fatalf("accepted createKey(keyPair) response carries no KeyPairDataResponseV2Dto variant: %+v", out)
		}
		meta = out.KeyPairDataResponseV2Dto.OperationMeta
	} else {
		if out.SecretKeyDataResponseV2Dto == nil {
			t.Fatalf("accepted createKey(secret) response carries no SecretKeyDataResponseV2Dto variant: %+v", out)
		}
		meta = out.SecretKeyDataResponseV2Dto.OperationMeta
	}
	if len(meta) == 0 {
		t.Fatalf("accepted createKey(%s) response carries no operationMeta: %+v", reqType, out)
	}
	return meta
}

// createKeyStatusOf returns the status of the createKey status variant
// matching reqType, asserting a completed variant carries its full key
// material.
func createKeyStatusOf(t *testing.T, reqType mdl.KeyRequestType, st *mdl.KeyCreationStatusResponse) mdl.OperationStatus {
	t.Helper()
	if reqType == mdl.KEYREQUESTTYPE_KEY_PAIR {
		v := st.KeyPairOperationStatusResponseV2Dto
		if v == nil {
			t.Fatalf("createKeyStatus response carries no KeyPairOperationStatusResponseV2Dto variant: %+v", st)
		}
		if v.Status == mdl.OPERATIONSTATUS_COMPLETED {
			res := v.Result
			if res == nil || res.PublicKeyData == nil || res.PrivateKeyData == nil || len(res.KeyPairMeta) == 0 {
				t.Fatalf("completed keyPair createKey status carries no key-pair result: %+v", v)
			}
			assertPublicKeySpki(t, res.PublicKeyData.KeyData)
			if res.PrivateKeyData.KeyData.Type != "Private" {
				t.Errorf("completed keyPair status private keyData.type = %q, want %q", res.PrivateKeyData.KeyData.Type, "Private")
			}
		}
		return v.Status
	}
	v := st.SecretKeyOperationStatusResponseV2Dto
	if v == nil {
		t.Fatalf("createKeyStatus response carries no SecretKeyOperationStatusResponseV2Dto variant: %+v", st)
	}
	if v.Status == mdl.OPERATIONSTATUS_COMPLETED {
		res := v.Result
		if res == nil || res.KeyData == nil || len(res.KeyMeta) == 0 {
			t.Fatalf("completed secret createKey status carries no result: %+v", v)
		}
	}
	return v.Status
}

// assertPublicKeySpki decodes publicKeySpki as a DER SubjectPublicKeyInfo and
// checks it against the declared algorithm and length.
func assertPublicKeySpki(t *testing.T, kd mdl.PublicKeyDataV2Dto) {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(kd.PublicKeySpki)
	if err != nil {
		t.Fatalf("publicKeySpki is not standard base64: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("publicKeySpki is not a DER SubjectPublicKeyInfo: %v", err)
	}
	if kd.Algorithm != mdl.KEYALGORITHM_ECDSA {
		t.Fatalf("public keyData.algorithm = %q, want %q", kd.Algorithm, mdl.KEYALGORITHM_ECDSA)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("publicKeySpki decodes to %T, want *ecdsa.PublicKey for algorithm %q", pub, kd.Algorithm)
	}
	if ec.Curve != elliptic.P256() {
		t.Errorf("publicKeySpki curve = %v, want P-256", ec.Curve.Params().Name)
	}
	if got := int32(ec.Curve.Params().BitSize); got != kd.Length {
		t.Errorf("publicKeySpki curve size = %d bits, but keyData.length = %d", got, kd.Length)
	}
}

// createKeySync creates a key of reqType synchronously and returns its
// handle plus the full decoded response, failing the test on any error.
func createKeySync(t *testing.T, h *itest.Harness, reqType mdl.KeyRequestType) ([]mdl.MetadataAttribute, mdl.KeyCreationResponse) {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKeys, Body: createKeyRequest(
		reqType, mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, uuid.NewString(),
	)})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var out mdl.KeyCreationResponse
	resp.JSON(t, &out)
	meta := keyMetaOf(t, reqType, &out)
	if len(meta) == 0 {
		t.Fatalf("createKey(%s) returned no key handle: %+v", reqType, out)
	}
	return meta, out
}

// --- /v2/info and /v2/health ------------------------------------------------

func TestCryptographyV2InfoAndHealth(t *testing.T) {
	h := startCrypto(t, nil)

	h.AssertHealthy(t, "/v2/health")
	h.AssertHealthy(t, "/v2/health/liveness")
	h.AssertHealthy(t, "/v2/health/readiness")

	var info shared.V2InfoResponse
	if status := h.GetJSON(t, http.MethodGet, "/v2/info", nil, &info); status != http.StatusOK {
		t.Fatalf("/v2/info = %d, want 200", status)
	}
	idx := slices.IndexFunc(info.Interfaces, func(i shared.InterfaceInfo) bool {
		return i.Code == "cryptography" && i.Version == "v2"
	})
	if idx < 0 {
		t.Fatalf("/v2/info missing {cryptography, v2} interface: %+v", info.Interfaces)
	}
	if !slices.Contains(info.Interfaces[idx].Features, "asynchronous") {
		t.Errorf("cryptography interface features = %v, want to contain %q", info.Interfaces[idx].Features, "asynchronous")
	}

	h.AssertLogsConform(t)
}

// --- synchronous key lifecycle, both arms -----------------------------------

func TestCryptographyV2KeyLifecycle(t *testing.T) {
	h := startCrypto(t, nil)

	for _, reqType := range []mdl.KeyRequestType{mdl.KEYREQUESTTYPE_SECRET, mdl.KEYREQUESTTYPE_KEY_PAIR} {
		t.Run(string(reqType), func(t *testing.T) {
			meta, out := createKeySync(t, h, reqType)

			switch reqType {
			case mdl.KEYREQUESTTYPE_SECRET:
				sk := out.SecretKeyDataResponseV2Dto
				if sk.KeyData == nil {
					t.Fatalf("secret createKey response missing keyData: %+v", sk)
				}
				// The spec pins this role tag and the SDK's model enforces it.
				if sk.KeyData.Type != "Secret" {
					t.Errorf("secret keyData.type = %q, want %q", sk.KeyData.Type, "Secret")
				}
			case mdl.KEYREQUESTTYPE_KEY_PAIR:
				kp := out.KeyPairDataResponseV2Dto
				if kp.PublicKeyData == nil || kp.PrivateKeyData == nil {
					t.Fatalf("keyPair createKey response missing public/private key data: %+v", kp)
				}
				assertPublicKeySpki(t, kp.PublicKeyData.KeyData)
				if kp.PublicKeyData.KeyData.Type != "Public" {
					t.Errorf("public keyData.type = %q, want %q", kp.PublicKeyData.KeyData.Type, "Public")
				}
				if kp.PrivateKeyData.KeyData.Type != "Private" {
					t.Errorf("private keyData.type = %q, want %q", kp.PrivateKeyData.KeyData.Type, "Private")
				}
			}

			// Sign to prove the returned handle is live.
			signResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSign, Body: signRequest(
				mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, meta,
				[]mdl.SignatureDataV2Dto{{Data: "sign-me", Identifier: "item-1"}},
			)})
			if !itest.AssertStatus(t, signResp, http.StatusOK) {
				t.FailNow()
			}
			var signOut mdl.SignDataResponseV2Dto
			signResp.JSON(t, &signOut)
			if len(signOut.Signatures) != 1 || signOut.Signatures[0].Data == "" {
				t.Fatalf("signing with the new key handle returned no signature: %+v", signOut)
			}

			// Destroy -> 200 synchronously, with no operationMeta.
			destroyResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathDestroyKey, Body: destroyKeyRequest(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, meta)})
			if !itest.AssertStatus(t, destroyResp, http.StatusOK) {
				t.FailNow()
			}
			var destroyOut mdl.KeyOperationResponseV2Dto
			destroyResp.JSON(t, &destroyOut)
			if len(destroyOut.OperationMeta) != 0 {
				t.Errorf("synchronous destroy response carries operationMeta: %+v", destroyOut)
			}

			after := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSign, Body: signRequest(
				mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, meta,
				[]mdl.SignatureDataV2Dto{{Data: "sign-me", Identifier: "item-1"}},
			)})
			itest.AssertProblem(t, after, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		})
	}
}

// --- synchronous operation semantics -----------------------------------------

func TestCryptographyV2CryptoOperations(t *testing.T) {
	h := startCrypto(t, nil)
	meta, _ := createKeySync(t, h, mdl.KEYREQUESTTYPE_SECRET)

	// Sign: correlate by identifier, since slice order carries no guarantee.
	idents := []string{"item-a", "item-b", "item-c"}
	signData := make([]mdl.SignatureDataV2Dto, len(idents))
	for i, id := range idents {
		signData[i] = mdl.SignatureDataV2Dto{Data: "payload-" + id, Identifier: id}
	}
	signResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSign, Body: signRequest(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, meta, signData)})
	if !itest.AssertStatus(t, signResp, http.StatusOK) {
		t.FailNow()
	}
	var signOut mdl.SignDataResponseV2Dto
	signResp.JSON(t, &signOut)
	sigByID := make(map[string]string, len(signOut.Signatures))
	for _, s := range signOut.Signatures {
		if _, dup := sigByID[s.Identifier]; dup {
			t.Errorf("identifier %q appears more than once in the sign response", s.Identifier)
		}
		sigByID[s.Identifier] = s.Data
	}
	for _, id := range idents {
		sig, ok := sigByID[id]
		if !ok {
			t.Errorf("sign response missing identifier %q", id)
		} else if sig == "" {
			t.Errorf("sign response for %q carries empty signature data", id)
		}
	}

	// Verify: one result per input, correlated by identifier.
	verifySigs := make([]mdl.SignatureDataV2Dto, len(idents))
	for i, id := range idents {
		verifySigs[i] = mdl.SignatureDataV2Dto{Data: sigByID[id], Identifier: id}
	}
	verifyResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathVerify, Body: verifyRequest(meta, signData, verifySigs)})
	if !itest.AssertStatus(t, verifyResp, http.StatusOK) {
		t.FailNow()
	}
	var verifyOut mdl.VerifyDataResponseV2Dto
	verifyResp.JSON(t, &verifyOut)
	if len(verifyOut.Verifications) != len(idents) {
		t.Fatalf("verify returned %d results, want %d (one per input): %+v", len(verifyOut.Verifications), len(idents), verifyOut.Verifications)
	}
	resultByID := make(map[string]bool, len(verifyOut.Verifications))
	for _, v := range verifyOut.Verifications {
		if _, dup := resultByID[v.Identifier]; dup {
			t.Errorf("identifier %q appears more than once in the verify response", v.Identifier)
		}
		resultByID[v.Identifier] = v.Result
	}
	for _, id := range idents {
		if !resultByID[id] {
			t.Errorf("verify result for %q = false, want true", id)
		}
	}

	// Encrypt then decrypt: the round trip must return the original
	// plaintext, which a status-only assertion would miss.
	const plaintext = "the quick brown fox jumps over the lazy dog"
	encResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathEncrypt, Body: cipherRequest(meta, []mdl.CipherDataV2Dto{{Data: plaintext, Identifier: "p-1"}})})
	if !itest.AssertStatus(t, encResp, http.StatusOK) {
		t.FailNow()
	}
	var encOut mdl.EncryptDataResponseV2Dto
	encResp.JSON(t, &encOut)
	if len(encOut.EncryptedData) != 1 {
		t.Fatalf("encrypt returned %d items, want 1: %+v", len(encOut.EncryptedData), encOut)
	}
	if encOut.EncryptedData[0].Data == plaintext {
		t.Errorf("encrypted output equals the plaintext input; want it transformed")
	}

	decResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathDecrypt, Body: cipherRequest(meta, []mdl.CipherDataV2Dto{{Data: encOut.EncryptedData[0].Data, Identifier: "p-1"}})})
	if !itest.AssertStatus(t, decResp, http.StatusOK) {
		t.FailNow()
	}
	var decOut mdl.DecryptDataResponseV2Dto
	decResp.JSON(t, &decOut)
	if len(decOut.DecryptedData) != 1 {
		t.Fatalf("decrypt returned %d items, want 1: %+v", len(decOut.DecryptedData), decOut)
	}
	if decOut.DecryptedData[0].Data != plaintext {
		t.Errorf("decrypted output = %q, want the original plaintext %q", decOut.DecryptedData[0].Data, plaintext)
	}

	const wantLen = int32(32)
	randResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathRandom, Body: randomRequest(wantLen)})
	if !itest.AssertStatus(t, randResp, http.StatusOK) {
		t.FailNow()
	}
	var randOut mdl.RandomDataResponseV2Dto
	randResp.JSON(t, &randOut)
	raw, err := base64.StdEncoding.DecodeString(randOut.Data)
	if err != nil {
		t.Fatalf("randomData response is not valid base64: %v", err)
	}
	if int32(len(raw)) != wantLen {
		t.Errorf("randomData length = %d, want %d", len(raw), wantLen)
	}
}

// --- attribute endpoints -----------------------------------------------------

func TestCryptographyV2AttributeEndpoints(t *testing.T) {
	h := startCrypto(t, nil)

	assertNonNullArray := func(t *testing.T, resp itest.Response) {
		t.Helper()
		if !itest.AssertStatus(t, resp, http.StatusOK) {
			return
		}
		var arr []mdl.BaseAttributeDto
		resp.JSON(t, &arr)
		if arr == nil {
			t.Errorf("attribute endpoint returned a null body, want a JSON array: %s", resp.Body)
		}
	}

	// keyMeta is minItems: 1, so these endpoints need a well-formed handle
	// even though they ignore the key it names.
	keyScoped := mdl.KeyScopedRequestV2Dto{
		TokenAttributes: noAttrs, TokenProfileAttributes: noAttrs, KeyUsages: oneUsage,
		KeyMeta: metaAttribute(uuid.NewString(), "keyHandle", "key handle"),
	}

	cases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"tokenAttributes", http.MethodGet, pathTokenAttrs, nil},
		{"tokenProfileAttributes", http.MethodPost, pathTokenProfileAttrs, mdl.TokenScopedRequestV2Dto{TokenAttributes: noAttrs}},
		{"createKeyAttributes", http.MethodPost, pathCreateKeyAttrs, mdl.CreateKeyAttributesRequestV2Dto{
			TokenAttributes: noAttrs, TokenProfileAttributes: noAttrs, KeyUsages: oneUsage, KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
		}},
		{"encryptAttributes", http.MethodPost, pathEncryptAttrs, keyScoped},
		{"decryptAttributes", http.MethodPost, pathDecryptAttrs, keyScoped},
		{"signAttributes", http.MethodPost, pathSignAttrs, keyScoped},
		{"verifyAttributes", http.MethodPost, pathVerifyAttrs, keyScoped},
		{"randomDataAttributes", http.MethodPost, pathRandomAttrs, mdl.TokenProfileScopedRequestV2Dto{
			TokenAttributes: noAttrs, TokenProfileAttributes: noAttrs, KeyUsages: oneUsage,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertNonNullArray(t, h.Do(t, itest.Request{Method: c.method, Path: c.path, Body: c.body}))
		})
	}
}

// pollAsyncOperation calls poll every pollInterval until it reports done or
// pollDeadline elapses, then requires that some poll observed the operation
// inProgress first. poll issues one status request and reports whether that
// response was inProgress and whether it was terminal.
func pollAsyncOperation(t *testing.T, opName string, poll func() (inProgress, done bool)) {
	t.Helper()
	var sawInProgress bool
	deadline := time.Now().Add(pollDeadline)
	for {
		inProgress, done := poll()
		if inProgress {
			sawInProgress = true
		}
		if done {
			if !sawInProgress {
				t.Errorf("%s status never reported inProgress before completing", opName)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("async %s did not reach completed within the poll deadline", opName)
		}
		time.Sleep(pollInterval)
	}
}

// --- async walk for key create, key destroy and sign ------------------------

func TestCryptographyV2AsyncWalk(t *testing.T) {
	// Each walk requires observing the operation inProgress before it
	// completes. The default asyncDelay races that: on a loaded CI host the
	// first status poll can land after completion. 2s outlasts a slow status
	// round trip and still finishes well inside pollDeadline.
	h := startCrypto(t, map[string]string{"APP_ASYNC_DELAY": "2s"})

	t.Run("createKey", func(t *testing.T) {
		// The store builds the accepted response and the completed status
		// payload in a separate branch per request type.
		for _, reqType := range []mdl.KeyRequestType{mdl.KEYREQUESTTYPE_SECRET, mdl.KEYREQUESTTYPE_KEY_PAIR} {
			t.Run(string(reqType), func(t *testing.T) {
				resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKeys, Body: createKeyRequest(
					reqType, mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS, uuid.NewString(),
				)})
				if !itest.AssertStatus(t, resp, http.StatusAccepted) {
					t.FailNow()
				}
				var out mdl.KeyCreationResponse
				resp.JSON(t, &out)
				handle := acceptedCreateMeta(t, reqType, &out)

				pollAsyncOperation(t, "createKey("+string(reqType)+")", func() (inProgress, done bool) {
					statusResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathCreateKeyStatus, Body: trackingRequest(handle)})
					if !itest.AssertStatus(t, statusResp, http.StatusOK) {
						t.FailNow()
					}
					var st mdl.KeyCreationStatusResponse
					statusResp.JSON(t, &st)
					switch status := createKeyStatusOf(t, reqType, &st); status {
					case mdl.OPERATIONSTATUS_IN_PROGRESS:
						return true, false
					case mdl.OPERATIONSTATUS_COMPLETED:
						return false, true
					default:
						t.Fatalf("createKeyStatus = %q, unexpected", status)
						return false, false
					}
				})
			})
		}
	})

	t.Run("destroyKey", func(t *testing.T) {
		meta, _ := createKeySync(t, h, mdl.KEYREQUESTTYPE_SECRET)
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathDestroyKey, Body: destroyKeyRequest(mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS, meta)})
		if !itest.AssertStatus(t, resp, http.StatusAccepted) {
			t.FailNow()
		}
		var out mdl.KeyOperationResponseV2Dto
		resp.JSON(t, &out)
		if len(out.OperationMeta) == 0 {
			t.Fatalf("accepted destroyKey response carries no operationMeta: %+v", out)
		}
		// The handle returned in the 202 body must be the one the status
		// endpoint accepts.
		handle := out.OperationMeta

		// The contract invalidates the key the moment destruction is
		// accepted, so this signature request must already be refused.
		during := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSign, Body: signRequest(
			mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, meta,
			[]mdl.SignatureDataV2Dto{{Data: "sign-me", Identifier: "item-1"}},
		)})
		itest.AssertProblem(t, during, http.StatusNotFound, "RESOURCE_NOT_FOUND")

		pollAsyncOperation(t, "destroyKey", func() (inProgress, done bool) {
			statusResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathDestroyKeyStatus, Body: trackingRequest(handle)})
			if !itest.AssertStatus(t, statusResp, http.StatusOK) {
				t.FailNow()
			}
			var st mdl.KeyDestructionStatusResponseV2Dto
			statusResp.JSON(t, &st)
			switch st.Status {
			case mdl.OPERATIONSTATUS_IN_PROGRESS:
				return true, false
			case mdl.OPERATIONSTATUS_COMPLETED:
				return false, true
			default:
				t.Fatalf("destroyKeyStatus = %q, unexpected", st.Status)
				return false, false
			}
		})
	})

	t.Run("sign", func(t *testing.T) {
		meta, _ := createKeySync(t, h, mdl.KEYREQUESTTYPE_SECRET)
		idents := []string{"async-a", "async-b"}
		data := make([]mdl.SignatureDataV2Dto, len(idents))
		for i, id := range idents {
			data[i] = mdl.SignatureDataV2Dto{Data: "payload-" + id, Identifier: id}
		}
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSign, Body: signRequest(mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS, meta, data)})
		if !itest.AssertStatus(t, resp, http.StatusAccepted) {
			t.FailNow()
		}
		var out mdl.SignDataResponseV2Dto
		resp.JSON(t, &out)
		if len(out.OperationMeta) == 0 {
			t.Fatalf("accepted sign response carries no operationMeta: %+v", out)
		}
		handle := out.OperationMeta

		pollAsyncOperation(t, "sign", func() (inProgress, done bool) {
			statusResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSignStatus, Body: trackingRequest(handle)})
			if !itest.AssertStatus(t, statusResp, http.StatusOK) {
				t.FailNow()
			}
			var st mdl.SignOperationStatusResponseV2Dto
			statusResp.JSON(t, &st)
			if len(st.Items) != len(idents) {
				t.Fatalf("signDataStatus returned %d items, want %d: %+v", len(st.Items), len(idents), st.Items)
			}
			allCompleted := true
			for _, item := range st.Items {
				switch item.Status {
				case mdl.OPERATIONSTATUS_IN_PROGRESS:
					inProgress = true
					allCompleted = false
				case mdl.OPERATIONSTATUS_COMPLETED:
					if item.Signature == nil || *item.Signature == "" {
						t.Errorf("completed sign item %q carries no signature", item.Identifier)
					}
				default:
					t.Fatalf("sign item %q status = %q, unexpected", item.Identifier, item.Status)
				}
			}
			return inProgress, allCompleted
		})
	})
}

// --- cancellation: accepted, refused, unknown --------------------------------

func TestCryptographyV2Cancellation(t *testing.T) {
	// Cancels land immediately after the 202, with no timing margin. A
	// generous asyncDelay keeps the operation in flight long enough for the
	// cancel to win on a loaded CI host.
	h := startCrypto(t, map[string]string{"APP_ASYNC_DELAY": "30s"})

	// Accepted (204): cancel while the createKey is still in flight.
	createResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKeys, Body: createKeyRequest(
		mdl.KEYREQUESTTYPE_SECRET, mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS, uuid.NewString(),
	)})
	if !itest.AssertStatus(t, createResp, http.StatusAccepted) {
		t.FailNow()
	}
	var createOut mdl.KeyCreationResponse
	createResp.JSON(t, &createOut)
	if createOut.SecretKeyDataResponseV2Dto == nil || len(createOut.SecretKeyDataResponseV2Dto.OperationMeta) == 0 {
		t.Fatalf("accepted createKey response carries no operationMeta: %+v", createOut)
	}
	cancelResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathCreateKeyCancel, Body: trackingRequest(createOut.SecretKeyDataResponseV2Dto.OperationMeta)})
	itest.AssertStatus(t, cancelResp, http.StatusNoContent)

	// A 204 reports only that the cancel was accepted; the terminal state is
	// what the store must actually record.
	statusResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathCreateKeyStatus, Body: trackingRequest(createOut.SecretKeyDataResponseV2Dto.OperationMeta)})
	if !itest.AssertStatus(t, statusResp, http.StatusOK) {
		t.FailNow()
	}
	var cancelledStatus mdl.KeyCreationStatusResponse
	statusResp.JSON(t, &cancelledStatus)
	if cancelledStatus.SecretKeyOperationStatusResponseV2Dto == nil {
		t.Fatalf("createKeyStatus response carries no SecretKeyOperationStatusResponseV2Dto variant: %+v", cancelledStatus)
	}
	got := cancelledStatus.SecretKeyOperationStatusResponseV2Dto
	if got.Status != mdl.OPERATIONSTATUS_CANCELLED {
		t.Errorf("cancelled createKey status = %q, want %q", got.Status, mdl.OPERATIONSTATUS_CANCELLED)
	}
	if got.Reason == nil || *got.Reason == "" {
		t.Errorf("cancelled createKey carries no reason: %+v", got)
	}
	if got.Result != nil {
		t.Errorf("cancelled createKey carries a result: %+v", got.Result)
	}

	// Cancelling an accepted async signing batch: 204, then every item
	// reports cancelled with a reason.
	signKeyMeta, _ := createKeySync(t, h, mdl.KEYREQUESTTYPE_SECRET)
	signResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSign, Body: signRequest(
		mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS, signKeyMeta,
		[]mdl.SignatureDataV2Dto{{Identifier: "a", Data: "Zmlyc3Q="}, {Identifier: "b", Data: "c2Vjb25k"}},
	)})
	if !itest.AssertStatus(t, signResp, http.StatusAccepted) {
		t.FailNow()
	}
	var signOut mdl.SignDataResponseV2Dto
	signResp.JSON(t, &signOut)
	if len(signOut.OperationMeta) == 0 {
		t.Fatalf("accepted signData response carries no operationMeta: %+v", signOut)
	}
	signCancelResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSignCancel, Body: trackingRequest(signOut.OperationMeta)})
	itest.AssertStatus(t, signCancelResp, http.StatusNoContent)

	signStatusResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSignStatus, Body: trackingRequest(signOut.OperationMeta)})
	if !itest.AssertStatus(t, signStatusResp, http.StatusOK) {
		t.FailNow()
	}
	var signStatus mdl.SignOperationStatusResponseV2Dto
	signStatusResp.JSON(t, &signStatus)
	if len(signStatus.Items) != 2 {
		t.Fatalf("cancelled signData status has %d items, want 2: %+v", len(signStatus.Items), signStatus.Items)
	}
	for _, item := range signStatus.Items {
		if item.Status != mdl.OPERATIONSTATUS_CANCELLED {
			t.Errorf("sign item %q status = %q, want %q", item.Identifier, item.Status, mdl.OPERATIONSTATUS_CANCELLED)
		}
		if item.Reason == nil || *item.Reason == "" {
			t.Errorf("cancelled sign item %q carries no reason", item.Identifier)
		}
		if item.Signature != nil {
			t.Errorf("cancelled sign item %q carries a signature", item.Identifier)
		}
	}

	// Cancelling an already-cancelled batch is refused: it is no longer
	// inProgress.
	againResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSignCancel, Body: trackingRequest(signOut.OperationMeta)})
	itest.AssertProblem(t, againResp, http.StatusUnprocessableEntity, "OPERATION_PAST_POINT_OF_NO_RETURN")

	// Refused (422): destruction is irreversible once accepted (see
	// store.go's asyncDestroyOp).
	meta, _ := createKeySync(t, h, mdl.KEYREQUESTTYPE_SECRET)
	destroyResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathDestroyKey, Body: destroyKeyRequest(mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS, meta)})
	if !itest.AssertStatus(t, destroyResp, http.StatusAccepted) {
		t.FailNow()
	}
	var destroyOut mdl.KeyOperationResponseV2Dto
	destroyResp.JSON(t, &destroyOut)
	if len(destroyOut.OperationMeta) == 0 {
		t.Fatalf("accepted destroyKey response carries no operationMeta: %+v", destroyOut)
	}
	refuseResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathDestroyKeyCancel, Body: trackingRequest(destroyOut.OperationMeta)})
	itest.AssertProblem(t, refuseResp, http.StatusUnprocessableEntity, "OPERATION_PAST_POINT_OF_NO_RETURN")

	// Unknown handle (404): a well-formed handle the store never issued.
	unknownResp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathCreateKeyCancel, Body: trackingRequest(unknownOperationMeta())})
	itest.AssertProblem(t, unknownResp, http.StatusNotFound, "OPERATION_NOT_TRACKED")
}

// --- keyCreationId replay and non-equivalent reuse ---------------------------

func TestCryptographyV2KeyCreationIdempotency(t *testing.T) {
	h := startCrypto(t, nil)
	creationID := uuid.NewString()

	req := createKeyRequest(mdl.KEYREQUESTTYPE_SECRET, mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, creationID)
	first := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKeys, Body: req})
	if !itest.AssertStatus(t, first, http.StatusOK) {
		t.FailNow()
	}
	var firstOut mdl.KeyCreationResponse
	first.JSON(t, &firstOut)
	firstHandle := metaUUID(t, keyMetaOf(t, mdl.KEYREQUESTTYPE_SECRET, &firstOut))

	// Equivalent replay (identical request, same keyCreationId) -> 200 with
	// the original key's handle.
	replay := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKeys, Body: req})
	if !itest.AssertStatus(t, replay, http.StatusOK) {
		t.FailNow()
	}
	var replayOut mdl.KeyCreationResponse
	replay.JSON(t, &replayOut)
	replayHandle := metaUUID(t, keyMetaOf(t, mdl.KEYREQUESTTYPE_SECRET, &replayOut))
	if replayHandle != firstHandle {
		t.Errorf("replayed keyCreationId returned handle %q, want the original %q", replayHandle, firstHandle)
	}

	// Non-equivalent reuse (same keyCreationId, different keyRequestType) ->
	// 409 RESOURCE_ALREADY_EXISTS.
	conflicting := createKeyRequest(mdl.KEYREQUESTTYPE_KEY_PAIR, mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, creationID)
	conflict := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKeys, Body: conflicting})
	itest.AssertProblem(t, conflict, http.StatusConflict, "RESOURCE_ALREADY_EXISTS")
}

// --- strict decoding ----------------------------------------------------------

func TestCryptographyV2StrictDecoding(t *testing.T) {
	h := startCrypto(t, nil)

	// Every v2 request DTO disallows unknown properties unconditionally.
	body := map[string]any{
		"tokenAttributes":        []any{},
		"tokenProfileAttributes": []any{},
		"keyUsages":              []any{"sign"},
		"length":                 16,
		"operationAttributes":    []any{},
		"unknownProperty":        "surprise",
	}
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathRandom, Body: body})
	itest.AssertProblem(t, resp, http.StatusBadRequest, "INVALID_JSON")

	h.AssertLogsConform(t)
}
