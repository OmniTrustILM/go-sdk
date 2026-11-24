package cryptography_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const (
	listKeysPath              = "/v2/cryptographyProvider/keys/list"
	keyListNotSupportedDetail = "key listing is not implemented by this connector"
	listKeyPairs              = `"keyRequestType":"keyPair","offset":0,"limit":10`
	listSecretKeys            = `"keyRequestType":"secret","offset":0,"limit":10`
)

// keyHandle renders a v3 handle naming one key ID.
func keyHandle(keyID string) string {
	return `[{"uuid":"m-1","name":"keyId","version":3,"schemaVersion":"v3","type":"meta","contentType":"string",` +
		`"properties":{"label":"Key ID","visible":true},"content":[{"data":"` + keyID + `","contentType":"string"}]}]`
}

func listedKeyPair(keyID string) string {
	return `{` + privateKeyPairFields(keyID) + `,"publicKeyData":{"keyMeta":` + keyHandle(keyID) + `,` +
		`"keyData":{"type":"Public","algorithm":"RSA","publicKeySpki":"AA=="}}}`
}

func privateOnlyPair(keyID string) string {
	return `{` + privateKeyPairFields(keyID) + `}`
}

func privateKeyPairFields(keyID string) string {
	return `"keyRequestType":"keyPair","keyPairMeta":` + keyHandle(keyID) + `,` +
		`"privateKeyData":{"keyMeta":` + keyHandle(keyID) + `,"keyData":{"type":"Private","algorithm":"RSA","length":2048}}`
}

func listedSecretKey(keyID string) string {
	return `{"keyRequestType":"secret","keyMeta":` + keyHandle(keyID) + `,` +
		`"keyData":{"type":"Secret","algorithm":"AES","length":256}}`
}

// available renders the entry of a key the platform can onboard.
func available(key string) string {
	return `{"status":"available","storageName":"stored key","key":` + key + `}`
}

func keyPage(t *testing.T, entries ...string) *mdl.ListKeysResponseV2Dto {
	t.Helper()
	var page mdl.ListKeysResponseV2Dto
	raw := `{"items":[` + strings.Join(entries, ",") + `],"totalItems":` + jsonInt(len(entries)) + `}`
	if err := json.Unmarshal([]byte(raw), &page); err != nil {
		t.Fatalf("decode page fixture: %v", err)
	}
	return &page
}

func jsonInt(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func listKeysBody(fields string) string {
	return `{"tokenAttributes":[],"tokenProfileAttributes":[],` + fields + `}`
}

func newKeyListServer(t *testing.T, keyList *stubKeyList) http.Handler {
	t.Helper()
	return newTestServer(t, &stubProvider{}, cryptography.WithKeyList(keyList))
}

func unlistableToken() cryptography.Option {
	return cryptography.Base(handlerbase.WithFeatures(string(mdl.FEATUREFLAG_UNLISTABLE_TOKEN)))
}

func newUnlistableServer(t *testing.T) http.Handler {
	t.Helper()
	h, err := cryptography.NewHandler(&stubProvider{}, unlistableToken())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return mount(t, h)
}

func TestListKeysRenders404OnAnUnlistableToken(t *testing.T) {
	srv := newUnlistableServer(t)

	problem := assertProblem(t, post(t, srv, listKeysPath, listKeysBody(listKeyPairs)),
		http.StatusNotFound, "OPERATION_NOT_SUPPORTED")

	if problem.Detail == nil || *problem.Detail != keyListNotSupportedDetail {
		t.Errorf("detail = %v, want %q", problem.Detail, keyListNotSupportedDetail)
	}
}

func TestListableTokenRequiresTheKeyListProvider(t *testing.T) {
	_, err := cryptography.NewHandler(&stubProvider{})

	if err == nil || !strings.Contains(err.Error(), "WithKeyList") {
		t.Fatalf("NewHandler error = %v, want one naming WithKeyList", err)
	}
}

func TestUnlistableTokenRefusesTheKeyListProvider(t *testing.T) {
	_, err := cryptography.NewHandler(&stubProvider{}, unlistableToken(), cryptography.WithKeyList(&stubKeyList{}))

	if err == nil || !strings.Contains(err.Error(), "advertised with WithKeyList") {
		t.Fatalf("NewHandler error = %v, want one refusing WithKeyList alongside unlistableToken", err)
	}
}

func TestListKeysReturnsThePage(t *testing.T) {
	keyList := &stubKeyList{page: keyPage(t, available(listedKeyPair("0a")), available(privateOnlyPair("0b")))}
	srv := newKeyListServer(t, keyList)

	rec := post(t, srv, listKeysPath, listKeysBody(listKeyPairs))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var page mdl.ListKeysResponseV2Dto
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(page.Items) != 2 || page.TotalItems != 2 {
		t.Fatalf("page = %d items of %d, want 2 of 2", len(page.Items), page.TotalItems)
	}
	if pair := page.Items[1].Key; pair == nil || pair.ListedKeyPairV2Dto == nil || pair.ListedKeyPairV2Dto.PublicKeyData != nil {
		t.Errorf("second entry = %+v, want a key pair without public key data", page.Items[1])
	}
	if keyList.listed == nil || keyList.listed.Limit != 10 || keyList.listed.KeyRequestType != mdl.KEYREQUESTTYPE_KEY_PAIR {
		t.Errorf("provider got %+v, want the decoded request", keyList.listed)
	}
}

func TestListKeysReturnsASecretKeyPage(t *testing.T) {
	srv := newKeyListServer(t, &stubKeyList{page: keyPage(t, available(listedSecretKey("0a")))})

	rec := post(t, srv, listKeysPath, listKeysBody(listSecretKeys))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var page mdl.ListKeysResponseV2Dto
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].Key == nil || page.Items[0].Key.ListedSecretKeyV2Dto == nil {
		t.Errorf("page = %+v, want one secret key", page.Items)
	}
}

func TestListKeysRendersTheRefusalOfAKeyTypeTheProviderCannotList(t *testing.T) {
	srv := newKeyListServer(t, &stubKeyList{err: cryptography.ErrKeyTypeNotListable})

	assertProblem(t, post(t, srv, listKeysPath, listKeysBody(listSecretKeys)),
		http.StatusUnprocessableEntity, "KEY_TYPE_NOT_LISTABLE")
}

func TestListKeysRejectsAnInvalidRequestBeforeTheProviderRuns(t *testing.T) {
	cases := map[string]string{
		"no key request type": `"offset":0,"limit":10`,
		"limit of zero":       `"keyRequestType":"keyPair","offset":0,"limit":0`,
		"limit above maximum": `"keyRequestType":"keyPair","offset":0,"limit":1001`,
		"negative offset":     `"keyRequestType":"keyPair","offset":-1,"limit":10`,
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			keyList := &stubKeyList{page: keyPage(t)}
			srv := newKeyListServer(t, keyList)

			assertProblem(t, post(t, srv, listKeysPath, listKeysBody(fields)),
				http.StatusUnprocessableEntity, "VALIDATION_FAILED")

			if keyList.listed != nil {
				t.Errorf("provider was called for a refused request")
			}
		})
	}
}

func TestListKeysRejectsAResponseOutsideTheContract(t *testing.T) {
	cases := map[string]struct {
		fields string
		page   func(t *testing.T) *mdl.ListKeysResponseV2Dto
	}{
		"more keys than the limit": {
			fields: `"keyRequestType":"keyPair","offset":0,"limit":1`,
			page: func(t *testing.T) *mdl.ListKeysResponseV2Dto {
				return keyPage(t, available(listedKeyPair("0a")), available(listedKeyPair("0b")))
			},
		},
		"a key pair with an empty handle": {
			fields: listKeyPairs,
			page: func(t *testing.T) *mdl.ListKeysResponseV2Dto {
				page := keyPage(t, available(listedKeyPair("0a")))
				page.Items[0].Key.ListedKeyPairV2Dto.KeyPairMeta = nil
				return page
			},
		},
		"a negative total": {
			fields: listKeyPairs,
			page: func(t *testing.T) *mdl.ListKeysResponseV2Dto {
				page := keyPage(t, available(listedKeyPair("0a")))
				page.TotalItems = -1
				return page
			},
		},
		"public and private key algorithms that differ": {
			fields: listKeyPairs,
			page: func(t *testing.T) *mdl.ListKeysResponseV2Dto {
				page := keyPage(t, available(listedKeyPair("0a")))
				page.Items[0].Key.ListedKeyPairV2Dto.PublicKeyData.KeyData.Algorithm = mdl.KEYALGORITHM_ECDSA
				return page
			},
		},
		"a key pair with a private algorithmIdentifier that is not base64": {
			fields: listKeyPairs,
			page: func(t *testing.T) *mdl.ListKeysResponseV2Dto {
				page := keyPage(t, available(listedKeyPair("0a")))
				page.Items[0].Key.ListedKeyPairV2Dto.PrivateKeyData.KeyData.SetAlgorithmIdentifier("not base64!")
				return page
			},
		},
		"a secret key in a key pair listing": {
			fields: listKeyPairs,
			page: func(t *testing.T) *mdl.ListKeysResponseV2Dto {
				return keyPage(t, available(listedKeyPair("0a")), available(listedSecretKey("0b")))
			},
		},
		"a key pair in a secret key listing": {
			fields: listSecretKeys,
			page: func(t *testing.T) *mdl.ListKeysResponseV2Dto {
				return keyPage(t, available(listedKeyPair("0a")))
			},
		},
		"an unaddressable secret key in a key pair listing": {
			fields: listKeyPairs,
			page: func(t *testing.T) *mdl.ListKeysResponseV2Dto {
				page := keyPage(t, available(listedKeyPair("0a")))
				page.Items = append(page.Items, unaddressableSecretKey())
				page.TotalItems = 2
				return page
			},
		},
		"an entry with the status only a resolution reports": {
			fields: listKeyPairs,
			page: func(t *testing.T) *mdl.ListKeysResponseV2Dto {
				page := keyPage(t, available(listedKeyPair("0a")))
				page.Items[0].Status = mdl.KEYENTRYSTATUS_INVALID_HANDLE
				return page
			},
		},
		"an available entry without its key": {
			fields: listKeyPairs,
			page: func(t *testing.T) *mdl.ListKeysResponseV2Dto {
				page := keyPage(t, available(listedKeyPair("0a")))
				page.Items[0].Key = nil
				return page
			},
		},
		"a nil page": {
			fields: listKeyPairs,
			page:   func(*testing.T) *mdl.ListKeysResponseV2Dto { return nil },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newKeyListServer(t, &stubKeyList{page: tc.page(t)})

			assertProblem(t, post(t, srv, listKeysPath, listKeysBody(tc.fields)),
				http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
		})
	}
}

func TestListKeysNormalizesNilItemsToEmptyArray(t *testing.T) {
	srv := newKeyListServer(t, &stubKeyList{page: &mdl.ListKeysResponseV2Dto{}})

	rec := post(t, srv, listKeysPath, listKeysBody(listKeyPairs))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Fatalf("status = %d, body %s; want 200 with an empty items array", rec.Code, rec.Body.String())
	}
}

// A provider may cache and share the page it returns.
func TestListKeysLeavesTheProvidersPageUnchanged(t *testing.T) {
	cached := &mdl.ListKeysResponseV2Dto{}
	srv := newKeyListServer(t, &stubKeyList{page: cached})

	rec := post(t, srv, listKeysPath, listKeysBody(listKeyPairs))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if cached.Items != nil {
		t.Errorf("provider's page Items = %v, want it left nil", cached.Items)
	}
}

func TestListKeysReturnsUnaddressableKeysInTheirPlace(t *testing.T) {
	cases := map[string]struct {
		fields        string
		unaddressable mdl.ListedKeyEntryV2Dto
		available     string
	}{
		"a private key in a key pair listing":  {listKeyPairs, unaddressablePrivateKey(), listedKeyPair("0b")},
		"a secret key in a secret key listing": {listSecretKeys, unaddressableSecretKey(), listedSecretKey("0b")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			page := keyPage(t, available(tc.available))
			page.Items = append([]mdl.ListedKeyEntryV2Dto{tc.unaddressable}, page.Items...)
			page.TotalItems = 2
			srv := newKeyListServer(t, &stubKeyList{page: page})

			rec := post(t, srv, listKeysPath, listKeysBody(tc.fields))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			var got mdl.ListKeysResponseV2Dto
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if len(got.Items) != 2 {
				t.Fatalf("response carries %d items, want 2", len(got.Items))
			}
			if got.Items[0].Status != mdl.KEYENTRYSTATUS_UNADDRESSABLE || got.Items[1].Status != mdl.KEYENTRYSTATUS_AVAILABLE {
				t.Errorf("items = %+v, want the unaddressable key before the available one", got.Items)
			}
			unaddressable := got.Items[0]
			if diagnostic := unaddressable.Diagnostic; diagnostic == nil || *diagnostic != unaddressableDiagnostic {
				t.Errorf("diagnostic = %v, want %q", diagnostic, unaddressableDiagnostic)
			}
			if name := unaddressable.StorageName; name == nil || *name != unaddressableStorageName {
				t.Errorf("storageName = %v, want %q", name, unaddressableStorageName)
			}
			if !reflect.DeepEqual(unaddressable.KeyData, tc.unaddressable.KeyData) {
				t.Errorf("keyData = %+v, want %+v", unaddressable.KeyData, tc.unaddressable.KeyData)
			}
		})
	}
}

const (
	unaddressableDiagnostic  = "the key has no CKA_ID"
	unaddressableStorageName = "legacy"
)

func unaddressablePrivateKey() mdl.ListedKeyEntryV2Dto {
	entry := unaddressableEntry()
	entry.SetKeyData(mdl.PrivateKeyDataV2DtoAsKeyDataV2(newPrivateKeyData(mdl.KEYALGORITHM_RSA, 2048)))
	return *entry
}

func unaddressableSecretKey() mdl.ListedKeyEntryV2Dto {
	entry := unaddressableEntry()
	entry.SetKeyData(mdl.SecretKeyDataV2DtoAsKeyDataV2(mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_AES, 256)))
	return *entry
}

func unaddressableEntry() *mdl.ListedKeyEntryV2Dto {
	entry := mdl.NewListedKeyEntryV2Dto(mdl.KEYENTRYSTATUS_UNADDRESSABLE)
	entry.SetDiagnostic(unaddressableDiagnostic)
	entry.SetStorageName(unaddressableStorageName)
	return entry
}

const (
	resolveKeysPath = "/v2/cryptographyProvider/keys/resolve"
	resolvePairs    = `"keyRequestType":"keyPair"`
)

func resolveHandle(identifier, keyID string) string {
	return `{"identifier":"` + identifier + `","keyMeta":` + keyHandle(keyID) + `}`
}

func resolveBody(fields string, handles ...string) string {
	return listKeysBody(fields + `,"keys":[` + strings.Join(handles, ",") + `]`)
}

func foundResult(identifier, key string) string {
	return `{"identifier":"` + identifier + `","status":"available","key":` + key + `}`
}

func bareResult(identifier string, status mdl.KeyEntryStatus) string {
	return `{"identifier":"` + identifier + `","status":"` + string(status) + `"}`
}

func resolution(t *testing.T, results ...string) *mdl.ResolveKeysResponseV2Dto {
	t.Helper()
	var out mdl.ResolveKeysResponseV2Dto
	if err := json.Unmarshal([]byte(`{"results":[`+strings.Join(results, ",")+`]}`), &out); err != nil {
		t.Fatalf("decode resolution fixture: %v", err)
	}
	return &out
}

func TestResolveKeysRenders404OnAnUnlistableToken(t *testing.T) {
	srv := newUnlistableServer(t)

	problem := assertProblem(t, post(t, srv, resolveKeysPath, resolveBody(resolvePairs, resolveHandle("a", "0a"))),
		http.StatusNotFound, "OPERATION_NOT_SUPPORTED")

	if problem.Detail == nil || *problem.Detail != keyListNotSupportedDetail {
		t.Errorf("detail = %v, want %q", problem.Detail, keyListNotSupportedDetail)
	}
}

func TestResolveKeysReturnsTheResults(t *testing.T) {
	keyList := &stubKeyList{results: resolution(t, foundResult("a", listedKeyPair("0a")), bareResult("b", mdl.KEYENTRYSTATUS_NOT_FOUND))}
	srv := newKeyListServer(t, keyList)

	rec := post(t, srv, resolveKeysPath, resolveBody(resolvePairs, resolveHandle("a", "0a"), resolveHandle("b", "0b")))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got mdl.ResolveKeysResponseV2Dto
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got.Results) != 2 {
		t.Fatalf("response carries %d results, want 2", len(got.Results))
	}
	if first := got.Results[0]; first.Identifier != "a" || first.Status != mdl.KEYENTRYSTATUS_AVAILABLE ||
		first.Key == nil || first.Key.ListedKeyPairV2Dto == nil {
		t.Errorf("first result = %+v, want a found key pair under a", first)
	}
	if second := got.Results[1]; second.Identifier != "b" || second.Status != mdl.KEYENTRYSTATUS_NOT_FOUND || second.Key != nil {
		t.Errorf("second result = %+v, want not found under b", second)
	}
	if keyList.resolved == nil || len(keyList.resolved.Keys) != 2 || keyList.resolved.KeyRequestType != mdl.KEYREQUESTTYPE_KEY_PAIR {
		t.Errorf("provider got %+v, want the decoded request", keyList.resolved)
	}
}

func TestResolveKeysReturnsADiagnostic(t *testing.T) {
	refused := `{"identifier":"a","status":"refused","diagnostic":"` + refusedDiagnostic + `","key":` + listedKeyPair("0a") + `}`
	srv := newKeyListServer(t, &stubKeyList{results: resolution(t, refused)})

	rec := post(t, srv, resolveKeysPath, resolveBody(resolvePairs, resolveHandle("a", "0a")))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got mdl.ResolveKeysResponseV2Dto
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got.Results) != 1 {
		t.Fatalf("response carries %d results, want 1", len(got.Results))
	}
	if result := got.Results[0]; result.Status != mdl.KEYENTRYSTATUS_REFUSED || result.Diagnostic == nil ||
		*result.Diagnostic != refusedDiagnostic {
		t.Errorf("result = %+v, want a refused key with diagnostic %q", result, refusedDiagnostic)
	}
}

const refusedDiagnostic = "CKA_SIGN is false"

func TestResolveKeysRendersTheRefusalOfAKeyTypeTheProviderCannotList(t *testing.T) {
	srv := newKeyListServer(t, &stubKeyList{resolveErr: cryptography.ErrKeyTypeNotListable})

	assertProblem(t, post(t, srv, resolveKeysPath, resolveBody(`"keyRequestType":"secret"`, resolveHandle("a", "0a"))),
		http.StatusUnprocessableEntity, "KEY_TYPE_NOT_LISTABLE")
}

func TestResolveKeysRejectsAnInvalidRequestBeforeTheProviderRuns(t *testing.T) {
	var thousandAndOne []string
	for i := range 1001 {
		thousandAndOne = append(thousandAndOne, resolveHandle(jsonInt(i), "0a"))
	}
	cases := map[string]struct {
		fields  string
		handles []string
	}{
		"no key request type":   {fields: `"offset":0`, handles: []string{resolveHandle("a", "0a")}},
		"no keys":               {fields: resolvePairs},
		"1001 keys":             {fields: resolvePairs, handles: thousandAndOne},
		"a blank identifier":    {fields: resolvePairs, handles: []string{resolveHandle(" ", "0a")}},
		"a repeated identifier": {fields: resolvePairs, handles: []string{resolveHandle("a", "0a"), resolveHandle("a", "0b")}},
		"an empty handle":       {fields: resolvePairs, handles: []string{`{"identifier":"a","keyMeta":[]}`}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			keyList := &stubKeyList{results: resolution(t)}
			srv := newKeyListServer(t, keyList)

			assertProblem(t, post(t, srv, resolveKeysPath, resolveBody(tc.fields, tc.handles...)),
				http.StatusUnprocessableEntity, "VALIDATION_FAILED")

			if keyList.resolved != nil {
				t.Errorf("provider was called for a refused request")
			}
		})
	}
}

func TestResolveKeysRejectsAResponseOutsideTheContract(t *testing.T) {
	cases := map[string]func(t *testing.T) *mdl.ResolveKeysResponseV2Dto{
		"a missing result": func(t *testing.T) *mdl.ResolveKeysResponseV2Dto {
			return resolution(t, bareResult("a", mdl.KEYENTRYSTATUS_NOT_FOUND))
		},
		"a result for an unknown identifier": func(t *testing.T) *mdl.ResolveKeysResponseV2Dto {
			return resolution(t, bareResult("a", mdl.KEYENTRYSTATUS_NOT_FOUND), bareResult("z", mdl.KEYENTRYSTATUS_NOT_FOUND))
		},
		"a repeated result": func(t *testing.T) *mdl.ResolveKeysResponseV2Dto {
			return resolution(t, bareResult("a", mdl.KEYENTRYSTATUS_NOT_FOUND), bareResult("a", mdl.KEYENTRYSTATUS_NOT_FOUND))
		},
		"available without a key": func(t *testing.T) *mdl.ResolveKeysResponseV2Dto {
			return resolution(t, bareResult("a", mdl.KEYENTRYSTATUS_AVAILABLE), bareResult("b", mdl.KEYENTRYSTATUS_NOT_FOUND))
		},
		"not found with a key": func(t *testing.T) *mdl.ResolveKeysResponseV2Dto {
			out := resolution(t, foundResult("a", listedKeyPair("0a")), bareResult("b", mdl.KEYENTRYSTATUS_NOT_FOUND))
			out.Results[0].Status = mdl.KEYENTRYSTATUS_NOT_FOUND
			return out
		},
		"an unknown status": func(t *testing.T) *mdl.ResolveKeysResponseV2Dto {
			out := resolution(t, bareResult("a", mdl.KEYENTRYSTATUS_NOT_FOUND), bareResult("b", mdl.KEYENTRYSTATUS_NOT_FOUND))
			out.Results[0].Status = "gone"
			return out
		},
		"a secret key in a key pair resolution": func(t *testing.T) *mdl.ResolveKeysResponseV2Dto {
			return resolution(t, foundResult("a", listedSecretKey("0a")), bareResult("b", mdl.KEYENTRYSTATUS_NOT_FOUND))
		},
		"a nil resolution": func(*testing.T) *mdl.ResolveKeysResponseV2Dto { return nil },
		"an unaddressable secret key in a key pair resolution": func(t *testing.T) *mdl.ResolveKeysResponseV2Dto {
			out := resolution(t, bareResult("a", mdl.KEYENTRYSTATUS_UNADDRESSABLE), bareResult("b", mdl.KEYENTRYSTATUS_NOT_FOUND))
			out.Results[0].SetKeyData(mdl.SecretKeyDataV2DtoAsKeyDataV2(mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_AES, 256)))
			return out
		},
		"a diagnostic over the cap": func(t *testing.T) *mdl.ResolveKeysResponseV2Dto {
			out := resolution(t, bareResult("a", mdl.KEYENTRYSTATUS_UNREADABLE), bareResult("b", mdl.KEYENTRYSTATUS_NOT_FOUND))
			out.Results[0].SetDiagnostic(strings.Repeat("x", 1001))
			return out
		},
		"a key with an ambiguous handle": func(t *testing.T) *mdl.ResolveKeysResponseV2Dto {
			out := resolution(t, foundResult("a", listedKeyPair("0a")), bareResult("b", mdl.KEYENTRYSTATUS_NOT_FOUND))
			pair := out.Results[0].Key.ListedKeyPairV2Dto
			pair.KeyPairMeta = append(pair.KeyPairMeta, pair.KeyPairMeta...)
			return out
		},
	}
	for name, results := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newKeyListServer(t, &stubKeyList{results: results(t)})

			assertProblem(t, post(t, srv, resolveKeysPath, resolveBody(resolvePairs, resolveHandle("a", "0a"), resolveHandle("b", "0b"))),
				http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
		})
	}
}
