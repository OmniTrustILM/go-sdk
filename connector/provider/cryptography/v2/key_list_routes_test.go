package cryptography_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const (
	listKeyPairsPath           = "/v2/cryptographyProvider/keys/list"
	keyListNotSupportedDetail  = "key pair listing is not implemented by this connector"
	listKeyPairsBodyUnfiltered = `{"tokenAttributes":[],"tokenProfileAttributes":[],"offset":0,"limit":10}`
)

// keyPairHandle renders a v3 pair handle naming one key ID.
func keyPairHandle(keyID string) string {
	return `[{"uuid":"m-1","name":"keyId","version":3,"schemaVersion":"v3","type":"meta","contentType":"string",` +
		`"properties":{"label":"Key ID","visible":true},"content":[{"data":"` + keyID + `","contentType":"string"}]}]`
}

func listedKeyPair(keyID string) string {
	return `{` + privateKeyPairFields(keyID) + `,"publicKeyData":{"keyMeta":` + keyPairHandle(keyID) + `,` +
		`"keyData":{"type":"Public","algorithm":"RSA","length":2048,"publicKeySpki":"AA=="}}}`
}

func privateOnlyPair(keyID string) string {
	return `{` + privateKeyPairFields(keyID) + `}`
}

func privateKeyPairFields(keyID string) string {
	return `"keyPairMeta":` + keyPairHandle(keyID) + `,"label":"signer ` + keyID + `",` +
		`"privateKeyData":{"keyMeta":` + keyPairHandle(keyID) + `,"keyData":{"type":"Private","algorithm":"RSA","length":2048}}`
}

func keyPairPage(t *testing.T, pairs ...string) *mdl.ListKeyPairsResponseV2Dto {
	t.Helper()
	var page mdl.ListKeyPairsResponseV2Dto
	raw := `{"items":[` + strings.Join(pairs, ",") + `],"totalItems":` + jsonInt(len(pairs)) + `}`
	if err := json.Unmarshal([]byte(raw), &page); err != nil {
		t.Fatalf("decode page fixture: %v", err)
	}
	return &page
}

func jsonInt(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func listKeyPairsBody(fields string) string {
	return `{"tokenAttributes":[],"tokenProfileAttributes":[],` + fields + `}`
}

func newKeyListServer(t *testing.T, keyList *stubKeyList) http.Handler {
	t.Helper()
	return newTestServer(t, &stubProvider{}, cryptography.WithKeyList(keyList))
}

func TestListKeyPairsRenders404WithoutItsProvider(t *testing.T) {
	srv := newTestServer(t, &stubProvider{})

	problem := assertProblem(t, post(t, srv, listKeyPairsPath, listKeyPairsBodyUnfiltered),
		http.StatusNotFound, "OPERATION_NOT_SUPPORTED")

	if problem.Detail == nil || *problem.Detail != keyListNotSupportedDetail {
		t.Errorf("detail = %v, want %q", problem.Detail, keyListNotSupportedDetail)
	}
}

func TestKeyListFeatureRequiresTheProvider(t *testing.T) {
	_, err := cryptography.NewHandler(&stubProvider{},
		cryptography.Base(handlerbase.WithFeatures(string(mdl.FEATUREFLAG_KEY_LIST))))

	if err == nil || !strings.Contains(err.Error(), "WithKeyList") {
		t.Fatalf("NewHandler error = %v, want one naming WithKeyList", err)
	}
}

func TestListKeyPairsReturnsThePage(t *testing.T) {
	keyList := &stubKeyList{page: keyPairPage(t, listedKeyPair("0a"), privateOnlyPair("0b"))}
	srv := newKeyListServer(t, keyList)

	rec := post(t, srv, listKeyPairsPath, listKeyPairsBodyUnfiltered)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var page mdl.ListKeyPairsResponseV2Dto
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(page.Items) != 2 || page.TotalItems != 2 {
		t.Fatalf("page = %d items of %d, want 2 of 2", len(page.Items), page.TotalItems)
	}
	if page.Items[1].PublicKeyData != nil {
		t.Errorf("second key pair carries public key data, want none")
	}
	if keyList.listed == nil || keyList.listed.Limit != 10 {
		t.Errorf("provider got %+v, want the decoded request", keyList.listed)
	}
}

func TestListKeyPairsRejectsAnInvalidRequestBeforeTheProviderRuns(t *testing.T) {
	cases := map[string]string{
		"limit of zero":          `"offset":0,"limit":0`,
		"limit above maximum":    `"offset":0,"limit":1001`,
		"negative offset":        `"offset":-1,"limit":10`,
		"empty filter":           `"offset":0,"limit":10,"keyPairMetaFilter":[]`,
		"empty handle in filter": `"offset":0,"limit":10,"keyPairMetaFilter":[[]]`,
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			keyList := &stubKeyList{page: keyPairPage(t)}
			srv := newKeyListServer(t, keyList)

			assertProblem(t, post(t, srv, listKeyPairsPath, listKeyPairsBody(fields)),
				http.StatusUnprocessableEntity, "VALIDATION_FAILED")

			if keyList.listed != nil {
				t.Errorf("provider was called for a refused request")
			}
		})
	}
}

func TestListKeyPairsRejectsAResponseOutsideTheContract(t *testing.T) {
	cases := map[string]struct {
		body string
		page func(t *testing.T) *mdl.ListKeyPairsResponseV2Dto
	}{
		"more key pairs than the limit": {
			body: listKeyPairsBody(`"offset":0,"limit":1`),
			page: func(t *testing.T) *mdl.ListKeyPairsResponseV2Dto {
				return keyPairPage(t, listedKeyPair("0a"), listedKeyPair("0b"))
			},
		},
		"a key pair with an empty handle": {
			body: listKeyPairsBodyUnfiltered,
			page: func(t *testing.T) *mdl.ListKeyPairsResponseV2Dto {
				page := keyPairPage(t, listedKeyPair("0a"))
				page.Items[0].KeyPairMeta = nil
				return page
			},
		},
		"a key pair outside the filter": {
			body: listKeyPairsBody(`"offset":0,"limit":10,"keyPairMetaFilter":[` + keyPairHandle("0a") + `]`),
			page: func(t *testing.T) *mdl.ListKeyPairsResponseV2Dto {
				return keyPairPage(t, listedKeyPair("0a"), listedKeyPair("0c"))
			},
		},
		"a negative total": {
			body: listKeyPairsBodyUnfiltered,
			page: func(t *testing.T) *mdl.ListKeyPairsResponseV2Dto {
				page := keyPairPage(t, listedKeyPair("0a"))
				page.TotalItems = -1
				return page
			},
		},
		"public and private key algorithms that differ": {
			body: listKeyPairsBodyUnfiltered,
			page: func(t *testing.T) *mdl.ListKeyPairsResponseV2Dto {
				page := keyPairPage(t, listedKeyPair("0a"))
				page.Items[0].PublicKeyData.KeyData.Algorithm = mdl.KEYALGORITHM_ECDSA
				return page
			},
		},
		"a nil page": {
			body: listKeyPairsBodyUnfiltered,
			page: func(*testing.T) *mdl.ListKeyPairsResponseV2Dto { return nil },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newKeyListServer(t, &stubKeyList{page: tc.page(t)})

			assertProblem(t, post(t, srv, listKeyPairsPath, tc.body),
				http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
		})
	}
}

func TestListKeyPairsAcceptsTheKeyPairsTheFilterNames(t *testing.T) {
	keyList := &stubKeyList{page: keyPairPage(t, listedKeyPair("0b"), privateOnlyPair("0a"))}
	srv := newKeyListServer(t, keyList)
	body := listKeyPairsBody(`"offset":0,"limit":2,"keyPairMetaFilter":[` + keyPairHandle("0a") + `,` +
		keyPairHandle("0b") + `]`)

	rec := post(t, srv, listKeyPairsPath, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
}

func TestListKeyPairsNormalizesNilItemsToEmptyArray(t *testing.T) {
	srv := newKeyListServer(t, &stubKeyList{page: &mdl.ListKeyPairsResponseV2Dto{}})

	rec := post(t, srv, listKeyPairsPath, listKeyPairsBodyUnfiltered)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Fatalf("status = %d, body %s; want 200 with an empty items array", rec.Code, rec.Body.String())
	}
}

// A provider may cache and share the page it returns.
func TestListKeyPairsLeavesTheProvidersPageUnchanged(t *testing.T) {
	cached := &mdl.ListKeyPairsResponseV2Dto{}
	srv := newKeyListServer(t, &stubKeyList{page: cached})

	rec := post(t, srv, listKeyPairsPath, listKeyPairsBodyUnfiltered)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if cached.Items != nil {
		t.Errorf("provider's page Items = %v, want it left nil", cached.Items)
	}
}

func TestListKeyPairsReturnsUnaddressableKeys(t *testing.T) {
	page := keyPairPage(t, listedKeyPair("0a"))
	page.UnaddressableKeys = []mdl.UnaddressableKeyV2Dto{*mdl.NewUnaddressableKeyV2Dto(*mdl.NewPrivateKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048))}
	srv := newKeyListServer(t, &stubKeyList{page: page})

	rec := post(t, srv, listKeyPairsPath, listKeyPairsBodyUnfiltered)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var got mdl.ListKeyPairsResponseV2Dto
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got.UnaddressableKeys) != 1 {
		t.Errorf("response carries %d unaddressable keys, want 1", len(got.UnaddressableKeys))
	}
}

func TestListKeyPairsLeavesOutAnEmptyUnaddressableKeysList(t *testing.T) {
	cases := map[string][]mdl.UnaddressableKeyV2Dto{"nil": nil, "empty": {}}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newKeyListServer(t, &stubKeyList{page: &mdl.ListKeyPairsResponseV2Dto{UnaddressableKeys: keys}})

			rec := post(t, srv, listKeyPairsPath, listKeyPairsBodyUnfiltered)

			if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "unaddressableKeys") {
				t.Fatalf("status = %d, body %s; want 200 without unaddressableKeys", rec.Code, rec.Body.String())
			}
		})
	}
}
