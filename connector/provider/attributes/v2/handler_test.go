package attributes_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/attributes/v2"
	attributes "github.com/OmniTrustILM/go-sdk/connector/provider/attributes/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Registry keys must be valid UUIDs (enforced at startup), so tests use these.
const (
	uRegion = "f0000000-0000-4000-8000-000000000001"
	uCity   = "f0000000-0000-4000-8000-000000000002"
	uDup    = "f0000000-0000-4000-8000-000000000003"
	uX      = "f0000000-0000-4000-8000-000000000004"
	uY      = "f0000000-0000-4000-8000-000000000005"
)

// --- definition builders ---------------------------------------------------

// dataAttr builds a static DATA attribute definition (no callback).
func dataAttr(uuid, name string) mdl.BaseAttributeDto {
	d := mdl.NewDataAttributeV3(uuid, name, 1, mdl.ATTRIBUTETYPE_DATA, mdl.ATTRIBUTECONTENTTYPE_STRING,
		*mdl.NewDataAttributeProperties(name, true, false, false, false, false, false), mdl.ATTRIBUTEVERSION_V3)
	w := mdl.DataAttributeV3AsBaseAttributeDtoV3(d)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&w)
}

// callbackAttr builds a DATA attribute declaring an NG callback triggered by
// deps. deps is stored as a non-nil slice, which is what marks the callback as
// an Attributes v2 (NG) callback.
func callbackAttr(uuid, name string, deps []string) mdl.BaseAttributeDto {
	d := mdl.NewDataAttributeV3(uuid, name, 1, mdl.ATTRIBUTETYPE_DATA, mdl.ATTRIBUTECONTENTTYPE_STRING,
		*mdl.NewDataAttributeProperties(name, true, false, false, false, false, false), mdl.ATTRIBUTEVERSION_V3)
	cb := mdl.NewAttributeCallback([]mdl.AttributeCallbackMapping{})
	cb.DependsOn = append([]string{}, deps...) // non-nil => NG callback
	d.AttributeCallback = cb
	w := mdl.DataAttributeV3AsBaseAttributeDtoV3(d)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&w)
}

func okCallback(context.Context, *mdl.AttributeCallbackRequestDto) (*mdl.AttributeCallbackResponseDto, error) {
	opt := mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.StringAttributeContentV3{
		Data: "option-1", ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
	})
	return attributes.ContentResponse([]mdl.BaseAttributeContentDtoV3{opt}, nil), nil
}

// bothOuterArms builds a malformed definition with both schema-version arms
// populated (V3 data + an empty V2 wrapper).
func bothOuterArms(uuid, name string) mdl.BaseAttributeDto {
	d := dataAttr(uuid, name) // V3 populated
	d.BaseAttributeDtoV2 = &mdl.BaseAttributeDtoV2{}
	return d
}

// twoNestedKinds builds a malformed definition whose V3 arm populates two
// attribute-kind arms (data + info).
func twoNestedKinds(uuid, name string) mdl.BaseAttributeDto {
	dv3 := mdl.NewDataAttributeV3(uuid, name, 1, mdl.ATTRIBUTETYPE_DATA, mdl.ATTRIBUTECONTENTTYPE_STRING,
		*mdl.NewDataAttributeProperties(name, true, false, false, false, false, false), mdl.ATTRIBUTEVERSION_V3)
	w := mdl.BaseAttributeDtoV3{DataAttributeV3: dv3, InfoAttributeV3: &mdl.InfoAttributeV3{}}
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&w)
}

// --- registry self-validation ----------------------------------------------

func TestValidate(t *testing.T) {
	cb := attributes.CallbackFunc(okCallback)

	cases := []struct {
		name    string
		defs    []attributes.Definition
		wantErr string // substring; "" means expect success
	}{
		{
			name: "valid: static + callback depending on a known attribute",
			defs: []attributes.Definition{
				{Attribute: dataAttr(uRegion, "region")},
				{Attribute: callbackAttr(uCity, "city", []string{"region"}), Callback: cb},
			},
		},
		{
			name: "duplicate uuid",
			defs: []attributes.Definition{
				{Attribute: dataAttr(uDup, "a")},
				{Attribute: dataAttr(uDup, "b")},
			},
			wantErr: "duplicate definition uuid",
		},
		{
			name:    "multiple outer schema-version arms",
			defs:    []attributes.Definition{{Attribute: bothOuterArms(uX, "x")}},
			wantErr: "exactly one schema-version arm",
		},
		{
			name:    "multiple nested attribute-kind arms",
			defs:    []attributes.Definition{{Attribute: twoNestedKinds(uY, "y")}},
			wantErr: "exactly one",
		},
		{
			name: "dependsOn callback without a Callback func",
			defs: []attributes.Definition{
				{Attribute: dataAttr(uRegion, "region")},
				{Attribute: callbackAttr(uCity, "city", []string{"region"})}, // no Callback
			},
			wantErr: "no Callback func is registered",
		},
		{
			name: "Callback func without a dependsOn trigger",
			defs: []attributes.Definition{
				{Attribute: dataAttr(uRegion, "region"), Callback: cb}, // static attr + callback
			},
			wantErr: "declares no dependsOn trigger",
		},
		{
			name: "dependsOn references an unknown attribute",
			defs: []attributes.Definition{
				{Attribute: callbackAttr(uCity, "city", []string{"nope"}), Callback: cb},
			},
			wantErr: "not a known attribute",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := attributes.Validate(tc.defs)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Validate = %v, want nil", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("Validate = nil, want error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("Validate = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewHandlerRejectsBlankConnectorVersion(t *testing.T) {
	for _, v := range []string{"", "   "} {
		if _, err := attributes.NewHandler(v, standardDefs()); err == nil {
			t.Errorf("NewHandler(%q, ...) = nil error, want blank-version rejection", v)
		}
	}
}

func TestNewHandlerFailsFastOnInvalidRegistry(t *testing.T) {
	_, err := attributes.NewHandler("1.0.0", []attributes.Definition{
		{Attribute: dataAttr(uDup, "a")},
		{Attribute: dataAttr(uDup, "b")},
	})
	if err == nil {
		t.Fatal("NewHandler with a duplicate uuid = nil error, want fail-fast")
	}
}

func TestNewHandlerRejectsNonUUIDKey(t *testing.T) {
	_, err := attributes.NewHandler("1.0.0", []attributes.Definition{
		{Attribute: dataAttr("not-a-uuid", "x")},
	})
	if err == nil {
		t.Error("NewHandler with a non-UUID definition key = nil error, want rejection")
	}
}

// --- HTTP surface ----------------------------------------------------------

func newServer(t *testing.T, defs []attributes.Definition) *httptest.Server {
	t.Helper()
	h, err := attributes.NewHandler("1.2.3", defs)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	c, err := shared.New(
		shared.WithInfo(shared.Info{ID: "a", Name: "a", Version: "0.0.1"}),
		shared.Register(h),
	)
	if err != nil {
		t.Fatalf("shared.New: %v", err)
	}
	srv := httptest.NewServer(c.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func standardDefs() []attributes.Definition {
	return []attributes.Definition{
		{Attribute: dataAttr(uRegion, "region")},
		{Attribute: callbackAttr(uCity, "city", []string{"region"}), Callback: attributes.CallbackFunc(okCallback)},
	}
}

func get(t *testing.T, srv *httptest.Server, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func TestListDefinitions(t *testing.T) {
	srv := newServer(t, standardDefs())

	resp := get(t, srv, "/v2/attributes")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v2/attributes = %d, want 200", resp.StatusCode)
	}
	var reg struct {
		ConnectorVersion string            `json:"connectorVersion"`
		Definitions      []json.RawMessage `json:"definitions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if reg.ConnectorVersion != "1.2.3" {
		t.Errorf("connectorVersion = %q, want 1.2.3", reg.ConnectorVersion)
	}
	if len(reg.Definitions) != 2 {
		t.Errorf("definitions = %d, want 2", len(reg.Definitions))
	}
}

func TestListDefinitionsUUIDsFilter(t *testing.T) {
	srv := newServer(t, standardDefs())

	resp := get(t, srv, "/v2/attributes?uuids="+uCity)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var reg struct {
		Definitions []json.RawMessage `json:"definitions"`
	}
	json.NewDecoder(resp.Body).Decode(&reg)
	if len(reg.Definitions) != 1 {
		t.Errorf("filtered definitions = %d, want 1", len(reg.Definitions))
	}
}

func TestGetDefinition(t *testing.T) {
	srv := newServer(t, standardDefs())

	// Known uuid -> 200.
	known := get(t, srv, "/v2/attributes/"+uRegion)
	known.Body.Close()
	if known.StatusCode != http.StatusOK {
		t.Errorf("GET known definition = %d, want 200", known.StatusCode)
	}

	// Unknown uuid -> 404 ATTRIBUTE_DEFINITION_NOT_FOUND.
	unknown := get(t, srv, "/v2/attributes/does-not-exist")
	body, _ := readClose(unknown)
	if unknown.StatusCode != http.StatusNotFound {
		t.Errorf("GET unknown definition = %d, want 404", unknown.StatusCode)
	}
	if !strings.Contains(body, "ATTRIBUTE_DEFINITION_NOT_FOUND") {
		t.Errorf("404 body missing errorCode ATTRIBUTE_DEFINITION_NOT_FOUND: %s", body)
	}
}

func TestCallbackDispatch(t *testing.T) {
	srv := newServer(t, standardDefs())

	// Dispatch to the registered callback (by attributeUuid) -> 200, content arm.
	ok := post(t, srv, "/v2/attributes/callback", mdl.AttributeCallbackRequestDto{
		ConnectorInterface: mdl.CONNECTORINTERFACE_AUTHORITY,
		InterfaceVersion:   "v3",
		AttributeUuid:      uCity,
		AttributeName:      "city",
		ContextAttributes:  []mdl.ScopedAttributes{},
		CurrentAttributes:  []mdl.RequestAttribute{},
	})
	body, _ := readClose(ok)
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("callback dispatch = %d, want 200: %s", ok.StatusCode, body)
	}
	if !strings.Contains(body, "content") {
		t.Errorf("callback response missing content arm: %s", body)
	}

	// Unregistered attribute uuid -> 404.
	missing := post(t, srv, "/v2/attributes/callback", mdl.AttributeCallbackRequestDto{
		ConnectorInterface: mdl.CONNECTORINTERFACE_AUTHORITY, InterfaceVersion: "v3",
		AttributeUuid: uRegion, AttributeName: "region", // static attr: no callback registered
		ContextAttributes: []mdl.ScopedAttributes{}, CurrentAttributes: []mdl.RequestAttribute{},
	})
	mb, _ := readClose(missing)
	if missing.StatusCode != http.StatusNotFound {
		t.Errorf("callback for attr with no callback = %d, want 404: %s", missing.StatusCode, mb)
	}
}

func TestCallbackNilResponseIs500(t *testing.T) {
	nilCb := attributes.CallbackFunc(func(context.Context, *mdl.AttributeCallbackRequestDto) (*mdl.AttributeCallbackResponseDto, error) {
		return nil, nil
	})
	srv := newServer(t, []attributes.Definition{
		{Attribute: dataAttr(uRegion, "region")},
		{Attribute: callbackAttr(uCity, "city", []string{"region"}), Callback: nilCb},
	})
	resp := post(t, srv, "/v2/attributes/callback", mdl.AttributeCallbackRequestDto{
		ConnectorInterface: mdl.CONNECTORINTERFACE_AUTHORITY, InterfaceVersion: "v3",
		AttributeUuid: uCity, AttributeName: "city",
		ContextAttributes: []mdl.ScopedAttributes{}, CurrentAttributes: []mdl.RequestAttribute{},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("nil callback response = %d, want 500", resp.StatusCode)
	}
}

// TestInfoDoesNotAdvertiseAttributes verifies the Attributes v2 handler opts
// out of the /v2/info interfaces list: the surface is common-baseline, and the
// interfaces ConnectorInterface enum has no "attributes" code, so advertising
// one would diverge from the wire contract (and risk strict Core decoding).
func TestInfoDoesNotAdvertiseAttributes(t *testing.T) {
	srv := newServer(t, standardDefs())
	resp := get(t, srv, "/v2/info")
	body, _ := readClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v2/info = %d, want 200", resp.StatusCode)
	}
	var info struct {
		Interfaces []struct {
			Code, Version string
		} `json:"interfaces"`
	}
	json.Unmarshal([]byte(body), &info)
	for _, i := range info.Interfaces {
		if i.Code == "attributes" || i.Code == "" {
			t.Errorf("/v2/info must not advertise the attributes surface, got %+v in %s", i, body)
		}
	}
}

func TestCallbackBothArmsIs500(t *testing.T) {
	bothArms := attributes.CallbackFunc(func(context.Context, *mdl.AttributeCallbackRequestDto) (*mdl.AttributeCallbackResponseDto, error) {
		return &mdl.AttributeCallbackResponseDto{
			Content:    []mdl.BaseAttributeContentDtoV3{},
			Attributes: []mdl.BaseAttributeDto{},
		}, nil
	})
	srv := newServer(t, []attributes.Definition{
		{Attribute: dataAttr(uRegion, "region")},
		{Attribute: callbackAttr(uCity, "city", []string{"region"}), Callback: bothArms},
	})
	resp := post(t, srv, "/v2/attributes/callback", mdl.AttributeCallbackRequestDto{
		ConnectorInterface: mdl.CONNECTORINTERFACE_AUTHORITY, InterfaceVersion: "v3",
		AttributeUuid: uCity, AttributeName: "city",
		ContextAttributes: []mdl.ScopedAttributes{}, CurrentAttributes: []mdl.RequestAttribute{},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("callback returning both arms = %d, want 500", resp.StatusCode)
	}
}

// --- helpers ---------------------------------------------------------------

func TestCallbackValidationRejects422(t *testing.T) {
	srv := newServer(t, standardDefs())
	badPage := int32(0)
	cases := map[string]mdl.AttributeCallbackRequestDto{
		"blank attributeName": {
			ConnectorInterface: mdl.CONNECTORINTERFACE_AUTHORITY, InterfaceVersion: "v3",
			AttributeUuid: uCity, AttributeName: "",
			ContextAttributes: []mdl.ScopedAttributes{}, CurrentAttributes: []mdl.RequestAttribute{},
		},
		"blank attributeUuid": {
			ConnectorInterface: mdl.CONNECTORINTERFACE_AUTHORITY, InterfaceVersion: "v3",
			AttributeUuid: "", AttributeName: "city",
			ContextAttributes: []mdl.ScopedAttributes{}, CurrentAttributes: []mdl.RequestAttribute{},
		},
		"pageNumber < 1": {
			ConnectorInterface: mdl.CONNECTORINTERFACE_AUTHORITY, InterfaceVersion: "v3",
			AttributeUuid: uCity, AttributeName: "city",
			ContextAttributes: []mdl.ScopedAttributes{}, CurrentAttributes: []mdl.RequestAttribute{},
			Pagination: &mdl.PaginationRequestDto{PageNumber: &badPage},
		},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			resp := post(t, srv, "/v2/attributes/callback", body)
			b, _ := readClose(resp)
			if resp.StatusCode != http.StatusUnprocessableEntity {
				t.Errorf("%s = %d, want 422: %s", name, resp.StatusCode, b)
			}
		})
	}
}

func post(t *testing.T, srv *httptest.Server, path string, body any) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func readClose(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}
