package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const (
	uuidV3 = "11111111-1111-4111-8111-111111111111"
	uuidV2 = "22222222-2222-4222-8222-222222222222"
)

func v3Def(uuid string) mdl.BaseAttributeDto {
	return mdl.BaseAttributeDto{BaseAttributeDtoV3: &mdl.BaseAttributeDtoV3{DataAttributeV3: &mdl.DataAttributeV3{Uuid: uuid, Name: "v3"}}}
}

func v2Def(uuid string) mdl.BaseAttributeDto {
	return mdl.BaseAttributeDto{BaseAttributeDtoV2: &mdl.BaseAttributeDtoV2{InfoAttributeV2: &mdl.InfoAttributeV2{Uuid: uuid, Name: "v2"}}}
}

// defsProvider serves one cached definitions DTO, as a provider that builds
// its set once would.
type defsProvider struct {
	cached  *mdl.AttributeDefinitionsDto
	def     *mdl.BaseAttributeDto
	resp    *mdl.AttributeCallbackResponseDto
	err     error
	gotUUID string
}

func (p *defsProvider) ListDefinitions(context.Context) (*mdl.AttributeDefinitionsDto, error) {
	return p.cached, p.err
}

func (p *defsProvider) GetDefinition(_ context.Context, uuid string) (*mdl.BaseAttributeDto, error) {
	p.gotUUID = uuid
	return p.def, p.err
}

func (p *defsProvider) Callback(context.Context, *mdl.AttributeCallbackRequestDto) (*mdl.AttributeCallbackResponseDto, error) {
	return p.resp, p.err
}

func serveDefs(t *testing.T, defs *defsProvider) *shared.Connector {
	t.Helper()
	h, e := NewHandler(&testProvider{}, WithAttributeDefinitions(defs))
	if e != nil {
		t.Fatal(e)
	}
	c, e := shared.New(shared.Register(h))
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func listedUUIDs(t *testing.T, body []byte) []string {
	t.Helper()
	var out struct {
		Definitions []struct {
			UUID string `json:"uuid"`
		} `json:"definitions"`
	}
	if e := json.Unmarshal(body, &out); e != nil {
		t.Fatalf("%v: %s", e, body)
	}
	uuids := make([]string, 0, len(out.Definitions))
	for _, d := range out.Definitions {
		uuids = append(uuids, d.UUID)
	}
	return uuids
}

func TestListDefinitionsFiltersByUUIDWithoutNarrowingTheProvidersSet(t *testing.T) {
	defs := &defsProvider{cached: &mdl.AttributeDefinitionsDto{ConnectorVersion: "1.0.0", Definitions: []mdl.BaseAttributeDto{v3Def(uuidV3), v2Def(uuidV2)}}}
	c := serveDefs(t, defs)

	w := request(t, c, "/v2/attributes?uuids="+uuidV2+"&uuids=&uuids=33333333-3333-4333-8333-333333333333", "")
	if got := listedUUIDs(t, w.Body.Bytes()); w.Code != 200 || len(got) != 1 || got[0] != uuidV2 {
		t.Fatalf("%d %v", w.Code, got)
	}
	w = request(t, c, "/v2/attributes?uuids="+uuidV3+"&uuids="+uuidV2, "")
	if got := listedUUIDs(t, w.Body.Bytes()); len(got) != 2 {
		t.Fatalf("both schema versions must match: %v", got)
	}
	w = request(t, c, "/v2/attributes", "")
	if got := listedUUIDs(t, w.Body.Bytes()); len(got) != 2 {
		t.Fatalf("no filter returns all: %v", got)
	}
	if len(defs.cached.Definitions) != 2 {
		t.Fatal("filtering narrowed the provider's cached set")
	}
}

func TestListDefinitionsDegradesToAnEmptySet(t *testing.T) {
	w := request(t, serveDefs(t, &defsProvider{}), "/v2/attributes", "")
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"definitions":[]`)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = request(t, serveDefs(t, &defsProvider{err: shared.Internal("INTERNAL_SERVER_ERROR", "boom")}), "/v2/attributes", "")
	if w.Code != 500 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestGetDefinition(t *testing.T) {
	def := v3Def(uuidV3)
	defs := &defsProvider{def: &def}
	w := request(t, serveDefs(t, defs), "/v2/attributes/"+uuidV3, "")
	if w.Code != 200 || defs.gotUUID != uuidV3 || !bytes.Contains(w.Body.Bytes(), []byte(uuidV3)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, tc := range []struct {
		defs *defsProvider
		code int
	}{{&defsProvider{err: ErrDefinitionNotFound}, 404}, {&defsProvider{}, 500}} {
		if w = request(t, serveDefs(t, tc.defs), "/v2/attributes/"+uuidV3, ""); w.Code != tc.code {
			t.Fatalf("want %d: %d %s", tc.code, w.Code, w.Body)
		}
	}
}

func TestAttributeCallback(t *testing.T) {
	body := `{"connectorInterface":"discovery","interfaceVersion":"v2","attributeUuid":"` + uuidV3 + `","attributeName":"v3","contextAttributes":[],"currentAttributes":[]}`
	w := request(t, serveDefs(t, &defsProvider{resp: &mdl.AttributeCallbackResponseDto{}}), "/v2/attributes/callback", body)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, tc := range []struct {
		defs *defsProvider
		body string
		code int
	}{
		{&defsProvider{err: ErrDefinitionNotFound}, body, 404},
		{&defsProvider{}, body, 500},
		{&defsProvider{}, `{`, 400},
	} {
		if w = request(t, serveDefs(t, tc.defs), "/v2/attributes/callback", tc.body); w.Code != tc.code {
			t.Fatalf("want %d: %d %s", tc.code, w.Code, w.Body)
		}
	}
}

func TestAttributeRoutesAreMountedOnlyWhenWired(t *testing.T) {
	c := serve(t, &testProvider{})
	for _, path := range []string{"/v2/attributes", "/v2/attributes/" + uuidV3} {
		if w := request(t, c, path, ""); w.Code != 404 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
}

func TestDefinitionUUID(t *testing.T) {
	const u = "44444444-4444-4444-8444-444444444444"
	for _, def := range []mdl.BaseAttributeDto{
		{BaseAttributeDtoV3: &mdl.BaseAttributeDtoV3{DataAttributeV3: &mdl.DataAttributeV3{Uuid: u}}},
		{BaseAttributeDtoV3: &mdl.BaseAttributeDtoV3{InfoAttributeV3: &mdl.InfoAttributeV3{Uuid: u}}},
		{BaseAttributeDtoV3: &mdl.BaseAttributeDtoV3{GroupAttributeV3: &mdl.GroupAttributeV3{Uuid: u}}},
		{BaseAttributeDtoV3: &mdl.BaseAttributeDtoV3{MetadataAttributeV3: &mdl.MetadataAttributeV3{Uuid: u}}},
		{BaseAttributeDtoV3: &mdl.BaseAttributeDtoV3{CustomAttributeV3: &mdl.CustomAttributeV3{Uuid: u}}},
		{BaseAttributeDtoV2: &mdl.BaseAttributeDtoV2{DataAttributeV2: &mdl.DataAttributeV2{Uuid: u}}},
		{BaseAttributeDtoV2: &mdl.BaseAttributeDtoV2{InfoAttributeV2: &mdl.InfoAttributeV2{Uuid: u}}},
		{BaseAttributeDtoV2: &mdl.BaseAttributeDtoV2{GroupAttributeV2: &mdl.GroupAttributeV2{Uuid: u}}},
		{BaseAttributeDtoV2: &mdl.BaseAttributeDtoV2{MetadataAttributeV2: &mdl.MetadataAttributeV2{Uuid: u}}},
		{BaseAttributeDtoV2: &mdl.BaseAttributeDtoV2{CustomAttributeV2: &mdl.CustomAttributeV2{Uuid: u}}},
	} {
		if got := DefinitionUUID(def); got != u {
			t.Fatalf("%+v: %q", def, got)
		}
	}
	for _, def := range []mdl.BaseAttributeDto{{}, {BaseAttributeDtoV3: &mdl.BaseAttributeDtoV3{}}} {
		if got := DefinitionUUID(def); got != "" {
			t.Fatalf("%+v: %q", def, got)
		}
	}
}
