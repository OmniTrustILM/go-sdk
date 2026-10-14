package main_test

// Wire-level oneOf coverage for the authority-v3 example. The generated
// model's own round-trip tests (connector/model/authority/v3) prove each
// discriminator decoder in isolation; these tests prove the same oneOfs
// survive a real HTTP hop in both directions: response bodies decode into
// the typed wrappers on the client, and every request-side content variant
// decodes server-side through shared.DecodeJSON.

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
)

// Connector-defined meta attribute UUIDs (connector/examples/authority-v3/attrs.go).
const (
	metaSerialUUID       = "4d5e6f70-1a2b-4c3d-8e9f-a0b1c2d3e404"
	metaRegistrationUUID = "8e9fa0b1-2c3d-4e5f-9607-18b9c0d1e205"
)

// Route paths not covered by integration_test.go.
const (
	pathAuthorityAttrs = "/v3/authorityProvider/authorities/attributes"
	pathRAProfileAttrs = "/v3/authorityProvider/authorities/raProfile/attributes"
	pathIssueAttrs     = "/v3/authorityProvider/certificates/issue/attributes"
	pathRevokeAttrs    = "/v3/authorityProvider/certificates/revoke/attributes"
	pathRegisterAttrs  = "/v3/authorityProvider/certificates/register/attributes"
	pathRegisterStatus = "/v3/authorityProvider/certificates/register/status"
	pathRegisterCancel = "/v3/authorityProvider/certificates/register/cancel"
	pathRevokeStatus   = "/v3/authorityProvider/certificates/revoke/status"
	pathRevokeCancel   = "/v3/authorityProvider/certificates/revoke/cancel"
	pathDefinitions    = "/v2/attributes"
	pathCallback       = "/v2/attributes/callback"
)

// --- helpers ---------------------------------------------------------------

// wireDataAttrWant is the expected shape of one published data attribute.
type wireDataAttrWant struct {
	uuid, name  string
	contentType mdl.AttributeContentType
}

var (
	wireCaNameWant   = wireDataAttrWant{caNameAttrUUID, "ca_name", mdl.ATTRIBUTECONTENTTYPE_STRING}
	wireAPIKeyWant   = wireDataAttrWant{apiKeyAttrUUID, "api_key", mdl.ATTRIBUTECONTENTTYPE_STRING}
	wireValidityWant = wireDataAttrWant{validityDaysAttrUUID, "validity_days", mdl.ATTRIBUTECONTENTTYPE_INTEGER}
)

// wireDataAttr unwraps a decoded BaseAttributeDto down to its DataAttributeV3
// leaf, failing when either oneOf level resolved to a different variant.
func wireDataAttr(t *testing.T, def mdl.BaseAttributeDto) *mdl.DataAttributeV3 {
	t.Helper()
	if def.BaseAttributeDtoV3 == nil {
		t.Fatalf("definition decoded as %T, want BaseAttributeDtoV3", def.GetActualInstance())
	}
	d := def.BaseAttributeDtoV3.DataAttributeV3
	if d == nil {
		t.Fatalf("definition decoded as %T, want DataAttributeV3", def.BaseAttributeDtoV3.GetActualInstance())
	}
	return d
}

// wireAssertDataAttrs asserts got is exactly the want set (order-free), every
// entry a required, visible, v3 data attribute with the expected name and
// content type — the shape stringDataAttr/integerDataAttr publish.
func wireAssertDataAttrs(t *testing.T, got []mdl.BaseAttributeDto, want ...wireDataAttrWant) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d attributes, want %d", len(got), len(want))
	}
	data := make([]*mdl.DataAttributeV3, 0, len(got))
	for _, def := range got {
		data = append(data, wireDataAttr(t, def))
	}
	for _, w := range want {
		d, ok := itest.Find(data, func(d *mdl.DataAttributeV3) string { return d.Uuid }, w.uuid)
		if !ok {
			t.Errorf("attribute %s (%s) missing", w.uuid, w.name)
			continue
		}
		if d.Name != w.name || d.ContentType != w.contentType {
			t.Errorf("attribute %s = {name %q, contentType %q}, want {%q, %q}", w.uuid, d.Name, d.ContentType, w.name, w.contentType)
		}
		if d.Type != mdl.ATTRIBUTETYPE_DATA || d.Version != 3 || d.SchemaVersion != mdl.ATTRIBUTEVERSION_V3 {
			t.Errorf("attribute %s = {type %q, version %d, schemaVersion %q}, want {data, 3, v3}", w.uuid, d.Type, d.Version, d.SchemaVersion)
		}
		if p := d.Properties; !p.Required || !p.Visible || p.ReadOnly || p.List || p.MultiSelect {
			t.Errorf("attribute %s properties = %+v, want required+visible only", w.uuid, p)
		}
		if d.Description == nil || *d.Description == "" {
			t.Errorf("attribute %s has no description", w.uuid)
		}
	}
}

// wireStringMeta builds a single-string v3 metadata attribute, mirroring the
// example's newMetaString, so tests can forge tracking handles.
func wireStringMeta(uuid, name, value string) mdl.MetadataAttribute {
	m := mdl.NewMetadataAttributeV3(uuid, name, 3, mdl.ATTRIBUTETYPE_META, mdl.ATTRIBUTECONTENTTYPE_STRING,
		*mdl.NewMetadataAttributeProperties(name, false), mdl.ATTRIBUTEVERSION_V3)
	m.Content = []mdl.BaseAttributeContentDtoV3{mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(
		&mdl.StringAttributeContentV3{Data: value, ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING})}
	return mdl.MetadataAttributeV3AsMetadataAttribute(m)
}

// wireCallbackReq builds an attribute callback request carrying current as
// the dependsOn form values, with the authority scope as context.
func wireCallbackReq(current ...mdl.RequestAttribute) itest.Request {
	return itest.Request{Method: http.MethodPost, Path: pathCallback, Body: mdl.AttributeCallbackRequestDto{
		ConnectorInterface: mdl.CONNECTORINTERFACE_AUTHORITY,
		InterfaceVersion:   "v3",
		AttributeUuid:      caNameAttrUUID,
		AttributeName:      "ca_name",
		ContextAttributes:  []mdl.ScopedAttributes{{Scope: mdl.RESOURCE_AUTHORITIES, Attributes: validAuth()}},
		CurrentAttributes:  append([]mdl.RequestAttribute{}, current...),
	}}
}

// --- attribute schemas decode into the typed oneOf wrappers --------------

// TestAuthorityV3AttributeSchemasTyped decodes every attribute-schema
// endpoint through the generated polymorphic types (BaseAttributeDto ->
// BaseAttributeDtoV3 -> DataAttributeV3) and pins the published contents
// against attrs.go.
func TestAuthorityV3AttributeSchemasTyped(t *testing.T) {
	h := startAuthority(t, nil)
	listReq := mdl.CertificateAttributeListRequestDtoV3{
		AuthorityAttributes: validAuth(), RaProfileAttributes: []mdl.RequestAttribute{},
	}

	t.Run("authorities/attributes", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathAuthorityAttrs})
		itest.AssertStatus(t, resp, http.StatusOK)
		var got []mdl.BaseAttributeDto
		resp.JSON(t, &got)
		wireAssertDataAttrs(t, got, wireCaNameWant, wireAPIKeyWant)
	})

	t.Run("issue/attributes", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathIssueAttrs, Body: listReq})
		itest.AssertStatus(t, resp, http.StatusOK)
		var got []mdl.BaseAttributeDto
		resp.JSON(t, &got)
		wireAssertDataAttrs(t, got, wireValidityWant)
	})

	// The example publishes empty schemas here; the wire body must still be
	// a JSON array (not null) that decodes into the typed slice.
	empty := []struct {
		name string
		req  itest.Request
	}{
		{"raProfile/attributes", itest.Request{Method: http.MethodPost, Path: pathRAProfileAttrs, Body: validAuth()}},
		{"revoke/attributes", itest.Request{Method: http.MethodPost, Path: pathRevokeAttrs, Body: listReq}},
		{"register/attributes", itest.Request{Method: http.MethodPost, Path: pathRegisterAttrs, Body: listReq}},
	}
	for _, tc := range empty {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.Do(t, tc.req)
			itest.AssertStatus(t, resp, http.StatusOK)
			var got []mdl.BaseAttributeDto
			resp.JSON(t, &got)
			if got == nil || len(got) != 0 {
				t.Errorf("got %v, want an empty array\nbody: %s", got, resp.Body)
			}
		})
	}

	t.Run("v2/attributes", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathDefinitions})
		itest.AssertStatus(t, resp, http.StatusOK)
		var defs mdl.AttributeDefinitionsDto
		resp.JSON(t, &defs)
		if defs.ConnectorVersion != "0.1.0" {
			t.Errorf("connectorVersion = %q, want 0.1.0", defs.ConnectorVersion)
		}
		wireAssertDataAttrs(t, defs.Definitions, wireCaNameWant, wireAPIKeyWant, wireValidityWant)
	})

	t.Run("v2/attributes/{uuid}", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathDefinitions + "/" + caNameAttrUUID})
		itest.AssertStatus(t, resp, http.StatusOK)
		var def mdl.BaseAttributeDto
		resp.JSON(t, &def)
		wireAssertDataAttrs(t, []mdl.BaseAttributeDto{def}, wireCaNameWant)
	})

	// The response DTO requires exactly one of content/attributes; the
	// example sets content to [] and leaves attributes unset (attrs.go
	// Callback). Assert on the raw keys too: the typed decode alone cannot
	// tell an absent key from an explicit null.
	t.Run("v2/attributes/callback", func(t *testing.T) {
		resp := h.Do(t, wireCallbackReq())
		itest.AssertStatus(t, resp, http.StatusOK)
		var cb mdl.AttributeCallbackResponseDto
		resp.JSON(t, &cb)
		if cb.Content == nil || len(cb.Content) != 0 {
			t.Errorf("content = %v, want an empty array", cb.Content)
		}
		if cb.Attributes != nil {
			t.Errorf("attributes = %v, want unset", cb.Attributes)
		}
		if cb.TotalItems == nil || *cb.TotalItems != 0 {
			t.Errorf("totalItems = %v, want 0", cb.TotalItems)
		}

		var raw map[string]json.RawMessage
		if err := json.Unmarshal(resp.Body, &raw); err != nil {
			t.Fatalf("callback body: %v", err)
		}
		if string(raw["content"]) != "[]" {
			t.Errorf(`raw "content" = %s, want []`, raw["content"])
		}
		if _, ok := raw["attributes"]; ok {
			t.Errorf(`raw body carries "attributes" alongside "content" (exactly-one-arm contract)\nbody: %s`, resp.Body)
		}
	})
}

// --- every request-side content variant decodes server-side ---------------

// wireContentCase is one BaseAttributeContentDtoV3 variant: the content, its
// attribute-level content type, and the leaf types it must decode back into.
type wireContentCase struct {
	name        string
	contentType mdl.AttributeContentType
	content     mdl.BaseAttributeContentDtoV3
	want        any // pointer to the expected BaseAttributeContentDtoV3 arm
	wantData    any // resource only: pointer to the expected ResourceObjectContentData arm
}

func wireContentCases(t *testing.T) []wireContentCase {
	t.Helper()
	resource := func(d mdl.ResourceObjectContentData) mdl.BaseAttributeContentDtoV3 {
		return mdl.ResourceObjectContentAsBaseAttributeContentDtoV3(
			mdl.NewResourceObjectContent(d, mdl.ATTRIBUTECONTENTTYPE_RESOURCE))
	}
	secret := mdl.ApiKeySecretContentAsSecretContent(mdl.NewApiKeySecretContent(mdl.SECRETTYPE_API_KEY, "s3cr3t"))
	secretData := mdl.NewResourceSecretContentData("33333333-3333-4333-8333-333333333333", "vault-secret", mdl.ATTRIBUTERESOURCE_SECRETS)
	secretData.Content = &secret
	certData := mdl.NewResourceCertificateContentData("22222222-2222-4222-8222-222222222222", "leaf", mdl.ATTRIBUTERESOURCE_CERTIFICATES)
	certData.CertificateType = ptr(mdl.CERTIFICATETYPE_X_509)
	certData.Content = ptr(foreignCertB64(t))

	return []wireContentCase{
		{"boolean", mdl.ATTRIBUTECONTENTTYPE_BOOLEAN,
			mdl.BooleanAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.BooleanAttributeContentV3{
				Data: true, ContentType: mdl.ATTRIBUTECONTENTTYPE_BOOLEAN}),
			&mdl.BooleanAttributeContentV3{}, nil},
		{"codeblock", mdl.ATTRIBUTECONTENTTYPE_CODEBLOCK,
			mdl.CodeBlockAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.CodeBlockAttributeContentV3{
				Data:        *mdl.NewCodeBlockAttributeContentData(mdl.PROGRAMMINGLANGUAGEENUM_GO, "cGFja2FnZSBtYWlu"),
				ContentType: mdl.ATTRIBUTECONTENTTYPE_CODEBLOCK}),
			&mdl.CodeBlockAttributeContentV3{}, nil},
		{"date", mdl.ATTRIBUTECONTENTTYPE_DATE,
			mdl.DateAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.DateAttributeContentV3{
				Data: "2026-10-14", ContentType: mdl.ATTRIBUTECONTENTTYPE_DATE}),
			&mdl.DateAttributeContentV3{}, nil},
		{"datetime", mdl.ATTRIBUTECONTENTTYPE_DATETIME,
			mdl.DateTimeAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.DateTimeAttributeContentV3{
				Data: time.Date(2026, 10, 14, 12, 34, 56, 0, time.UTC), ContentType: mdl.ATTRIBUTECONTENTTYPE_DATETIME}),
			&mdl.DateTimeAttributeContentV3{}, nil},
		{"file", mdl.ATTRIBUTECONTENTTYPE_FILE,
			mdl.FileAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.FileAttributeContentV3{
				Data:        *mdl.NewFileAttributeContentData("aGVsbG8=", "hello.txt", "text/plain"),
				ContentType: mdl.ATTRIBUTECONTENTTYPE_FILE}),
			&mdl.FileAttributeContentV3{}, nil},
		{"float", mdl.ATTRIBUTECONTENTTYPE_FLOAT,
			mdl.FloatAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.FloatAttributeContentV3{
				Data: 1.5, ContentType: mdl.ATTRIBUTECONTENTTYPE_FLOAT}),
			&mdl.FloatAttributeContentV3{}, nil},
		{"integer", mdl.ATTRIBUTECONTENTTYPE_INTEGER,
			mdl.IntegerAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.IntegerAttributeContentV3{
				Data: 42, ContentType: mdl.ATTRIBUTECONTENTTYPE_INTEGER}),
			&mdl.IntegerAttributeContentV3{}, nil},
		{"object", mdl.ATTRIBUTECONTENTTYPE_OBJECT,
			mdl.ObjectAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.ObjectAttributeContentV3{
				Data: map[string]any{"k": "v", "n": 1}, ContentType: mdl.ATTRIBUTECONTENTTYPE_OBJECT}),
			&mdl.ObjectAttributeContentV3{}, nil},
		{"resource/simple", mdl.ATTRIBUTECONTENTTYPE_RESOURCE,
			resource(mdl.ResourceSimpleContentDataAsResourceObjectContentData(mdl.NewResourceSimpleContentData(
				mdl.ATTRIBUTERESOURCE_AUTHORITIES, "11111111-1111-4111-8111-111111111111", "demo-authority"))),
			&mdl.ResourceObjectContent{}, &mdl.ResourceSimpleContentData{}},
		{"resource/certificate", mdl.ATTRIBUTECONTENTTYPE_RESOURCE,
			resource(mdl.ResourceCertificateContentDataAsResourceObjectContentData(certData)),
			&mdl.ResourceObjectContent{}, &mdl.ResourceCertificateContentData{}},
		{"resource/secret", mdl.ATTRIBUTECONTENTTYPE_RESOURCE,
			resource(mdl.ResourceSecretContentDataAsResourceObjectContentData(secretData)),
			&mdl.ResourceObjectContent{}, &mdl.ResourceSecretContentData{}},
		{"string", mdl.ATTRIBUTECONTENTTYPE_STRING,
			mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.StringAttributeContentV3{
				Data: "hello", ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING}),
			&mdl.StringAttributeContentV3{}, nil},
		{"text", mdl.ATTRIBUTECONTENTTYPE_TEXT,
			mdl.TextAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.TextAttributeContentV3{
				Data: "multi\nline", ContentType: mdl.ATTRIBUTECONTENTTYPE_TEXT}),
			&mdl.TextAttributeContentV3{}, nil},
		{"time", mdl.ATTRIBUTECONTENTTYPE_TIME,
			mdl.TimeAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.TimeAttributeContentV3{
				Data: "12:34:56", ContentType: mdl.ATTRIBUTECONTENTTYPE_TIME}),
			&mdl.TimeAttributeContentV3{}, nil},
	}
}

// wireAssertLocalRoundTrip marshals attr exactly as the test client sends it
// and decodes it back through the generated RequestAttribute oneOf, so a
// server-side 200 is known to have seen the intended variant on the wire.
func wireAssertLocalRoundTrip(t *testing.T, attr mdl.RequestAttribute, tc wireContentCase) {
	t.Helper()
	b, err := json.Marshal(attr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire struct {
		Version string `json:"version"`
		Content []struct {
			ContentType string          `json:"contentType"`
			Data        json.RawMessage `json:"data"`
		} `json:"content"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatalf("wire shape: %v\nwire: %s", err, b)
	}
	if wire.Version != "v3" || len(wire.Content) != 1 || wire.Content[0].ContentType != string(tc.contentType) {
		t.Fatalf("wire = %s, want version v3 and one content with contentType %q", b, tc.contentType)
	}

	var back mdl.RequestAttribute
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("decode back: %v\nwire: %s", err, b)
	}
	if back.RequestAttributeV3 == nil || len(back.RequestAttributeV3.Content) != 1 {
		t.Fatalf("decoded back as %T, want RequestAttributeV3 with one content", back.GetActualInstance())
	}
	c := back.RequestAttributeV3.Content[0]
	if got := reflect.TypeOf(c.GetActualInstance()); got != reflect.TypeOf(tc.want) {
		t.Errorf("content decoded back as %v, want %T", got, tc.want)
	}
	if tc.wantData == nil {
		return
	}
	if c.ResourceObjectContent == nil {
		t.Fatalf("resource content decoded back as %T", c.GetActualInstance())
	}
	if got := reflect.TypeOf(c.ResourceObjectContent.Data.GetActualInstance()); got != reflect.TypeOf(tc.wantData) {
		t.Errorf("resource data decoded back as %v, want %T\nwire data: %s", got, tc.wantData, wire.Content[0].Data)
	}
	if sd := c.ResourceObjectContent.Data.ResourceSecretContentData; sd != nil {
		if sd.Content == nil || sd.Content.ApiKeySecretContent == nil || sd.Content.ApiKeySecretContent.Content != "s3cr3t" {
			t.Errorf("nested secret content decoded back as %+v, want ApiKeySecretContent s3cr3t", sd.Content)
		}
	}
}

// TestAuthorityV3CallbackDecodesEveryContentVariant posts every
// BaseAttributeContentDtoV3 variant (the resource variant once per
// ResourceObjectContentData arm) as a v3 request attribute to the attribute
// callback, whose handler decodes AttributeCallbackRequestDto via
// shared.DecodeJSON: a 200 proves the server-side discriminator decoders
// accept the variant. Unknown discriminators must be 400 INVALID_JSON.
func TestAuthorityV3CallbackDecodesEveryContentVariant(t *testing.T) {
	h := startAuthority(t, nil)
	cases := wireContentCases(t)

	all := make([]mdl.RequestAttribute, 0, len(cases))
	for _, tc := range cases {
		attr := mdl.RequestAttributeV3AsRequestAttribute(mdl.NewRequestAttributeV3(
			"44444444-4444-4444-8444-444444444444", "attr_"+tc.name, tc.contentType, mdl.ATTRIBUTEVERSION_V3))
		attr.RequestAttributeV3.Content = []mdl.BaseAttributeContentDtoV3{tc.content}
		all = append(all, attr)

		t.Run(tc.name, func(t *testing.T) {
			wireAssertLocalRoundTrip(t, attr, tc)
			itest.AssertStatus(t, h.Do(t, wireCallbackReq(attr)), http.StatusOK)
		})
	}

	t.Run("all variants in one request", func(t *testing.T) {
		itest.AssertStatus(t, h.Do(t, wireCallbackReq(all...)), http.StatusOK)
	})

	// V2 attribute with no content: V2 content is not decodable by design
	// (ObjectAttributeContentV2 matches every payload), so only the V2 arm of
	// the RequestAttribute oneOf is exercised here.
	t.Run("v2 empty content", func(t *testing.T) {
		v2 := mdl.RequestAttributeV2AsRequestAttribute(mdl.NewRequestAttributeV2(
			"55555555-5555-4555-8555-555555555555", "legacy", mdl.ATTRIBUTECONTENTTYPE_STRING, mdl.ATTRIBUTEVERSION_V2))
		b, err := json.Marshal(v2)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var raw map[string]any
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, has := raw["content"]; has || raw["version"] != "v2" {
			t.Fatalf("v2 wire = %s, want version v2 and no content", b)
		}
		itest.AssertStatus(t, h.Do(t, wireCallbackReq(v2)), http.StatusOK)
	})

	// Negatives as raw maps: the typed builders cannot express them.
	rawReq := func(attr map[string]any) itest.Request {
		return itest.Request{Method: http.MethodPost, Path: pathCallback, Body: map[string]any{
			"connectorInterface": "authority",
			"interfaceVersion":   "v3",
			"attributeUuid":      caNameAttrUUID,
			"attributeName":      "ca_name",
			"contextAttributes":  []any{},
			"currentAttributes":  []any{attr},
		}}
	}
	rawAttr := func(version, contentType string) map[string]any {
		return map[string]any{
			"uuid": "66666666-6666-4666-8666-666666666666", "name": "neg", "contentType": "string", "version": version,
			"content": []any{map[string]any{"contentType": contentType, "data": "x"}},
		}
	}

	t.Run("unknown version", func(t *testing.T) {
		itest.AssertProblem(t, h.Do(t, rawReq(rawAttr("v9", "string"))), http.StatusBadRequest, "INVALID_JSON")
	})
	t.Run("unknown content contentType", func(t *testing.T) {
		itest.AssertProblem(t, h.Do(t, rawReq(rawAttr("v3", "bogus"))), http.StatusBadRequest, "INVALID_JSON")
	})
	// Control: the same raw shape with valid discriminators is accepted, so
	// the two 400s above are caused by the discriminators alone.
	t.Run("raw control", func(t *testing.T) {
		itest.AssertStatus(t, h.Do(t, rawReq(rawAttr("v3", "string"))), http.StatusOK)
	})
}

// --- register / revoke status + cancel -------------------------------------

// TestAuthorityV3RegisterAndRevokeStatusCancel drives the synchronous
// register and revoke families through status and cancel, replaying the meta
// tracking handles (MetadataAttribute oneOf) verbatim and forging unknown
// ones locally.
func TestAuthorityV3RegisterAndRevokeStatusCancel(t *testing.T) {
	h := startAuthority(t, nil)

	statusReq := func(path string, meta []mdl.MetadataAttribute) itest.Request {
		return itest.Request{Method: http.MethodPost, Path: path, Body: mdl.CertificateOperationStatusRequestDtoV3{
			AuthorityAttributes: validAuth(), RaProfileAttributes: []mdl.RequestAttribute{}, Meta: meta,
		}}
	}
	cancelReq := func(path string, meta []mdl.MetadataAttribute) itest.Request {
		return itest.Request{Method: http.MethodPost, Path: path, Body: mdl.CertificateOperationCancelRequestDtoV3{
			AuthorityAttributes: validAuth(), RaProfileAttributes: []mdl.RequestAttribute{}, Meta: meta,
		}}
	}
	// assertCompleted decodes a status response: completed, no certificate
	// (always null for register/revoke status), meta echoing want under name.
	assertCompleted := func(t *testing.T, resp itest.Response, name, want string) {
		t.Helper()
		if !itest.AssertStatus(t, resp, http.StatusOK) {
			return
		}
		var st mdl.CertificateOperationStatusResponseDtoV3
		resp.JSON(t, &st)
		if st.Status != mdl.CERTIFICATEOPERATIONSTATUSV3_COMPLETED {
			t.Errorf("status = %q, want completed", st.Status)
		}
		if st.CertificateData != nil {
			t.Errorf("certificateData = %q, want null", *st.CertificateData)
		}
		if got := metaValue(t, st.Meta, name); got != want {
			t.Errorf("meta %s = %q, want %q", name, got, want)
		}
	}

	t.Run("register", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathRegister, Body: mdl.CertificateRegistrationRequestDtoV3{
			AuthorityAttributes: validAuth(), RaProfileAttributes: []mdl.RequestAttribute{}, SubjectDn: ptr("registered-status"),
		}})
		itest.AssertStatus(t, resp, http.StatusOK)
		var reg mdl.CertificateDataResponseDtoV3
		resp.JSON(t, &reg)
		regID := metaValue(t, reg.Meta, "registration_id")
		if regID == "" {
			t.Fatalf("register response carries no registration_id meta: %s", resp.Body)
		}

		assertCompleted(t, h.Do(t, statusReq(pathRegisterStatus, reg.Meta)), "registration_id", regID)
		itest.AssertProblem(t, h.Do(t, cancelReq(pathRegisterCancel, reg.Meta)), http.StatusUnprocessableEntity, "CANCEL_REFUSED")

		unknown := []mdl.MetadataAttribute{wireStringMeta(metaRegistrationUUID, "registration_id", "no-such-registration")}
		itest.AssertProblem(t, h.Do(t, statusReq(pathRegisterStatus, unknown)), http.StatusNotFound, "OPERATION_NOT_FOUND")
		itest.AssertProblem(t, h.Do(t, cancelReq(pathRegisterCancel, unknown)), http.StatusNotFound, "OPERATION_NOT_FOUND")

		// No meta at all: the handle is optional in the spec, so this
		// reaches the provider, which requires it.
		itest.AssertProblem(t, h.Do(t, statusReq(pathRegisterStatus, nil)), http.StatusUnprocessableEntity, "VALIDATION_FAILED")
	})

	t.Run("revoke", func(t *testing.T) {
		issued := issueCert(t, h, "revoke-status.example.test")
		serial := parseCertB64(t, *issued.CertificateData).SerialNumber.String()
		if got := metaValue(t, issued.Meta, "serial"); got != serial {
			t.Fatalf("issue meta serial = %q, want %q", got, serial)
		}

		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathRevoke, Body: mdl.CertificateRevocationRequestDtoV3{
			AuthorityAttributes: validAuth(), RaProfileAttributes: []mdl.RequestAttribute{},
			Certificate: *issued.CertificateData, Reason: mdl.CERTIFICATEREVOCATIONREASON_SUPERSEDED,
		}})
		itest.AssertStatus(t, resp, http.StatusNoContent)

		assertCompleted(t, h.Do(t, statusReq(pathRevokeStatus, issued.Meta)), "serial", serial)
		itest.AssertProblem(t, h.Do(t, cancelReq(pathRevokeCancel, issued.Meta)), http.StatusUnprocessableEntity, "CANCEL_REFUSED")

		// A second, issued-but-not-revoked certificate has no revocation
		// operation to report or cancel.
		other := issueCert(t, h, "not-revoked.example.test")
		itest.AssertProblem(t, h.Do(t, statusReq(pathRevokeStatus, other.Meta)), http.StatusNotFound, "OPERATION_NOT_FOUND")
		itest.AssertProblem(t, h.Do(t, cancelReq(pathRevokeCancel, other.Meta)), http.StatusNotFound, "OPERATION_NOT_FOUND")

		// A forged handle for a serial the CA never issued -> 404 as well.
		forged := []mdl.MetadataAttribute{wireStringMeta(metaSerialUUID, "serial", "999999")}
		itest.AssertProblem(t, h.Do(t, statusReq(pathRevokeStatus, forged)), http.StatusNotFound, "OPERATION_NOT_FOUND")
	})
}
