package main_test

// Wire-level (live container) coverage for the entity-v1 request decoding
// paths: the 422 shape of shared.DecodeJSON failures, the v1 validateAttributes
// routes, and the discriminator-aware oneOf decoders (RequestAttribute and
// MetadataAttribute) driven by real HTTP bodies. The model package's own
// round-trip tests cover the wrappers in isolation; these tests prove the
// server decodes them through the handlers.

import (
	"net/http"
	"slices"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
)

const (
	// Messages shared.DecodeJSON puts in the v1 422 body (shared/codec.go).
	msgRequiredMissing = "required field is missing"
	msgInvalidType     = "request body has invalid field type"

	wireAttrUUID = "11111111-2222-3333-4444-555555555555"
)

// --- local payload builders -------------------------------------------------

// wireStringAttrV3 builds a v3 request attribute with one string content item.
func wireStringAttrV3(name, value string) mdl.RequestAttribute {
	a := mdl.NewRequestAttributeV3(wireAttrUUID, name, mdl.ATTRIBUTECONTENTTYPE_STRING, mdl.ATTRIBUTEVERSION_V3)
	a.Content = []mdl.BaseAttributeContentDtoV3{
		mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(
			mdl.NewStringAttributeContentV3(value, mdl.ATTRIBUTECONTENTTYPE_STRING)),
	}
	return mdl.RequestAttributeV3AsRequestAttribute(a)
}

// wireResourceAttrV3 builds a v3 request attribute carrying resource content
// whose data is a ResourceSimpleContentData (resource "entities").
func wireResourceAttrV3(name, resUUID, resName string) mdl.RequestAttribute {
	a := mdl.NewRequestAttributeV3(wireAttrUUID, name, mdl.ATTRIBUTECONTENTTYPE_RESOURCE, mdl.ATTRIBUTEVERSION_V3)
	data := mdl.ResourceSimpleContentDataAsResourceObjectContentData(
		mdl.NewResourceSimpleContentData(mdl.ATTRIBUTERESOURCE_ENTITIES, resUUID, resName))
	a.Content = []mdl.BaseAttributeContentDtoV3{
		mdl.ResourceObjectContentAsBaseAttributeContentDtoV3(
			mdl.NewResourceObjectContent(data, mdl.ATTRIBUTECONTENTTYPE_RESOURCE)),
	}
	return mdl.RequestAttributeV3AsRequestAttribute(a)
}

// wireEmptyAttrV2 builds a v2 request attribute with no content at all.
func wireEmptyAttrV2(name string) mdl.RequestAttribute {
	a := mdl.NewRequestAttributeV2(wireAttrUUID, name, mdl.ATTRIBUTECONTENTTYPE_STRING, mdl.ATTRIBUTEVERSION_V2)
	return mdl.RequestAttributeV2AsRequestAttribute(a)
}

// wireMetaV3 builds a v3 metadata attribute with one string content item.
func wireMetaV3(name, value string) mdl.MetadataAttribute {
	m := mdl.NewMetadataAttributeV3(wireAttrUUID, name, 3, mdl.ATTRIBUTETYPE_META,
		mdl.ATTRIBUTECONTENTTYPE_STRING, *mdl.NewMetadataAttributeProperties(name, true), mdl.ATTRIBUTEVERSION_V3)
	m.Content = []mdl.BaseAttributeContentDtoV3{
		mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(
			mdl.NewStringAttributeContentV3(value, mdl.ATTRIBUTECONTENTTYPE_STRING)),
	}
	return mdl.MetadataAttributeV3AsMetadataAttribute(m)
}

// wireMetaV2NoContent builds a v2 metadata attribute without content (v2
// content is not decodable by design, so the wire form omits it).
func wireMetaV2NoContent(name string) mdl.MetadataAttribute {
	m := mdl.NewMetadataAttributeV2(wireAttrUUID, name, 2, mdl.ATTRIBUTETYPE_META,
		mdl.ATTRIBUTECONTENTTYPE_STRING, *mdl.NewMetadataAttributeProperties(name, true))
	return mdl.MetadataAttributeV2AsMetadataAttribute(m)
}

// wireBadVersionAttr is a raw request attribute with an unknown discriminator.
func wireBadVersionAttr() map[string]any {
	return map[string]any{
		"uuid": wireAttrUUID, "name": "bad", "contentType": "string", "version": "v9",
	}
}

// --- create: 422 / 400 decode failures --------------------------------------

func TestEntityV1Create422MissingRequired(t *testing.T) {
	h := startEntity(t)

	// The spec declares a 422 []string on create; this pins the
	// shared.DecodeJSON behaviour that produces it (missing required
	// property / wrong type -> v1 422 []string).
	t.Run("missing kind", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathEntities,
			Body: map[string]any{"name": "no-kind", "attributes": []any{}}})
		msgs := itest.AssertV1ValidationErrors(t, resp)
		if !slices.Contains(msgs, msgRequiredMissing) {
			t.Errorf("422 messages = %q, want to contain %q", msgs, msgRequiredMissing)
		}
	})

	t.Run("missing attributes", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathEntities,
			Body: map[string]any{"name": "no-attrs", "kind": entityKind}})
		msgs := itest.AssertV1ValidationErrors(t, resp)
		if !slices.Contains(msgs, msgRequiredMissing) {
			t.Errorf("422 messages = %q, want to contain %q", msgs, msgRequiredMissing)
		}
	})

	t.Run("attributes of the wrong type", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathEntities,
			Body: map[string]any{"name": "bad-attrs", "kind": entityKind, "attributes": map[string]any{}}})
		msgs := itest.AssertV1ValidationErrors(t, resp)
		if !slices.Contains(msgs, msgInvalidType) {
			t.Errorf("422 messages = %q, want to contain %q", msgs, msgInvalidType)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathEntities, RawBody: []byte("{")})
		itest.AssertV1MessageEnvelope(t, resp, http.StatusBadRequest)
	})
}

// --- validate routes: 422 shape ---------------------------------------------

func TestEntityV1Validate422Shape(t *testing.T) {
	h := startEntity(t)

	// All four validateAttributes routes (kind, location, push, csr). The
	// per-entity ones do not consult the store, so an unknown UUID is fine.
	paths := []string{
		base + "/" + entityKind + "/attributes/validate",
		pathEntities + "/" + unknownEntity + "/location/attributes/validate",
		pathEntities + "/" + unknownEntity + "/locations/push/attributes/validate",
		pathEntities + "/" + unknownEntity + "/locations/csr/attributes/validate",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			// An object where an attribute array is expected -> v1 422 array.
			resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: p, Body: map[string]any{}})
			itest.AssertV1ValidationErrors(t, resp)

			// A well-formed, typed attribute list -> 200.
			resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: p, Body: []mdl.RequestAttribute{
				wireStringAttrV3("a", "x"), wireEmptyAttrV2("b"),
			}})
			itest.AssertStatus(t, resp, http.StatusOK)
		})
	}
}

// --- oneOf request decoding on the wire -------------------------------------

func TestEntityV1RequestOneOfsDecodeOnWire(t *testing.T) {
	h := startEntity(t)

	t.Run("create with v3, v3 resource and v2 attributes", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathEntities, Body: mdl.EntityInstanceRequestDto{
			Name: "oneof-create",
			Kind: entityKind,
			Attributes: []mdl.RequestAttribute{
				wireStringAttrV3("s", "hello"),
				wireResourceAttrV3("r", unknownEntity, "some-entity"),
				wireEmptyAttrV2("e"),
			},
		}})
		itest.AssertStatus(t, resp, http.StatusOK)
		var inst mdl.EntityInstanceDto
		resp.JSON(t, &inst)
		if inst.Uuid == "" || inst.Name != "oneof-create" {
			t.Errorf("created = %+v, want a uuid and name oneof-create", inst)
		}
	})

	uuid := createEntity(t, h, "oneof-loc")
	loc := pathEntities + "/" + uuid + "/locations"

	t.Run("update with mixed attributes", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPut, Path: pathEntities + "/" + uuid, Body: mdl.EntityInstanceRequestDto{
			Name:       "oneof-loc",
			Kind:       entityKind,
			Attributes: []mdl.RequestAttribute{wireStringAttrV3("s", "v"), wireEmptyAttrV2("e")},
		}})
		itest.AssertStatus(t, resp, http.StatusOK)
	})

	t.Run("locations/remove with v3 and v2 metadata", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: loc + "/remove", Body: mdl.RemoveCertificateRequestDto{
			CertificateMetadata: []mdl.MetadataAttribute{wireMetaV3("m3", "x"), wireMetaV2NoContent("m2")},
			LocationAttributes:  []mdl.RequestAttribute{wireStringAttrV3("l", "y")},
		}})
		itest.AssertStatus(t, resp, http.StatusOK)
		var out mdl.RemoveCertificateResponseDto
		resp.JSON(t, &out)
		if out.CertificateMetadata == nil {
			t.Errorf("remove certificateMetadata is null, want an array: %s", resp.Body)
		}
	})

	t.Run("locations/push with push attributes", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: loc + "/push", Body: mdl.PushCertificateRequestDto{
			Certificate:        "cGxhY2Vob2xkZXItY2VydA==", // base64 "placeholder-cert"
			LocationAttributes: []mdl.RequestAttribute{wireEmptyAttrV2("l")},
			PushAttributes:     []mdl.RequestAttribute{wireStringAttrV3("p", "z"), wireResourceAttrV3("pr", unknownEntity, "res")},
		}})
		itest.AssertStatus(t, resp, http.StatusOK)
	})

	// An unknown attribute version is a decode failure that is not a missing
	// required property or a type mismatch, so it renders as 400.
	t.Run("unknown version is 400", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathEntities, Body: map[string]any{
			"name": "bad-version", "kind": entityKind, "attributes": []any{wireBadVersionAttr()},
		}})
		itest.AssertV1Error(t, resp, http.StatusBadRequest)

		resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: loc + "/push", Body: map[string]any{
			"certificate":        "cGxhY2Vob2xkZXItY2VydA==",
			"locationAttributes": []any{wireBadVersionAttr()},
			"pushAttributes":     []any{},
		}})
		itest.AssertV1Error(t, resp, http.StatusBadRequest)

		resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: loc + "/remove", Body: map[string]any{
			"certificateMetadata": []any{map[string]any{
				"uuid": wireAttrUUID, "name": "m", "version": 9, "type": "meta", "contentType": "string",
				"properties": map[string]any{"label": "m", "visible": true},
			}},
			"locationAttributes": []any{},
		}})
		itest.AssertV1Error(t, resp, http.StatusBadRequest)
	})

	t.Run("typed health and info", func(t *testing.T) {
		itest.AssertV1HealthDto[mdl.HealthDto, mdl.HealthStatus](t, h)

		var groups []mdl.InfoResponse
		if status := h.GetJSON(t, http.MethodGet, "/v1", nil, &groups); status != http.StatusOK {
			t.Fatalf("GET /v1 = %d, want 200", status)
		}
		g, ok := itest.Find(groups, func(g mdl.InfoResponse) mdl.FunctionGroupCode { return g.FunctionGroupCode },
			mdl.FUNCTIONGROUPCODE_ENTITY_PROVIDER)
		if !ok {
			t.Fatalf("/v1 missing %q function group: %+v", fgEntity, groups)
		}
		if !slices.Contains(g.Kinds, entityKind) {
			t.Errorf("%s kinds = %v, want to contain %q", fgEntity, g.Kinds, entityKind)
		}
		if len(g.EndPoints) == 0 {
			t.Errorf("%s advertises no endPoints", fgEntity)
		}
	})
}
