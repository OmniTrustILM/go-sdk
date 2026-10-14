package main_test

// Wire-level integration tests for the notification-v1 example: the
// RequestAttribute oneOf decoded server-side from real HTTP bodies, and the v1
// 422 shape, exercised against the live container rather than at the model
// level. The example serves no attribute definitions, so the BaseAttributeDto
// and DataAttribute response decodes only pin the empty-array (never null)
// shape; their variant decoders are covered by the model package's round-trip
// tests. Same conventions as integration_test.go.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/notification/v1"
)

const (
	pathKindAttributes = base + "/" + notificationKind + "/attributes"
	pathKindValidate   = pathKindAttributes + "/validate"
	pathKindMapping    = pathKindAttributes + "/mapping"

	oneofAttrUUID = "7b1c2d3e-0000-4000-8000-000000000001"
	oneofV2UUID   = "7b1c2d3e-0000-4000-8000-000000000002"
)

// oneofRequestAttrs builds one V3 string attribute (with content) and one V2
// attribute with empty content, the two RequestAttribute arms.
func oneofRequestAttrs() []mdl.RequestAttribute {
	v3 := mdl.NewRequestAttributeV3(oneofAttrUUID, "recipientEmail", mdl.ATTRIBUTECONTENTTYPE_STRING, mdl.ATTRIBUTEVERSION_V3)
	v3.Content = []mdl.BaseAttributeContentDtoV3{
		mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(
			mdl.NewStringAttributeContentV3("ops@example.test", mdl.ATTRIBUTECONTENTTYPE_STRING)),
	}
	v2 := mdl.NewRequestAttributeV2(oneofV2UUID, "legacyAttr", mdl.ATTRIBUTECONTENTTYPE_STRING, mdl.ATTRIBUTEVERSION_V2)
	return []mdl.RequestAttribute{
		mdl.RequestAttributeV3AsRequestAttribute(v3),
		mdl.RequestAttributeV2AsRequestAttribute(v2),
	}
}

// --- validate: 422 shape ---------------------------------------------------

func TestNotificationV1Validate422Shape(t *testing.T) {
	h := startNotification(t)

	// A JSON object where the array of RequestAttribute is expected is a
	// structural decode failure -> v1 422 []string.
	t.Run("object instead of array", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKindValidate, Body: map[string]any{}})
		itest.AssertV1ValidationErrors(t, resp)
	})

	t.Run("valid attributes", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKindValidate, Body: oneofRequestAttrs()})
		itest.AssertStatus(t, resp, http.StatusOK)
	})
}

// --- create: 422 on missing required --------------------------------------

// The spec declares no 422 on create; this pins shared.DecodeJSON, which maps
// a missing required property (and a wrong-typed field) to the v1 422
// []string shape instead of a 400.
func TestNotificationV1Create422MissingRequired(t *testing.T) {
	h := startNotification(t)

	t.Run("missing kind", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathInstances, Body: map[string]any{
			"name":       "no-kind",
			"attributes": []any{},
		}})
		msgs := itest.AssertV1ValidationErrors(t, resp)
		if len(msgs) > 0 && !strings.Contains(msgs[0], "required field is missing") {
			t.Errorf("422 message = %q, want it to mention the missing required field", msgs[0])
		}
	})

	t.Run("missing attributes", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathInstances, Body: map[string]any{
			"name": "no-attrs",
			"kind": notificationKind,
		}})
		itest.AssertV1ValidationErrors(t, resp)
	})

	t.Run("attributes of the wrong type", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathInstances, Body: map[string]any{
			"name":       "bad-attrs",
			"kind":       notificationKind,
			"attributes": map[string]any{},
		}})
		itest.AssertV1ValidationErrors(t, resp)
	})

	t.Run("malformed JSON", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathInstances, RawBody: []byte("{")})
		itest.AssertV1MessageEnvelope(t, resp, http.StatusBadRequest)
	})
}

// --- typed attribute / info / health decodes ------------------------------

func TestNotificationV1AttributesTyped(t *testing.T) {
	h := startNotification(t)

	// Mapping attributes decode into the DataAttribute oneOf wrapper; the
	// example registers no mapping provider, so the list is empty but must be
	// a JSON array (never null).
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathKindMapping})
	itest.AssertStatus(t, resp, http.StatusOK)
	var mapping []mdl.DataAttribute
	resp.JSON(t, &mapping)
	if mapping == nil {
		t.Errorf("%s returned null, want a JSON array", pathKindMapping)
	}

	// Per-kind attribute definitions decode into the BaseAttributeDto oneOf
	// wrapper; never null either.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathKindAttributes})
	itest.AssertStatus(t, resp, http.StatusOK)
	var attrs []mdl.BaseAttributeDto
	resp.JSON(t, &attrs)
	if attrs == nil {
		t.Errorf("%s returned null, want a JSON array", pathKindAttributes)
	}

	// Typed v1 health (status enum and nested parts through the model).
	itest.AssertV1HealthDto[mdl.HealthDto, mdl.HealthStatus](t, h)

	// GET /v1 decodes into the generated InfoResponse (strict enum for the
	// function group code).
	var info []mdl.InfoResponse
	if status := h.GetJSON(t, http.MethodGet, "/v1", nil, &info); status != http.StatusOK {
		t.Fatalf("GET /v1 = %d, want 200", status)
	}
	got, ok := itest.Find(info, func(i mdl.InfoResponse) mdl.FunctionGroupCode { return i.FunctionGroupCode }, mdl.FUNCTIONGROUPCODE_NOTIFICATION_PROVIDER)
	if !ok {
		t.Fatalf("/v1 missing %q function group: %+v", fgNotification, info)
	}
	if len(got.Kinds) != 1 || got.Kinds[0] != notificationKind {
		t.Errorf("%s kinds = %v, want [%s]", fgNotification, got.Kinds, notificationKind)
	}
	if len(got.EndPoints) == 0 {
		t.Errorf("%s endpoints is empty, want the mounted routes", fgNotification)
	}
}

// --- request oneOfs decode on the wire ------------------------------------

func TestNotificationV1RequestOneOfsDecodeOnWire(t *testing.T) {
	h := startNotification(t)

	req := mdl.NotificationProviderInstanceRequestDto{
		Name:       "oneof",
		Kind:       notificationKind,
		Attributes: oneofRequestAttrs(),
	}

	// Create with a V3 attribute carrying content plus a V2 attribute with
	// empty content: both oneOf arms go through the server-side decoder.
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathInstances, Body: req})
	itest.AssertStatus(t, resp, http.StatusOK)
	var inst mdl.NotificationProviderInstanceDto
	resp.JSON(t, &inst)
	if inst.Uuid == "" {
		t.Fatalf("create returned no uuid\nbody: %s", resp.Body)
	}

	// Update takes the same request DTO.
	req.Name = "oneof-renamed"
	resp = h.Do(t, itest.Request{Method: http.MethodPut, Path: pathInstances + "/" + inst.Uuid, Body: req})
	itest.AssertStatus(t, resp, http.StatusOK)
	var updated mdl.NotificationProviderInstanceDto
	resp.JSON(t, &updated)
	if updated.Name != "oneof-renamed" {
		t.Errorf("updated name = %q, want oneof-renamed", updated.Name)
	}

	// An unknown attribute version is rejected by the oneOf discriminator
	// decoder -> 400 (not a missing-required / wrong-type 422).
	badAttr := map[string]any{
		"uuid":        oneofAttrUUID,
		"name":        "recipientEmail",
		"contentType": "string",
		"version":     "v9",
	}
	badBody := map[string]any{
		"name":       "bad-version",
		"kind":       notificationKind,
		"attributes": []any{badAttr},
	}
	t.Run("create unknown version", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathInstances, Body: badBody})
		itest.AssertV1Error(t, resp, http.StatusBadRequest)
	})
	t.Run("update unknown version", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPut, Path: pathInstances + "/" + inst.Uuid, Body: badBody})
		itest.AssertV1Error(t, resp, http.StatusBadRequest)
	})
}
