package main_test

// Integration tests for the credential-v1 example (Credential Provider with a
// fixed basic / apiKey attribute schema), driven over the public HTTP
// interface via the shared testcontainers harness. Requests/responses use the
// generated connector/model/credential/v1 types so the test exercises the
// spec, the generated models, and the shared/provider runtime end to end.
// Skips with no Docker or under -short.
//
// credential-v1 is a v1-family connector: info at GET /v1, health at
// GET /v1/health, v1 ErrorMessageDto envelope — so error paths use
// itest.AssertV1Error / AssertV1MessageEnvelope, and 422 is a bare []string.
//
// Example quirks the tests rely on:
//   - Routes are wildcard ({kind}); CREDENTIAL_KIND only drives what /v1
//     advertises. The store itself serves "basic" and "apiKey" regardless,
//     and answers any other kind with 404 "credential kind not supported".
//   - ValidateAttributes is a placeholder: it only checks that each submitted
//     attribute is a V3 attribute with a non-empty name (one
//     "missing attribute name" message per offending element).

import (
	"net/http"
	"slices"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/credential/v1"
)

const (
	fgCredential = string(mdl.FUNCTIONGROUPCODE_CREDENTIAL_PROVIDER)
	kindBasic    = "basic"
	kindAPIKey   = "apiKey"

	base = "/v1/credentialProvider"

	// Attribute UUIDs the example's store emits (connector/examples/credential-v1/store.go).
	usernameAttrUUID = "11111111-1111-1111-1111-111111111111"
	passwordAttrUUID = "22222222-2222-2222-2222-222222222222"
	apiKeyAttrUUID   = "33333333-3333-3333-3333-333333333333"

	// Messages the example / provider emit.
	msgKindNotSupported = "credential kind not supported"
	msgMissingName      = "missing attribute name"
)

func attrsPath(kind string) string    { return base + "/" + kind + "/attributes" }
func validatePath(kind string) string { return attrsPath(kind) + "/validate" }

// startCredential launches the credential-v1 example container with the given
// extra environment and returns the harness.
func startCredential(t *testing.T, env map[string]string) *itest.Harness {
	t.Helper()
	return itest.Start(t, itest.Example{
		Path:       "connector/examples/credential-v1",
		Env:        env,
		HealthPath: "/v1/health",
	})
}

// stringAttr builds a V3 string RequestAttribute (same construction as the
// secret-v1 test) — the only shape the example's validator inspects.
func stringAttr(uuid, name, value string) mdl.RequestAttribute {
	content := mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.StringAttributeContentV3{
		Data:        value,
		ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
	})
	return mdl.RequestAttributeV3AsRequestAttribute(&mdl.RequestAttributeV3{
		Uuid:        uuid,
		Name:        name,
		ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
		Version:     mdl.ATTRIBUTEVERSION_V3,
		Content:     []mdl.BaseAttributeContentDtoV3{content},
	})
}

// dataAttrs decodes an attribute-list response through the generated oneOf
// wrappers and returns the V3 data attributes, failing on any other shape.
func dataAttrs(t *testing.T, resp itest.Response) []mdl.DataAttributeV3 {
	t.Helper()
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow() // avoid decoding an error envelope into the success DTO
	}
	var list []mdl.BaseAttributeDto
	resp.JSON(t, &list) // Fatalf on decode error: this is the model<->example seam
	out := make([]mdl.DataAttributeV3, 0, len(list))
	for i, a := range list {
		if a.BaseAttributeDtoV3 == nil || a.BaseAttributeDtoV3.DataAttributeV3 == nil {
			t.Fatalf("attribute %d is not a V3 data attribute: %s", i, resp.Body)
		}
		out = append(out, *a.BaseAttributeDtoV3.DataAttributeV3)
	}
	return out
}

// attrName is the itest.Find key for attributes (the list order is an
// implementation detail, so never index into it).
func attrName(a mdl.DataAttributeV3) string { return a.Name }

// --- /v1 info + health -----------------------------------------------------

func TestCredentialV1InfoAndHealth(t *testing.T) {
	h := startCredential(t, nil)

	// Status "ok" plus parts.liveness/readiness "ok" (itest v1 branch).
	h.AssertHealthy(t, "/v1/health")

	// The same body through the generated HealthDto (the checkHealth schema):
	// the status enum and the nested parts decode into the spec's types.
	itest.AssertV1HealthDto[mdl.HealthDto, mdl.HealthStatus](t, h)

	// v1-family only: the v2 management surface is not mounted, so the mux
	// answers with its stdlib 404 (text/plain).
	h.AssertNotServed(t, "/v2/health", "/v2/info")

	// Decode into the generated InfoResponse model (the /v1
	// listSupportedFunctions element shape) for a typed functionGroupCode.
	// This is not schema validation: the generated decoder only checks that
	// required keys are present — it accepts null for required strings (shared
	// emits "uuid": null on every endpoint although the spec declares a
	// non-nullable string) and keeps unknown keys in AdditionalProperties. The
	// explicit assertions below carry the contract.
	var groups []mdl.InfoResponse
	if status := h.GetJSON(t, http.MethodGet, "/v1", nil, &groups); status != http.StatusOK {
		t.Fatalf("GET /v1 = %d, want 200", status)
	}
	if len(groups) != 1 {
		t.Fatalf("/v1 returned %d function groups, want 1: %+v", len(groups), groups)
	}
	cred := groups[0]
	if string(cred.FunctionGroupCode) != fgCredential {
		t.Errorf("function group code = %q, want %q", cred.FunctionGroupCode, fgCredential)
	}

	// Default CREDENTIAL_KIND, in configured order (main.go).
	if want := []string{kindBasic, kindAPIKey}; !slices.Equal(cred.Kinds, want) {
		t.Errorf("%s kinds = %v, want %v", fgCredential, cred.Kinds, want)
	}

	// The provider's two routes (FunctionGroup()) plus the shared checkHealth +
	// listSupportedFunctions extras wired in via WithExtraEndpoints. Exact
	// count: a handler advertising an endpoint it does not mount (or vice
	// versa) is caught here. Names are the credential.json operationIds.
	itest.AssertEndpoints(t, fgCredential, cred.EndPoints, []itest.Endpoint{
		{Name: "listSupportedFunctions", Method: http.MethodGet, Context: "/v1"}, // extra
		{Name: "checkHealth", Method: http.MethodGet, Context: "/v1/health"},     // extra
		{Name: "listAttributeDefinitions", Method: http.MethodGet, Context: base + "/{kind}/attributes"},
		{Name: "validateAttributes", Method: http.MethodPost, Context: base + "/{kind}/attributes/validate"},
	})

	// The shared metrics middleware labels by matched mux pattern; build info
	// comes from the example's BuildInfo.
	h.AssertMetric(t, `app_build_info{commit="dev"`)
	h.AssertMetric(t, `http_requests_total{method="GET",route="/v1/health",status="200"}`)

	h.AssertLogsConform(t)
}

// --- attribute schemas -----------------------------------------------------

// TestCredentialV1AttributeSchemas is the drift test for the model <-> example
// seam: the example's attribute list must decode through the SDK's own
// generated BaseAttributeDto -> BaseAttributeDtoV3 -> DataAttributeV3 chain.
func TestCredentialV1AttributeSchemas(t *testing.T) {
	h := startCredential(t, nil)

	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: attrsPath(kindBasic)})
	attrs := dataAttrs(t, resp)
	if len(attrs) != 2 {
		t.Fatalf("basic kind returned %d attributes, want 2: %s", len(attrs), resp.Body)
	}
	for _, want := range []struct{ name, uuid, label string }{
		{"username", usernameAttrUUID, "Username"},
		{"password", passwordAttrUUID, "Password"},
	} {
		a, ok := itest.Find(attrs, attrName, want.name)
		if !ok {
			t.Fatalf("attribute %q not found in %+v", want.name, attrs)
		}
		if a.Uuid != want.uuid {
			t.Errorf("%s uuid = %q, want %q", want.name, a.Uuid, want.uuid)
		}
		if a.Type != mdl.ATTRIBUTETYPE_DATA {
			t.Errorf("%s type = %q, want %q", want.name, a.Type, mdl.ATTRIBUTETYPE_DATA)
		}
		if a.ContentType != mdl.ATTRIBUTECONTENTTYPE_STRING {
			t.Errorf("%s contentType = %q, want %q", want.name, a.ContentType, mdl.ATTRIBUTECONTENTTYPE_STRING)
		}
		// The discriminators the generated oneOf decoders dispatch on
		// (tools/fixoneof/main.go): a V3 attribute must say so.
		if a.SchemaVersion != mdl.ATTRIBUTEVERSION_V3 {
			t.Errorf("%s schemaVersion = %q, want %q", want.name, a.SchemaVersion, mdl.ATTRIBUTEVERSION_V3)
		}
		if a.Version != 3 {
			t.Errorf("%s version = %d, want 3", want.name, a.Version)
		}
		if !a.Properties.Required || !a.Properties.Visible {
			t.Errorf("%s properties = %+v, want required and visible", want.name, a.Properties)
		}
		if a.Properties.Label != want.label {
			t.Errorf("%s label = %q, want %q", want.name, a.Properties.Label, want.label)
		}
		if a.Description == nil {
			t.Errorf("%s description is nil, want the label", want.name)
		}
	}

	// Raw wire check: documents why the discriminators matter — BaseAttributeDto
	// dispatches on the numeric "version", DataAttributeV3 requires the string
	// "schemaVersion" enum.
	var raw []map[string]any
	resp.JSON(t, &raw)
	for i, m := range raw {
		if m["version"] != float64(3) {
			t.Errorf("attribute %d wire version = %v, want 3: %s", i, m["version"], resp.Body)
		}
		if m["schemaVersion"] != "v3" {
			t.Errorf("attribute %d wire schemaVersion = %v, want \"v3\": %s", i, m["schemaVersion"], resp.Body)
		}
	}

	// apiKey kind: a single required attribute.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: attrsPath(kindAPIKey)})
	attrs = dataAttrs(t, resp)
	if len(attrs) != 1 {
		t.Fatalf("apiKey kind returned %d attributes, want 1: %s", len(attrs), resp.Body)
	}
	if a := attrs[0]; a.Name != "apiKey" || a.Uuid != apiKeyAttrUUID || !a.Properties.Required {
		t.Errorf("apiKey attribute = %+v, want required apiKey/%s", a, apiKeyAttrUUID)
	}

	// Unknown kind -> 404 with the provider's sentinel message.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: attrsPath("ldap")})
	if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgKindNotSupported {
		t.Errorf("unknown-kind message = %q, want %q", msg, msgKindNotSupported)
	}

	// Event names come from provider routes.go; the route label is the matched
	// mux pattern.
	h.AssertMetric(t, `connector_events_total{event="list_attributes",outcome="ok"}`)
	h.AssertMetric(t, `connector_events_total{event="list_attributes",outcome="error"}`)
	h.AssertMetric(t, `http_requests_total{method="GET",route="`+base+`/{kind}/attributes",status="404"}`)
}

// --- validate attributes ---------------------------------------------------

func TestCredentialV1ValidateAttributes(t *testing.T) {
	h := startCredential(t, nil)

	// Valid sets -> 200 with an empty body (no content to return).
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: validatePath(kindBasic), Body: []mdl.RequestAttribute{
		stringAttr(usernameAttrUUID, "username", "alice"),
		stringAttr(passwordAttrUUID, "password", "s3cret"),
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
	if len(resp.Body) != 0 {
		t.Errorf("valid basic validate returned a body, want empty: %s", resp.Body)
	}

	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: validatePath(kindAPIKey), Body: []mdl.RequestAttribute{
		stringAttr(apiKeyAttrUUID, "apiKey", "k-1"),
	}})
	itest.AssertStatus(t, resp, http.StatusOK)

	// Empty list: nothing to validate.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: validatePath(kindBasic), Body: []mdl.RequestAttribute{}})
	itest.AssertStatus(t, resp, http.StatusOK)

	// One nameless attribute -> 422 with exactly the placeholder message
	// (store.go ValidateAttributes), rendered as a bare []string.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: validatePath(kindBasic), Body: []mdl.RequestAttribute{
		stringAttr(usernameAttrUUID, "", "alice"),
	}})
	if msgs := itest.AssertV1ValidationErrors(t, resp); msgs != nil && !slices.Equal(msgs, []string{msgMissingName}) {
		t.Errorf("422 messages = %v, want [%q]", msgs, msgMissingName)
	}

	// Two nameless attributes -> one message per offending element.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: validatePath(kindBasic), Body: []mdl.RequestAttribute{
		stringAttr(usernameAttrUUID, "", "alice"),
		stringAttr(passwordAttrUUID, "", "s3cret"),
	}})
	if msgs := itest.AssertV1ValidationErrors(t, resp); msgs != nil && !slices.Equal(msgs, []string{msgMissingName, msgMissingName}) {
		t.Errorf("422 messages = %v, want [%q %q] (one per bad element)", msgs, msgMissingName, msgMissingName)
	}

	// Unknown kind with an otherwise valid attribute -> 404, and the strict
	// v1 envelope: exactly {"message"} as application/json. The correlation id
	// must be echoed and land on the matching log line.
	const corrID = "credential-404"
	resp = h.Do(t, itest.Request{
		Method:  http.MethodPost,
		Path:    validatePath("ldap"),
		Body:    []mdl.RequestAttribute{stringAttr(usernameAttrUUID, "username", "alice")},
		Headers: map[string]string{"Correlation-Id": corrID},
	})
	if msg := itest.AssertV1MessageEnvelope(t, resp, http.StatusNotFound); msg != msgKindNotSupported {
		t.Errorf("unknown-kind message = %q, want %q", msg, msgKindNotSupported)
	}
	if got := resp.Header.Get("Correlation-Id"); got != corrID {
		t.Errorf("Correlation-Id echoed = %q, want %q", got, corrID)
	}

	// Malformed / ill-typed bodies. Wrong JSON type for the list -> 422 (the
	// codec's UnmarshalTypeError branch), still a []string.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: validatePath(kindBasic), Body: map[string]any{}})
	itest.AssertV1ValidationErrors(t, resp)

	// Syntactically broken JSON -> 400.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: validatePath(kindBasic), RawBody: []byte("[")})
	itest.AssertV1Error(t, resp, http.StatusBadRequest)

	// No body at all -> 400 EMPTY_BODY.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: validatePath(kindBasic)})
	itest.AssertV1Error(t, resp, http.StatusBadRequest)

	// An attribute whose "version" discriminator matches no RequestAttribute
	// variant is rejected by the generated oneOf decoder -> 400 INVALID_JSON.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: validatePath(kindBasic), Body: []map[string]any{
		{"version": "v9", "uuid": "u", "name": "n", "contentType": "string"},
	}})
	itest.AssertV1Error(t, resp, http.StatusBadRequest)

	// Rejected requests log "request rejected" with the sentinel's code,
	// carrying the correlation id of the request that caused it.
	h.AssertLogged(t, "request rejected", map[string]any{"error_code": "KIND_NOT_FOUND", "status": 404, "correlation_id": corrID})
	h.AssertLogged(t, "request completed", map[string]any{"method": "POST", "path": validatePath(kindBasic), "status": 422})

	h.AssertMetric(t, `connector_events_total{event="validate_attributes",outcome="ok"}`)
	h.AssertMetric(t, `connector_events_total{event="validate_attributes",outcome="error"}`)
}

// --- kinds from env --------------------------------------------------------

func TestCredentialV1KindsFromEnv(t *testing.T) {
	h := startCredential(t, map[string]string{"CREDENTIAL_KIND": kindAPIKey})

	var groups []mdl.InfoResponse
	if status := h.GetJSON(t, http.MethodGet, "/v1", nil, &groups); status != http.StatusOK {
		t.Fatalf("GET /v1 = %d, want 200", status)
	}
	if len(groups) != 1 {
		t.Fatalf("/v1 returned %d function groups, want 1: %+v", len(groups), groups)
	}
	if want := []string{kindAPIKey}; !slices.Equal(groups[0].Kinds, want) {
		t.Errorf("%s kinds = %v, want %v", fgCredential, groups[0].Kinds, want)
	}

	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: attrsPath(kindAPIKey)})
	if attrs := dataAttrs(t, resp); len(attrs) != 1 {
		t.Errorf("apiKey kind returned %d attributes, want 1: %s", len(attrs), resp.Body)
	}

	// Pins current SDK behaviour: CREDENTIAL_KIND only drives the /v1
	// advertisement. Routes are wildcard (provider handler.go Mount) and the
	// example's store is not gated by the configured kinds, so basic is still
	// served although it is no longer advertised.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: attrsPath(kindBasic)})
	if attrs := dataAttrs(t, resp); len(attrs) != 2 {
		t.Errorf("basic kind returned %d attributes, want 2: %s", len(attrs), resp.Body)
	}
}
