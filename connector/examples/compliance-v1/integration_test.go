package main_test

// Integration tests for the compliance-v1 example (hard-coded rule/group
// store), driven over the public HTTP interface via the shared testcontainers
// harness. Requests/responses use the generated connector/model/compliance/v1
// types. Skips with no Docker or under -short.
//
// compliance-v1 is a v1-family connector: info at GET /v1, health at
// GET /v1/health, v1 ErrorMessageDto envelope (422 as a bare []string) — so
// error paths use itest.AssertV1Error / AssertV1ValidationErrors, never
// AssertProblem. The v2 management surface (GET /v2/info, GET /v2/health) is
// not mounted and 404s at the mux.
//
// The example wires the provider with COMPLIANCE_KIND (default "default") as
// an advertisement-only list: the {kind} routes are wildcards, and kind gating
// lives in the example's store (unknown kind -> 404 "compliance kind not
// supported"). The store seeds, for kind "default", two X.509 rules —
// rsa-min-2048 (no group) and valid-for-max-1y (in the "baseline" group) — and
// one group. The store is also the KindAttributeProvider: every backed kind
// has one required V3 string data attribute ("profile"), and validation
// rejects a request without it with a semantic 422.
//
// CheckCompliance is placeholder logic: overall status is always "ok"; each
// requested rule is "ok" with its stored name, or "<unknown>" + "na" when the
// uuid is not in the kind's rule set. The tests assert that wiring, not any
// real certificate evaluation.

import (
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/compliance/v1"
)

const (
	fgCompliance   = string(mdl.FUNCTIONGROUPCODE_COMPLIANCE_PROVIDER) // "complianceProvider"
	complianceKind = "default"                                         // example default (COMPLIANCE_KIND)

	base            = "/v1/complianceProvider"
	kindBase        = base + "/" + complianceKind
	profileAttrUUID = "44444444-4444-4444-4444-444444444444" // complianceattr.ProfileUUID
	profileAttrName = "profile"

	rule1UUID   = "11111111-1111-1111-1111-111111111111" // rsa-min-2048 (no group)
	rule2UUID   = "22222222-2222-2222-2222-222222222222" // valid-for-max-1y (in group)
	groupUUID   = "33333333-3333-3333-3333-333333333333" // baseline
	unknownUUID = "00000000-0000-0000-0000-000000000000"

	msgKindNotFound   = "compliance kind not supported"
	msgGroupNotFound  = "compliance group not found"
	msgMissingProfile = "missing required attribute profile" // complianceattr.MsgMissingProfile
)

// sampleCert is an opaque base64 payload: the placeholder CheckCompliance never
// inspects the certificate, it only requires the field to be present.
var sampleCert = base64.StdEncoding.EncodeToString([]byte("placeholder-cert"))

func startCompliance(t *testing.T, env map[string]string) *itest.Harness {
	t.Helper()
	return itest.Start(t, itest.Example{
		Path:       "connector/examples/compliance-v1",
		HealthPath: "/v1/health",
		Env:        env,
	})
}

// profileReq builds the V3 string request attribute the store's validator
// looks for (same construction as the credential-v1 test).
func profileReq(value string) mdl.RequestAttribute {
	content := mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.StringAttributeContentV3{
		Data:        value,
		ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
	})
	return mdl.RequestAttributeV3AsRequestAttribute(&mdl.RequestAttributeV3{
		Uuid:        profileAttrUUID,
		Name:        profileAttrName,
		ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
		Version:     mdl.ATTRIBUTEVERSION_V3,
		Content:     []mdl.BaseAttributeContentDtoV3{content},
	})
}

// ruleUUID is the itest.Find key for rules: the store keeps rules in a slice
// but the assertions never rely on order.
func ruleUUID(r mdl.ComplianceRulesResponseDto) string { return r.Uuid }

// --- /v1 info + health -----------------------------------------------------

func TestComplianceV1InfoAndHealth(t *testing.T) {
	h := startCompliance(t, nil)

	// Status "ok" plus parts.liveness/readiness "ok" (itest v1 branch).
	h.AssertHealthy(t, "/v1/health")

	// The same body through the generated HealthDto (the checkHealth schema):
	// the status enum and the nested parts decode into the spec's types.
	itest.AssertV1HealthDto[mdl.HealthDto, mdl.HealthStatus](t, h)

	// A v1-family connector mounts no v2 management surface; these are
	// unmatched mux paths (stdlib text/plain 404).
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
		t.Fatalf("/v1 returned %d function groups, want exactly 1: %+v", len(groups), groups)
	}
	g := groups[0]
	if string(g.FunctionGroupCode) != fgCompliance {
		t.Errorf("functionGroupCode = %q, want %q", g.FunctionGroupCode, fgCompliance)
	}
	if want := []string{complianceKind}; !slices.Equal(g.Kinds, want) {
		t.Errorf("%s kinds = %v, want %v", fgCompliance, g.Kinds, want)
	}

	// Assert the full advertised endpoint set: the provider's six own routes
	// (FunctionGroup()) plus the shared checkHealth + listSupportedFunctions
	// wired via WithExtraEndpoints. {kind}/{uuid} are the literal template
	// tokens the function group publishes; names are the compliance-v1.json
	// operationIds.
	itest.AssertEndpoints(t, fgCompliance, g.EndPoints, []itest.Endpoint{
		{Name: "listSupportedFunctions", Method: http.MethodGet, Context: "/v1"}, // extra
		{Name: "checkHealth", Method: http.MethodGet, Context: "/v1/health"},     // extra
		{Name: "listAttributeDefinitions", Method: http.MethodGet, Context: base + "/{kind}/attributes"},
		{Name: "validateAttributes", Method: http.MethodPost, Context: base + "/{kind}/attributes/validate"},
		{Name: "getRules", Method: http.MethodGet, Context: base + "/{kind}/rules"},
		{Name: "getGroups", Method: http.MethodGet, Context: base + "/{kind}/groups"},
		{Name: "getGroupRules", Method: http.MethodGet, Context: base + "/{kind}/groups/{uuid}"},
		{Name: "checkCompliance", Method: http.MethodPost, Context: base + "/{kind}/compliance"},
	})

	// v1-vs-v2 distinction: the v2 provider mounts under /v2/complianceProvider
	// (its group code is pinned out by the functionGroupCode check above). No
	// v2 context may leak here.
	for _, e := range g.EndPoints {
		if strings.Contains(e.Context, "/v2/") {
			t.Errorf("endpoint %s %s is v2-shaped; compliance-v1 must advertise only v1 contexts", e.Method, e.Context)
		}
	}

	h.AssertMetric(t, `app_build_info{commit="dev",runtime="go`)
	h.AssertMetric(t, `http_requests_total{method="GET",route="/v1/health",status="200"}`)
	h.AssertLogsConform(t)
}

// --- rules and groups ------------------------------------------------------

func TestComplianceV1RulesAndGroups(t *testing.T) {
	h := startCompliance(t, nil)

	// Rules: both seeded rules, matched by uuid (never by index).
	rulesResp := h.Do(t, itest.Request{Method: http.MethodGet, Path: kindBase + "/rules"})
	if !itest.AssertStatus(t, rulesResp, http.StatusOK) {
		t.FailNow() // avoid decoding an error envelope into the success DTO
	}
	var rules []mdl.ComplianceRulesResponseDto
	rulesResp.JSON(t, &rules)
	if len(rules) != 2 {
		t.Fatalf("GET %s/rules returned %d rules, want 2\nbody: %s", kindBase, len(rules), rulesResp.Body)
	}
	rule1, ok := itest.Find(rules, ruleUUID, rule1UUID)
	if !ok {
		t.Fatalf("rules missing %s\nbody: %s", rule1UUID, rulesResp.Body)
	}
	if rule1.Name != "rsa-min-2048" {
		t.Errorf("rule1 name = %q, want rsa-min-2048", rule1.Name)
	}
	// CertificateType is compared through the model constant, so this pins
	// the example/model agreement only; a literal drift applied to the model
	// on both the encode and decode side would still pass.
	if rule1.CertificateType != mdl.CERTIFICATETYPE_X_509 {
		t.Errorf("rule1 certificateType = %q, want %q", rule1.CertificateType, mdl.CERTIFICATETYPE_X_509)
	}
	// groupUuid is an optional pointer: rule1 has no group, so it is absent.
	if rule1.GroupUuid != nil {
		t.Errorf("rule1 groupUuid = %q, want absent", *rule1.GroupUuid)
	}
	if rule1.Description == nil {
		t.Errorf("rule1 description is absent, want present\nbody: %s", rulesResp.Body)
	}
	rule2, ok := itest.Find(rules, ruleUUID, rule2UUID)
	if !ok {
		t.Fatalf("rules missing %s\nbody: %s", rule2UUID, rulesResp.Body)
	}
	if rule2.Name != "valid-for-max-1y" {
		t.Errorf("rule2 name = %q, want valid-for-max-1y", rule2.Name)
	}
	if rule2.GroupUuid == nil || *rule2.GroupUuid != groupUUID {
		t.Errorf("rule2 groupUuid = %v, want %q\nbody: %s", rule2.GroupUuid, groupUUID, rulesResp.Body)
	}

	// Groups: exactly the seeded "baseline" group.
	groupsResp := h.Do(t, itest.Request{Method: http.MethodGet, Path: kindBase + "/groups"})
	if !itest.AssertStatus(t, groupsResp, http.StatusOK) {
		t.FailNow()
	}
	var groups []mdl.ComplianceGroupsResponseDto
	groupsResp.JSON(t, &groups)
	if len(groups) != 1 {
		t.Fatalf("GET %s/groups returned %d groups, want 1\nbody: %s", kindBase, len(groups), groupsResp.Body)
	}
	if groups[0].Uuid != groupUUID || groups[0].Name != "baseline" || groups[0].Description == nil {
		t.Errorf("group = %+v, want uuid %s, name baseline, description present\nbody: %s", groups[0], groupUUID, groupsResp.Body)
	}

	// Group rules: only rule2 belongs to the baseline group.
	grResp := h.Do(t, itest.Request{Method: http.MethodGet, Path: kindBase + "/groups/" + groupUUID})
	if !itest.AssertStatus(t, grResp, http.StatusOK) {
		t.FailNow()
	}
	var groupRules []mdl.ComplianceRulesResponseDto
	grResp.JSON(t, &groupRules)
	if len(groupRules) != 1 || groupRules[0].Uuid != rule2UUID {
		t.Errorf("group rules = %+v, want exactly [rule2 %s]\nbody: %s", groupRules, rule2UUID, grResp.Body)
	}

	// Unknown group -> 404 with the provider's sentinel message
	// (ErrGroupNotFound in provider/compliance/v1/errors.go).
	unknownGroup := h.Do(t, itest.Request{Method: http.MethodGet, Path: kindBase + "/groups/" + unknownUUID})
	if msg := itest.AssertV1Error(t, unknownGroup, http.StatusNotFound); msg != msgGroupNotFound {
		t.Errorf("unknown group message = %q, want %q", msg, msgGroupNotFound)
	}

	// Unknown kind -> 404 on every kind-scoped read; the {kind} route is a
	// wildcard, the store does the gating (ErrKindNotFound).
	for _, path := range []string{
		base + "/nokind/rules",
		base + "/nokind/groups",
		base + "/nokind/groups/" + groupUUID,
	} {
		resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: path})
		if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgKindNotFound {
			t.Errorf("GET %s message = %q, want %q", path, msg, msgKindNotFound)
		}
	}

	// connector_events_total: get_group_rules recorded an error (unknown group
	// and unknown kind), get_rules/get_groups at least one success each.
	h.AssertMetric(t, `connector_events_total{event="get_rules",outcome="ok"}`)
	h.AssertMetric(t, `connector_events_total{event="get_groups",outcome="ok"}`)
	h.AssertMetric(t, `connector_events_total{event="get_group_rules",outcome="error"}`)

	// Rendered errors are logged by shared.WriteV1Error with the sentinel code.
	h.AssertLogged(t, "request rejected", map[string]any{"error_code": "GROUP_NOT_FOUND", "status": 404})
}

// --- check compliance ------------------------------------------------------

func TestComplianceV1CheckCompliance(t *testing.T) {
	h := startCompliance(t, nil)
	path := kindBase + "/compliance"

	// One known rule + one unknown rule. Note v1's per-rule status enum is
	// "ok|nok|na" (COMPLIANCERULESTATUS_NA); v2 renames the last to
	// "not_available".
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: path, Body: mdl.ComplianceRequestDto{
		Certificate: sampleCert,
		Rules:       []mdl.ComplianceRequestRulesDto{{Uuid: rule1UUID}, {Uuid: unknownUUID}},
	}})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var out mdl.ComplianceResponseDto
	resp.JSON(t, &out)
	if out.Status != mdl.COMPLIANCESTATUS_OK {
		t.Errorf("status = %q, want %q\nbody: %s", out.Status, mdl.COMPLIANCESTATUS_OK, resp.Body)
	}
	if len(out.Rules) != 2 {
		t.Fatalf("rules = %d entries, want 2\nbody: %s", len(out.Rules), resp.Body)
	}
	// Each requested rule exactly once: a duplicated result (and a dropped
	// one) must fail, so track what was seen.
	seen := map[string]int{}
	for _, r := range out.Rules {
		seen[r.Uuid]++
		switch r.Uuid {
		case rule1UUID:
			if r.Name != "rsa-min-2048" || r.Status != mdl.COMPLIANCERULESTATUS_OK {
				t.Errorf("known rule = %+v, want name rsa-min-2048 status %q", r, mdl.COMPLIANCERULESTATUS_OK)
			}
		case unknownUUID:
			if r.Name != "<unknown>" || r.Status != mdl.COMPLIANCERULESTATUS_NA {
				t.Errorf("unknown rule = %+v, want name <unknown> status %q", r, mdl.COMPLIANCERULESTATUS_NA)
			}
		default:
			t.Errorf("unexpected rule uuid %q in response\nbody: %s", r.Uuid, resp.Body)
		}
	}
	for _, u := range []string{rule1UUID, unknownUUID} {
		if seen[u] != 1 {
			t.Errorf("rule %s appears %d times in the results, want exactly once\nbody: %s", u, seen[u], resp.Body)
		}
	}

	// No rules requested: still 200/ok. v1 `rules` is omitempty, so an empty
	// result is absent on the wire — assert the length, not non-nil.
	noRules := h.Do(t, itest.Request{Method: http.MethodPost, Path: path, Body: mdl.ComplianceRequestDto{Certificate: sampleCert}})
	if !itest.AssertStatus(t, noRules, http.StatusOK) {
		t.FailNow()
	}
	var empty mdl.ComplianceResponseDto
	noRules.JSON(t, &empty)
	if empty.Status != mdl.COMPLIANCESTATUS_OK || len(empty.Rules) != 0 {
		t.Errorf("no-rules response = %+v, want status ok and 0 rules\nbody: %s", empty, noRules.Body)
	}

	// certificate is a required property of ComplianceRequestDto: its absence
	// and a wrong JSON type both surface as v1 422 []string
	// (shared/codec.go -> WriteV1Error).
	missing := h.Do(t, itest.Request{Method: http.MethodPost, Path: path, Body: map[string]any{"rules": []any{}}})
	itest.AssertV1ValidationErrors(t, missing)
	wrongType := h.Do(t, itest.Request{Method: http.MethodPost, Path: path, Body: map[string]any{"certificate": 5}})
	itest.AssertV1ValidationErrors(t, wrongType)

	// Malformed JSON -> 400 with the strict {"message"} envelope; pinned once
	// here, the other error paths use AssertV1Error.
	malformed := h.Do(t, itest.Request{Method: http.MethodPost, Path: path, RawBody: []byte("{")})
	itest.AssertV1MessageEnvelope(t, malformed, http.StatusBadRequest)

	// No body at all -> 400 EMPTY_BODY.
	noBody := h.Do(t, itest.Request{Method: http.MethodPost, Path: path})
	itest.AssertV1Error(t, noBody, http.StatusBadRequest)

	// Unknown kind -> 404; the Correlation-Id header must be echoed into the
	// log line of the rejected request.
	const corrID = "compliance-v1-404"
	unknownKind := h.Do(t, itest.Request{
		Method:  http.MethodPost,
		Path:    base + "/nokind/compliance",
		Body:    mdl.ComplianceRequestDto{Certificate: sampleCert},
		Headers: map[string]string{"Correlation-Id": corrID},
	})
	if msg := itest.AssertV1Error(t, unknownKind, http.StatusNotFound); msg != msgKindNotFound {
		t.Errorf("unknown kind message = %q, want %q", msg, msgKindNotFound)
	}

	h.AssertMetric(t, `connector_events_total{event="check_compliance",outcome="ok"}`)
	h.AssertMetric(t, `connector_events_total{event="check_compliance",outcome="error"}`)
	h.AssertMetric(t, `http_requests_total{method="POST",route="/v1/complianceProvider/{kind}/compliance",status="200"}`)

	h.AssertLogged(t, "request rejected", map[string]any{"error_code": "KIND_NOT_FOUND", "status": 404, "correlation_id": corrID})
}

// --- kind attributes -------------------------------------------------------

func TestComplianceV1Attributes(t *testing.T) {
	h := startCompliance(t, nil)

	// The per-kind schema (store.go Attributes): exactly one required V3
	// string data attribute, decoded through the generated BaseAttributeDto ->
	// BaseAttributeDtoV3 -> DataAttributeV3 oneOf chain (tools/fixoneof), which
	// dispatches on the numeric version and requires schemaVersion.
	list := h.Do(t, itest.Request{Method: http.MethodGet, Path: kindBase + "/attributes"})
	if !itest.AssertStatus(t, list, http.StatusOK) {
		t.FailNow()
	}
	var attrs []mdl.BaseAttributeDto
	list.JSON(t, &attrs)
	if len(attrs) != 1 || attrs[0].BaseAttributeDtoV3 == nil || attrs[0].BaseAttributeDtoV3.DataAttributeV3 == nil {
		t.Fatalf("attributes = %s, want exactly one V3 data attribute", list.Body)
	}
	a := attrs[0].BaseAttributeDtoV3.DataAttributeV3
	if a.Uuid != profileAttrUUID || a.Name != profileAttrName || a.Type != mdl.ATTRIBUTETYPE_DATA ||
		a.ContentType != mdl.ATTRIBUTECONTENTTYPE_STRING || !a.Properties.Required {
		t.Errorf("attribute = uuid %q name %q type %q contentType %q required %v, want %s %s data string true\nbody: %s",
			a.Uuid, a.Name, a.Type, a.ContentType, a.Properties.Required, profileAttrUUID, profileAttrName, list.Body)
	}

	// Valid input: the required attribute is present -> 200, empty body.
	validate := kindBase + "/attributes/validate"
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: validate, Body: []mdl.RequestAttribute{profileReq("strict")}})
	if itest.AssertStatus(t, resp, http.StatusOK) && len(resp.Body) != 0 {
		t.Errorf("valid validate body = %q, want empty", resp.Body)
	}

	// Invalid input: the required attribute is missing -> semantic 422
	// (shared.WriteV1ValidationErrors) with exactly the store's message.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: validate, Body: []mdl.RequestAttribute{}})
	if msgs := itest.AssertV1ValidationErrors(t, resp); msgs != nil && !slices.Equal(msgs, []string{msgMissingProfile}) {
		t.Errorf("missing profile 422 = %v, want [%q]", msgs, msgMissingProfile)
	}

	// The body must be an array of attributes: a JSON object is a wrong-type
	// decode failure -> v1 422 []string.
	wrongShape := h.Do(t, itest.Request{Method: http.MethodPost, Path: validate, Body: map[string]any{}})
	itest.AssertV1ValidationErrors(t, wrongShape)

	// The attribute routes are wildcard {kind} routes
	// (provider/compliance/v1/handler.go); kind gating lives in the store, so
	// an unbacked kind is 404 on both.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: base + "/anything/attributes"})
	if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgKindNotFound {
		t.Errorf("attributes for unbacked kind message = %q, want %q", msg, msgKindNotFound)
	}
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: base + "/anything/attributes/validate", Body: []mdl.RequestAttribute{profileReq("strict")}})
	if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgKindNotFound {
		t.Errorf("validate for unbacked kind message = %q, want %q", msg, msgKindNotFound)
	}
}

// --- COMPLIANCE_KIND configuration ----------------------------------------

func TestComplianceV1KindsFromEnv(t *testing.T) {
	h := startCompliance(t, map[string]string{"COMPLIANCE_KIND": "default,strict"})

	var groups []mdl.InfoResponse
	if status := h.GetJSON(t, http.MethodGet, "/v1", nil, &groups); status != http.StatusOK {
		t.Fatalf("GET /v1 = %d, want 200", status)
	}
	if len(groups) != 1 {
		t.Fatalf("/v1 returned %d function groups, want exactly 1: %+v", len(groups), groups)
	}
	if want := []string{"default", "strict"}; !slices.Equal(groups[0].Kinds, want) {
		t.Errorf("kinds = %v, want %v", groups[0].Kinds, want)
	}

	// Advertised-only: COMPLIANCE_KIND feeds the /v1 listing, but the example
	// store backs only "default". Kind gating lives in the store, not the
	// handler, so an advertised kind without store backing is still a 404.
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: base + "/strict/rules"})
	if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgKindNotFound {
		t.Errorf("advertised-but-unbacked kind message = %q, want %q", msg, msgKindNotFound)
	}
}
