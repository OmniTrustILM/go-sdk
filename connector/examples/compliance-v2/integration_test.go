package main_test

// Integration tests for the compliance-v2 example (Compliance Provider v2
// with a hard-coded rule/group store), driven over the public HTTP interface
// via the shared testcontainers harness. Requests/responses use the generated
// connector/model/compliance/v2 types. Skips with no Docker or under -short.
//
// compliance-v2 is a v1-family connector on the wire. compliance-v2.json
// declares every error as ErrorMessageDto ({"message"}), 422 as a bare
// []string, info as GET /v1 (InfoResponse[]) and health as GET /v1/health
// (HealthDto, ok|nok|unknown); it has no /v2/info, no /v2/health and no
// RFC 9457 ProblemDetail (see provider/compliance/v2/provider.go and
// shared/v1errors.go). Error paths therefore use itest.AssertV1Error and
// friends, never AssertProblem. Issue #28's "RFC 9457 problem bodies" and
// "/v2/info + /v2/health" wording does not match the spec; these tests pin
// the real contract and assert that the /v2 info/health routes are absent.
//
// What is "v2" is the management surface under /v2/complianceProvider:
// rule and group lookup by uuid, the batch lookup (POST .../rules), the
// required `resource` field on rules, the `not_available` rule status, the
// required `data`/`rules`/`groups` check request, and the
// complianceProviderV2 function group code — whose kind attribute endpoints
// live under the literal /v1/complianceProviderV2 path token, while the
// management routes use the /v2/complianceProvider token.
//
// Example quirks the tests rely on (connector/examples/compliance-v2/store.go):
// kind "default" has rule1 (no group) and rule2 (in group "baseline"), both
// with resource "certificates"; GetRulesBatch silently skips unknown uuids;
// CheckCompliance reports unknown rules as "<unknown>" + not_available. The
// store is also the KindAttributeProvider: every backed kind has one required
// V3 string data attribute ("profile"), and validation rejects a request
// without it with a semantic 422.

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/compliance/v2"
)

const (
	fgComplianceV2 = string(mdl.FUNCTIONGROUPCODE_COMPLIANCE_PROVIDER_V2) // "complianceProviderV2"
	complianceKind = "default"                                            // example default (COMPLIANCE_KIND)

	base     = "/v2/complianceProvider" // management routes (path token != group code)
	attrBase = "/v1/" + fgComplianceV2  // kind attribute routes under the literal code
	kindBase = base + "/" + complianceKind
	v1Base   = "/v1/complianceProvider" // compliance-v1's surface; must be absent here

	rule1UUID   = "11111111-1111-1111-1111-111111111111" // rsa-min-2048 (no group)
	rule2UUID   = "22222222-2222-2222-2222-222222222222" // valid-for-max-1y (in group)
	groupUUID   = "33333333-3333-3333-3333-333333333333" // baseline
	unknownUUID = "00000000-0000-0000-0000-000000000000"

	rule1Name = "rsa-min-2048"
	rule2Name = "valid-for-max-1y"

	profileAttrUUID = "44444444-4444-4444-4444-444444444444" // store.go profileAttr
	profileAttrName = "profile"

	// sampleData is base64("placeholder-cert"); the example does not inspect
	// the compliance subject, it only needs the required field present.
	sampleData = "cGxhY2Vob2xkZXItY2VydA=="

	msgRuleNotFound   = "compliance rule not found"          // provider/compliance/v2/errors.go
	msgGroupNotFound  = "compliance group not found"         // provider/compliance/v2/errors.go
	msgKindNotFound   = "compliance kind not supported"      // provider/compliance/v2/errors.go
	msgRequiredField  = "required field is missing"          // shared/codec.go DecodeJSON
	msgMissingProfile = "missing required attribute profile" // store.go ValidateAttributes
)

func startComplianceV2(t *testing.T, env map[string]string) *itest.Harness {
	t.Helper()
	return itest.Start(t, itest.Example{
		Path:       "connector/examples/compliance-v2",
		Env:        env,
		HealthPath: "/v1/health",
	})
}

// hasEndpoint reports whether the function group advertises an endpoint with
// the given name (the spec operationId), method and context, marked
// required=false (the SDK marks no endpoint required; a change must be
// deliberate).
func hasEndpoint(g mdl.InfoResponse, name, method, context string) bool {
	for _, e := range g.EndPoints {
		if e.Name == name && e.Method == method && e.Context == context && !e.Required {
			return true
		}
	}
	return false
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

// findRule returns the rule with the given uuid (store maps are unordered, so
// lists are searched by uuid, never indexed).
func findRule(rules []mdl.ComplianceRuleResponseDto, uuid string) (mdl.ComplianceRuleResponseDto, bool) {
	i := slices.IndexFunc(rules, func(r mdl.ComplianceRuleResponseDto) bool { return r.Uuid == uuid })
	if i < 0 {
		return mdl.ComplianceRuleResponseDto{}, false
	}
	return rules[i], true
}

// ruleUUIDs returns the uuids of rules, for exact-set comparisons in messages.
func ruleUUIDs(rules []mdl.ComplianceRuleResponseDto) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Uuid)
	}
	return out
}

func boolPtr(b bool) *bool { return &b }

// --- /v1 info + health -----------------------------------------------------

func TestComplianceV2InfoAndHealth(t *testing.T) {
	h := startComplianceV2(t, nil)

	// Status "ok" plus parts.liveness/readiness "ok" (itest v1 branch).
	h.AssertHealthy(t, "/v1/health")

	// The same body through the generated HealthDto (the checkHealth schema):
	// the status enum and the nested parts decode into the spec's types.
	healthResp := h.Do(t, itest.Request{Method: http.MethodGet, Path: "/v1/health"})
	if itest.AssertStatus(t, healthResp, http.StatusOK) {
		var health mdl.HealthDto
		healthResp.JSON(t, &health)
		if health.Status != mdl.HEALTHSTATUS_OK || health.Parts["liveness"].Status != mdl.HEALTHSTATUS_OK || health.Parts["readiness"].Status != mdl.HEALTHSTATUS_OK {
			t.Errorf("HealthDto = %+v, want status ok with liveness/readiness parts ok\nbody: %s", health, healthResp.Body)
		}
	}

	// v1-family info/health per compliance-v2.json: the /v2 info and health
	// routes are not mounted, so the stdlib mux answers 404 (text/plain —
	// status only, never the v1 envelope).
	for _, path := range []string{"/v2/health", "/v2/health/liveness", "/v2/info"} {
		resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: path})
		itest.AssertStatus(t, resp, http.StatusNotFound)
	}

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
		t.Fatalf("/v1 has %d function groups, want 1: %+v", len(groups), groups)
	}
	g := groups[0]
	if string(g.FunctionGroupCode) != fgComplianceV2 {
		t.Errorf("functionGroupCode = %q, want %q", g.FunctionGroupCode, fgComplianceV2)
	}
	if !slices.Equal(g.Kinds, []string{complianceKind}) {
		t.Errorf("%s kinds = %v, want [%s]", fgComplianceV2, g.Kinds, complianceKind)
	}

	// The full advertised endpoint set: the provider's 9 routes
	// (handler.go FunctionGroup) plus the 2 extras wired in main.go. Names
	// are the compliance-v2.json operationIds.
	want := []struct{ name, method, context string }{
		{"listSupportedFunctions", http.MethodGet, "/v1"}, // extra
		{"checkHealth", http.MethodGet, "/v1/health"},     // extra
		{"listAttributeDefinitions", http.MethodGet, attrBase + "/{kind}/attributes"},
		{"validateAttributes", http.MethodPost, attrBase + "/{kind}/attributes/validate"},
		{"getRules", http.MethodGet, base + "/{kind}/rules"},
		{"getRulesBatch", http.MethodPost, base + "/{kind}/rules"},
		{"getRule", http.MethodGet, base + "/{kind}/rules/{ruleUuid}"},
		{"getGroups", http.MethodGet, base + "/{kind}/groups"},
		{"getGroup", http.MethodGet, base + "/{kind}/groups/{groupUuid}"},
		{"getGroupRules", http.MethodGet, base + "/{kind}/groups/{groupUuid}/rules"},
		{"checkCompliance", http.MethodPost, base + "/{kind}/compliance"},
	}
	if len(g.EndPoints) != len(want) {
		t.Errorf("%s has %d endPoints, want %d: %+v", fgComplianceV2, len(g.EndPoints), len(want), g.EndPoints)
	}
	for _, w := range want {
		if !hasEndpoint(g, w.name, w.method, w.context) {
			t.Errorf("%s endPoints missing %s %s %s (required=false): %+v", fgComplianceV2, w.name, w.method, w.context, g.EndPoints)
		}
	}

	// v2-vs-v1 distinction: management routes live under the /v2 token, the
	// attribute routes under the literal complianceProviderV2 code, and
	// nothing is advertised on compliance-v1's /v1/complianceProvider surface.
	var attrContexts int
	for _, e := range g.EndPoints {
		switch {
		case e.Context == "/v1" || e.Context == "/v1/health":
			// shared extras
		case strings.HasPrefix(e.Context, attrBase+"/"):
			attrContexts++
		case !strings.HasPrefix(e.Context, base+"/"):
			t.Errorf("endpoint %s %s is neither under %s nor %s", e.Method, e.Context, base, attrBase)
		}
		if strings.HasPrefix(e.Context, v1Base+"/") {
			t.Errorf("endpoint %s %s is on the compliance-v1 surface %s", e.Method, e.Context, v1Base)
		}
	}
	if attrContexts != 2 {
		t.Errorf("%d endpoints under %s, want 2 (attributes + validate): %+v", attrContexts, attrBase, g.EndPoints)
	}

	h.AssertMetric(t, `app_build_info{commit="dev",runtime="go`)
	h.AssertMetric(t, `http_requests_total{method="GET",route="/v1/health",status="200"}`)

	h.AssertLogsConform(t)
}

// --- rules + groups (by kind and by uuid) ----------------------------------

func TestComplianceV2RulesAndGroups(t *testing.T) {
	h := startComplianceV2(t, nil)

	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: kindBase + "/rules"})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var rules []mdl.ComplianceRuleResponseDto
	resp.JSON(t, &rules)
	if len(rules) != 2 {
		t.Fatalf("GET %s/rules returned %d rules, want 2\nbody: %s", kindBase, len(rules), resp.Body)
	}
	// resource is required on v2 rules (absent in v1's ComplianceRulesResponseDto).
	for _, r := range rules {
		if r.Resource != mdl.RESOURCE_CERTIFICATES {
			t.Errorf("rule %s resource = %q, want %q\nbody: %s", r.Uuid, r.Resource, mdl.RESOURCE_CERTIFICATES, resp.Body)
		}
	}
	if r1, ok := findRule(rules, rule1UUID); !ok {
		t.Errorf("rules missing rule1 %s\nbody: %s", rule1UUID, resp.Body)
	} else if r1.Name != rule1Name || r1.GroupUuid != nil || r1.Description == nil {
		t.Errorf("rule1 = name %q, want %q with no groupUuid and a description\nbody: %s", r1.Name, rule1Name, resp.Body)
	}
	if r2, ok := findRule(rules, rule2UUID); !ok {
		t.Errorf("rules missing rule2 %s\nbody: %s", rule2UUID, resp.Body)
	} else if r2.Name != rule2Name || r2.GroupUuid == nil || *r2.GroupUuid != groupUUID {
		t.Errorf("rule2 = name %q, want %q with groupUuid %s\nbody: %s", r2.Name, rule2Name, groupUUID, resp.Body)
	}

	// Single rule by uuid — a v2-only operation.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: kindBase + "/rules/" + rule1UUID})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var rule mdl.ComplianceRuleResponseDto
	resp.JSON(t, &rule)
	if rule.Uuid != rule1UUID || rule.Name != rule1Name || rule.Resource != mdl.RESOURCE_CERTIFICATES {
		t.Errorf("GET rules/%s = uuid %q name %q resource %q, want %s %q %q\nbody: %s",
			rule1UUID, rule.Uuid, rule.Name, rule.Resource, rule1UUID, rule1Name, mdl.RESOURCE_CERTIFICATES, resp.Body)
	}

	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: kindBase + "/rules/" + unknownUUID})
	if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgRuleNotFound {
		t.Errorf("unknown rule message = %q, want %q", msg, msgRuleNotFound)
	}

	// Groups: the v2 group carries an optional resource, set by the example.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: kindBase + "/groups"})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var groups []mdl.ComplianceGroupResponseDto
	resp.JSON(t, &groups)
	if len(groups) != 1 {
		t.Fatalf("GET %s/groups returned %d groups, want 1\nbody: %s", kindBase, len(groups), resp.Body)
	}
	if gr := groups[0]; gr.Uuid != groupUUID || gr.Name != "baseline" || gr.Resource == nil || *gr.Resource != mdl.RESOURCE_CERTIFICATES {
		t.Errorf("group = uuid %q name %q, want %s baseline with resource certificates\nbody: %s", gr.Uuid, gr.Name, groupUUID, resp.Body)
	}

	// Single group by uuid — v2-only (v1's GET groups/{uuid} returns the rules).
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: kindBase + "/groups/" + groupUUID})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var group mdl.ComplianceGroupResponseDto
	resp.JSON(t, &group)
	if group.Uuid != groupUUID || group.Name != "baseline" {
		t.Errorf("GET groups/%s = uuid %q name %q, want %s baseline\nbody: %s", groupUUID, group.Uuid, group.Name, groupUUID, resp.Body)
	}

	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: kindBase + "/groups/" + groupUUID + "/rules"})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var groupRules []mdl.ComplianceRuleResponseDto
	resp.JSON(t, &groupRules)
	if !slices.Equal(ruleUUIDs(groupRules), []string{rule2UUID}) {
		t.Errorf("group %s rules = %v, want exactly [%s]\nbody: %s", groupUUID, ruleUUIDs(groupRules), rule2UUID, resp.Body)
	}

	for _, path := range []string{kindBase + "/groups/" + unknownUUID, kindBase + "/groups/" + unknownUUID + "/rules"} {
		resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: path})
		if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgGroupNotFound {
			t.Errorf("GET %s message = %q, want %q", path, msg, msgGroupNotFound)
		}
	}

	// Unknown kind: the {kind} route matches; the store rejects the kind.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: base + "/nokind/rules"})
	if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgKindNotFound {
		t.Errorf("unknown kind message = %q, want %q", msg, msgKindNotFound)
	}

	h.AssertMetric(t, `connector_events_total{event="get_rule",outcome="ok"}`)
	h.AssertMetric(t, `connector_events_total{event="get_rule",outcome="error"}`)
	h.AssertMetric(t, `connector_events_total{event="get_group",outcome="ok"}`)

	h.AssertLogged(t, "request rejected", map[string]any{"error_code": "RULE_NOT_FOUND", "status": 404})
}

// --- batch rule lookup (v2-only) -------------------------------------------

func TestComplianceV2RulesBatch(t *testing.T) {
	h := startComplianceV2(t, nil)

	// withGroupRules=true inlines each group's rules; unknown uuids are
	// silently skipped (store.go GetRulesBatch), not a 404.
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: kindBase + "/rules", Body: mdl.ComplianceRulesBatchRequestDto{
		RuleUuids:      []string{rule1UUID, unknownUUID},
		GroupUuids:     []string{groupUUID},
		WithGroupRules: boolPtr(true),
	}})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var batch mdl.ComplianceRulesBatchResponseDto
	resp.JSON(t, &batch)
	// rules and groups are both required arrays on ComplianceRulesBatchResponseDto
	// (compliance-v2.json): non-empty here, and pinned as [] (never null)
	// below when nothing is requested.
	if !slices.Equal(ruleUUIDs(batch.Rules), []string{rule1UUID}) {
		t.Errorf("batch rules = %v, want exactly [%s] (unknown skipped)\nbody: %s", ruleUUIDs(batch.Rules), rule1UUID, resp.Body)
	}
	if len(batch.Groups) != 1 || batch.Groups[0].Uuid != groupUUID {
		t.Fatalf("batch groups = %+v, want exactly group %s\nbody: %s", batch.Groups, groupUUID, resp.Body)
	}
	if got := ruleUUIDs(batch.Groups[0].Rules); !slices.Equal(got, []string{rule2UUID}) {
		t.Errorf("batch group rules = %v, want exactly [%s] with withGroupRules=true\nbody: %s", got, rule2UUID, resp.Body)
	}

	// No rule uuids and no withGroupRules: the required top-level rules is
	// still present as [] (never null), and the group's optional,
	// non-nullable rules is not inlined — absent or empty on the wire, never
	// null.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: kindBase + "/rules", Body: mdl.ComplianceRulesBatchRequestDto{
		RuleUuids:  []string{},
		GroupUuids: []string{groupUUID},
	}})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	batch = mdl.ComplianceRulesBatchResponseDto{}
	resp.JSON(t, &batch)
	if batch.Rules == nil || len(batch.Rules) != 0 {
		t.Errorf("batch without rule uuids rules = %v, want [] (required, never null)\nbody: %s", batch.Rules, resp.Body)
	}
	if len(batch.Groups) != 1 || len(batch.Groups[0].Rules) != 0 {
		t.Errorf("batch without withGroupRules = %+v, want one group with no inlined rules\nbody: %s", batch.Groups, resp.Body)
	}
	var raw struct {
		Groups []map[string]any `json:"groups"`
	}
	resp.JSON(t, &raw)
	if len(raw.Groups) == 1 {
		if v, has := raw.Groups[0]["rules"]; has && v == nil {
			t.Errorf("batch group carries \"rules\": null, want the key absent or []\nbody: %s", resp.Body)
		}
	}

	// No group uuids: the required groups is still present as [] (never null).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: kindBase + "/rules", Body: mdl.ComplianceRulesBatchRequestDto{
		RuleUuids:  []string{rule1UUID},
		GroupUuids: []string{},
	}})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	batch = mdl.ComplianceRulesBatchResponseDto{}
	resp.JSON(t, &batch)
	if batch.Groups == nil || len(batch.Groups) != 0 {
		t.Errorf("batch without group uuids groups = %v, want [] (required, never null)\nbody: %s", batch.Groups, resp.Body)
	}

	// ruleUuids is required by the spec. The spec declares no 422 for
	// getRulesBatch; this pins the shared codec, which maps every missing
	// required property to 422 VALIDATION_FAILED (shared/codec.go DecodeJSON).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: kindBase + "/rules", Body: map[string]any{"groupUuids": []any{}}})
	if msgs := itest.AssertV1ValidationErrors(t, resp); msgs != nil && !slices.Equal(msgs, []string{msgRequiredField}) {
		t.Errorf("missing ruleUuids 422 = %v, want [%q]", msgs, msgRequiredField)
	}

	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: base + "/nokind/rules", Body: mdl.ComplianceRulesBatchRequestDto{
		RuleUuids: []string{rule1UUID}, GroupUuids: []string{},
	}})
	if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgKindNotFound {
		t.Errorf("batch unknown kind message = %q, want %q", msg, msgKindNotFound)
	}

	h.AssertMetric(t, `connector_events_total{event="get_rules_batch",outcome="ok"}`)
}

// --- check compliance ------------------------------------------------------

func TestComplianceV2CheckCompliance(t *testing.T) {
	h := startComplianceV2(t, nil)

	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: kindBase + "/compliance", Body: mdl.ComplianceRequestDtoV2{
		Data:   sampleData,
		Rules:  []mdl.ComplianceRuleRequestDto{{Uuid: rule1UUID}, {Uuid: unknownUUID}},
		Groups: []string{},
	}})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var out mdl.ComplianceResponseDtoV2
	resp.JSON(t, &out)
	if out.Status == nil || *out.Status != mdl.COMPLIANCESTATUS_OK {
		t.Errorf("compliance status is not ok\nbody: %s", resp.Body)
	}
	if len(out.Rules) != 2 {
		t.Fatalf("compliance returned %d rules, want 2\nbody: %s", len(out.Rules), resp.Body)
	}
	// Each requested rule exactly once: a duplicated result (and a dropped
	// one) must fail, so track what was seen.
	seen := map[string]int{}
	for _, r := range out.Rules {
		seen[r.Uuid]++
		switch r.Uuid {
		case rule1UUID:
			if r.Name != rule1Name || r.Status != mdl.COMPLIANCERULESTATUS_OK {
				t.Errorf("rule1 result = %q/%q, want %q/ok\nbody: %s", r.Name, r.Status, rule1Name, resp.Body)
			}
		case unknownUUID:
			// v2 reports an unknown rule as not_available; compliance-v1's
			// example uses na for the same case.
			if r.Name != "<unknown>" || r.Status != mdl.COMPLIANCERULESTATUS_NOT_AVAILABLE {
				t.Errorf("unknown rule result = %q/%q, want <unknown>/not_available\nbody: %s", r.Name, r.Status, resp.Body)
			}
		default:
			t.Errorf("unexpected rule result %s\nbody: %s", r.Uuid, resp.Body)
		}
	}
	for _, u := range []string{rule1UUID, unknownUUID} {
		if seen[u] != 1 {
			t.Errorf("rule %s appears %d times in the results, want exactly once\nbody: %s", u, seen[u], resp.Body)
		}
	}

	// Empty rules: v2 `rules` is required on the response, so it is always
	// serialized as [] (v1's ComplianceResponseDto.rules is omitempty).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: kindBase + "/compliance", Body: mdl.ComplianceRequestDtoV2{
		Data: sampleData, Rules: []mdl.ComplianceRuleRequestDto{}, Groups: []string{},
	}})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	out = mdl.ComplianceResponseDtoV2{}
	resp.JSON(t, &out)
	if out.Rules == nil || len(out.Rules) != 0 {
		t.Errorf("empty-rules compliance rules = %v, want [] (present, empty)\nbody: %s", out.Rules, resp.Body)
	}

	// Required-field matrix: v2 requires data, rules and groups (v1 only
	// requires certificate). Each absence -> 422 []string.
	full := func() map[string]any {
		return map[string]any{"data": sampleData, "rules": []any{}, "groups": []any{}}
	}
	for _, field := range []string{"data", "rules", "groups"} {
		t.Run("missing_"+field, func(t *testing.T) {
			body := full()
			delete(body, field)
			resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: kindBase + "/compliance", Body: body})
			if msgs := itest.AssertV1ValidationErrors(t, resp); msgs != nil && !slices.Equal(msgs, []string{msgRequiredField}) {
				t.Errorf("missing %s 422 = %v, want [%q]", field, msgs, msgRequiredField)
			}
		})
	}

	// Malformed JSON -> 400 with exactly the v1 {"message"} envelope.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: kindBase + "/compliance", RawBody: []byte("{")})
	itest.AssertV1MessageEnvelope(t, resp, http.StatusBadRequest)

	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: base + "/nokind/compliance", Body: full()})
	if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgKindNotFound {
		t.Errorf("compliance unknown kind message = %q, want %q", msg, msgKindNotFound)
	}

	h.AssertMetric(t, `connector_events_total{event="check_compliance",outcome="ok"}`)
	h.AssertMetric(t, `http_requests_total{method="POST",route="/v2/complianceProvider/{kind}/compliance",status="200"}`)

	h.AssertLogged(t, "request completed", map[string]any{"method": http.MethodPost, "path": kindBase + "/compliance", "status": 200})
}

// --- kind attribute endpoints ----------------------------------------------

func TestComplianceV2Attributes(t *testing.T) {
	h := startComplianceV2(t, nil)

	// The per-kind schema (store.go Attributes): exactly one required V3
	// string data attribute, decoded through the generated BaseAttributeDto ->
	// BaseAttributeDtoV3 -> DataAttributeV3 oneOf chain (tools/fixoneof), which
	// dispatches on the numeric version and requires schemaVersion.
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: attrBase + "/" + complianceKind + "/attributes"})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var attrs []mdl.BaseAttributeDto
	resp.JSON(t, &attrs)
	if len(attrs) != 1 || attrs[0].BaseAttributeDtoV3 == nil || attrs[0].BaseAttributeDtoV3.DataAttributeV3 == nil {
		t.Fatalf("%s/attributes = %s, want exactly one V3 data attribute", complianceKind, resp.Body)
	}
	a := attrs[0].BaseAttributeDtoV3.DataAttributeV3
	if a.Uuid != profileAttrUUID || a.Name != profileAttrName || a.Type != mdl.ATTRIBUTETYPE_DATA ||
		a.ContentType != mdl.ATTRIBUTECONTENTTYPE_STRING || !a.Properties.Required {
		t.Errorf("attribute = uuid %q name %q type %q contentType %q required %v, want %s %s data string true\nbody: %s",
			a.Uuid, a.Name, a.Type, a.ContentType, a.Properties.Required, profileAttrUUID, profileAttrName, resp.Body)
	}

	// Valid input: the required attribute is present -> 200, empty body.
	validate := attrBase + "/" + complianceKind + "/attributes/validate"
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: validate, Body: []mdl.RequestAttribute{profileReq("strict")}})
	if itest.AssertStatus(t, resp, http.StatusOK) && len(resp.Body) != 0 {
		t.Errorf("valid validate body = %q, want empty", resp.Body)
	}

	// Invalid input: the required attribute is missing -> semantic 422
	// (shared.WriteV1ValidationErrors) with exactly the store's message.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: validate, Body: []mdl.RequestAttribute{}})
	if msgs := itest.AssertV1ValidationErrors(t, resp); msgs != nil && !slices.Equal(msgs, []string{msgMissingProfile}) {
		t.Errorf("missing profile 422 = %v, want [%q]", msgs, msgMissingProfile)
	}

	// A JSON object where an array is expected -> 422 []string.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: validate, Body: map[string]any{}})
	itest.AssertV1ValidationErrors(t, resp)

	// Wildcard {kind} route, kind gating in the store: an unbacked kind is 404.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: attrBase + "/nokind/attributes"})
	if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgKindNotFound {
		t.Errorf("attributes for unbacked kind message = %q, want %q", msg, msgKindNotFound)
	}

	// compliance-v1's token/surface is not mounted on the v2 example (stdlib
	// mux 404, status only).
	for _, path := range []string{v1Base + "/" + complianceKind + "/attributes", v1Base + "/" + complianceKind + "/rules"} {
		resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: path})
		itest.AssertStatus(t, resp, http.StatusNotFound)
	}
}

// --- error envelope (the answer to issue #28) ------------------------------

// TestComplianceV2ErrorEnvelopeIsV1Shape pins the v1-family error envelope.
// Had compliance-v2 been an RFC 9457 interface (as issue #28 assumed), a 404
// would be Content-Type application/problem+json with a ProblemDetail body
// ({"type","title","status","detail","errorCode",...}). compliance-v2.json
// declares no ProblemDetail schema: errors are ErrorMessageDto {"message"}
// as application/json and 422 is a bare []string.
func TestComplianceV2ErrorEnvelopeIsV1Shape(t *testing.T) {
	h := startComplianceV2(t, nil)

	const correlationID = "compliance-v2-404"
	resp := h.Do(t, itest.Request{
		Method:  http.MethodGet,
		Path:    kindBase + "/rules/" + unknownUUID,
		Headers: map[string]string{"Correlation-Id": correlationID},
	})
	if msg := itest.AssertV1MessageEnvelope(t, resp, http.StatusNotFound); msg != msgRuleNotFound {
		t.Errorf("v1 envelope message = %q, want %q", msg, msgRuleNotFound)
	}
	if got := resp.Header.Get("Correlation-Id"); got != correlationID {
		t.Errorf("Correlation-Id response header = %q, want %q", got, correlationID)
	}
	// The rejection is logged with the error code and the request's
	// correlation id (shared/v1errors.go WriteV1Error, middleware.go).
	h.AssertLogged(t, "request rejected", map[string]any{"error_code": "RULE_NOT_FOUND", "correlation_id": correlationID})

	// A missing required field is a bare []string 422, not a problem document.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: kindBase + "/compliance", Body: map[string]any{"rules": []any{}, "groups": []any{}}})
	itest.AssertV1ValidationErrors(t, resp)
}

// --- kinds from env --------------------------------------------------------

func TestComplianceV2KindsFromEnv(t *testing.T) {
	h := startComplianceV2(t, map[string]string{"COMPLIANCE_KIND": "default,strict"})

	var groups []mdl.InfoResponse
	if status := h.GetJSON(t, http.MethodGet, "/v1", nil, &groups); status != http.StatusOK {
		t.Fatalf("GET /v1 = %d, want 200", status)
	}
	if len(groups) != 1 || !slices.Equal(groups[0].Kinds, []string{"default", "strict"}) {
		t.Fatalf("/v1 groups = %+v, want one group with kinds [default strict]", groups)
	}

	// Kinds are advertisement-only: "strict" has no store backing, so the
	// store rejects it (gating lives in the store, not the handler).
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: base + "/strict/rules"})
	if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgKindNotFound {
		t.Errorf("advertised-but-unbacked kind message = %q, want %q", msg, msgKindNotFound)
	}
}
