package main_test

// Integration tests for the legacy-auth-v1 example (Authority Provider Legacy
// v1, in-memory store, placeholder PKI), driven over the public HTTP
// interface via the shared testcontainers harness. Requests/responses use the
// generated connector/model/authority/v1 types. Skips with no Docker or under
// -short.
//
// legacy-auth-v1 is a v1-family connector: info at GET /v1 (listSupportedFunctions),
// health at GET /v1/health, v1 ErrorMessageDto envelope / []string 422 — so
// error paths use itest.AssertV1Error / AssertV1ValidationErrors, never the
// RFC 9457 AssertProblem. Its quirk: the function group code is
// "legacyAuthorityProvider" while every route uses the literal
// "authorityProvider" path token (provider/authority/v1/handler.go).
//
// The legacy spec has no renew/identify operations (those are authority
// v2/v3); certificate coverage is issue + revoke + CRL + CA certificates.

import (
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v1"
)

const (
	fgLegacyAuthority = string(mdl.FUNCTIONGROUPCODE_LEGACY_AUTHORITY_PROVIDER) // "legacyAuthorityProvider"
	authorityKind     = "ejbca"                                                 // example default (AUTHORITY_KIND)

	base            = "/v1/authorityProvider" // literal path token != function group code
	pathAuthorities = base + "/authorities"
	pathKindAttrs   = base + "/" + authorityKind + "/attributes"
	profileName     = "default-profile"
	unknownUUID     = "00000000-0000-0000-0000-000000000000"

	// Endpoint context templates below pathAuthorities, as /v1 advertises them.
	ctxAuthority  = pathAuthorities + "/{uuid}"
	ctxEEProfiles = ctxAuthority + "/endEntityProfiles"
	ctxEEProfile  = ctxEEProfiles + "/{endEntityProfileName}"
	ctxEEProfileI = ctxEEProfiles + "/{endEntityProfileId}"
	ctxEndEntity  = ctxEEProfile + "/endEntities/{endEntityName}"

	msgInvalidRequest    = "invalid request"              // authority.ErrInvalidRequest
	msgAuthorityNotFound = "authority instance not found" // authority.ErrAuthorityNotFound
	msgEndEntityNotFound = "end entity not found"         // authority.ErrEndEntityNotFound
)

var (
	placeholderCSR = base64.StdEncoding.EncodeToString([]byte("placeholder-csr"))
	placeholderCRL = base64.StdEncoding.EncodeToString([]byte("placeholder-crl")) // store.go GetCrl
)

func startLegacyAuth(t *testing.T, env map[string]string) *itest.Harness {
	t.Helper()
	return itest.Start(t, itest.Example{
		Path:       "connector/examples/legacy-auth-v1",
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

func authorityReq(name string) mdl.AuthorityProviderInstanceRequestDto {
	return mdl.AuthorityProviderInstanceRequestDto{Name: name, Kind: authorityKind, Attributes: []mdl.RequestAttribute{}}
}

// createAuthority creates an instance and returns its uuid (FailNow on error).
func createAuthority(t *testing.T, h *itest.Harness, name string) string {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities, Body: authorityReq(name)})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var inst mdl.AuthorityProviderInstanceDto
	resp.JSON(t, &inst)
	if inst.Uuid == "" || inst.Name != name || inst.Attributes == nil {
		t.Fatalf("create returned uuid=%q name=%q attributes=%v, want uuid, name %q, [] attributes\nbody: %s", inst.Uuid, inst.Name, inst.Attributes, name, resp.Body)
	}
	return inst.Uuid
}

// eePath is the end-entity profile scope every end-entity and certificate
// operation lives under.
func eePath(authority string) string {
	return pathAuthorities + "/" + authority + "/endEntityProfiles/" + profileName
}

// getInfo fetches GET /v1 into the generated InfoResponse model and returns
// the single legacyAuthorityProvider group (FailNow otherwise).
func getInfo(t *testing.T, h *itest.Harness) mdl.InfoResponse {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: "/v1"})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var groups []mdl.InfoResponse
	resp.JSON(t, &groups)
	if len(groups) != 1 || string(groups[0].FunctionGroupCode) != fgLegacyAuthority {
		t.Fatalf("GET /v1 = %d group(s), want exactly one %q\nbody: %s", len(groups), fgLegacyAuthority, resp.Body)
	}
	return groups[0]
}

// --- /v1 info + health -----------------------------------------------------

func TestLegacyAuthV1InfoAndHealth(t *testing.T) {
	h := startLegacyAuth(t, nil)

	// Status "ok" plus parts.liveness/readiness "ok" (itest v1 branch).
	h.AssertHealthy(t, "/v1/health")

	// The same body through the generated HealthDto (the checkHealth schema):
	// the status enum and the nested parts decode into the spec's types.
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: "/v1/health"})
	if itest.AssertStatus(t, resp, http.StatusOK) {
		var health mdl.HealthDto
		resp.JSON(t, &health)
		if health.Status != mdl.HEALTHSTATUS_OK || health.Parts["liveness"].Status != mdl.HEALTHSTATUS_OK || health.Parts["readiness"].Status != mdl.HEALTHSTATUS_OK {
			t.Errorf("HealthDto = %+v, want status ok with liveness/readiness parts ok\nbody: %s", health, resp.Body)
		}
	}

	// v1-family: the v2 info/health surface is not mounted at all (stdlib
	// text 404, so status only).
	for _, p := range []string{"/v2/health", "/v2/info"} {
		resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: p})
		itest.AssertStatus(t, resp, http.StatusNotFound)
	}

	// Decode into the generated InfoResponse model (the /v1
	// listSupportedFunctions element shape) for a typed functionGroupCode.
	// This is not schema validation: the generated decoder only checks that
	// required keys are present — it accepts null for required strings (shared
	// emits "uuid": null on every endpoint although the spec declares a
	// non-nullable string) and keeps unknown keys in AdditionalProperties. The
	// explicit assertions below carry the contract.
	g := getInfo(t, h)
	if !slices.Equal(g.Kinds, []string{authorityKind}) {
		t.Errorf("%s kinds = %v, want [%s]", fgLegacyAuthority, g.Kinds, authorityKind)
	}

	// The full advertised endpoint set: the provider's 23 routes
	// (FunctionGroup()) plus the shared checkHealth + listSupportedFunctions
	// extras (main.go WithExtraEndpoints). The exact count catches an extra
	// or dropped entry; the list catches a renamed operation, context or
	// method. Names are the authority-v1.json operationIds.
	wantEndpoints := []struct{ name, method, context string }{
		{"listSupportedFunctions", http.MethodGet, "/v1"}, // extra
		{"checkHealth", http.MethodGet, "/v1/health"},     // extra
		// kind attributes
		{"listAttributeDefinitions", http.MethodGet, base + "/{kind}/attributes"},
		{"validateAttributes", http.MethodPost, base + "/{kind}/attributes/validate"},
		// authority management
		{"listAuthorityInstances", http.MethodGet, pathAuthorities},
		{"createAuthorityInstance", http.MethodPost, pathAuthorities},
		{"getAuthorityInstance", http.MethodGet, ctxAuthority},
		{"updateAuthorityInstance", http.MethodPost, ctxAuthority},
		{"removeAuthorityInstance", http.MethodDelete, ctxAuthority},
		{"getConnection", http.MethodGet, ctxAuthority + "/connect"},
		{"getCaCertificates", http.MethodPost, ctxAuthority + "/caCertificates"},
		{"getCrl", http.MethodPost, ctxAuthority + "/crl"},
		// RA profile attributes
		{"listRAProfileAttributes", http.MethodGet, ctxAuthority + "/raProfile/attributes"},
		{"validateRAProfileAttributes", http.MethodPost, ctxAuthority + "/raProfile/attributes/validate"},
		// end-entity profile lookups
		{"listEntityProfiles", http.MethodGet, ctxEEProfiles},
		{"listCertificateProfiles", http.MethodGet, ctxEEProfileI + "/certificateprofiles"},
		{"listCAsInProfile", http.MethodGet, ctxEEProfileI + "/cas"},
		// end-entity management
		{"listEndEntities", http.MethodGet, ctxEEProfile + "/endEntities"},
		{"createEndEntity", http.MethodPost, ctxEEProfile + "/endEntities"},
		{"getEndEntity", http.MethodGet, ctxEndEntity},
		{"updateEndEntity", http.MethodPost, ctxEndEntity},
		{"removeEndEntity", http.MethodDelete, ctxEndEntity},
		{"resetPassword", http.MethodPut, ctxEndEntity + "/resetPassword"},
		// certificate management
		{"issueCertificate", http.MethodPost, ctxEEProfile + "/certificates/issue"},
		{"revokeCertificate", http.MethodPost, ctxEEProfile + "/certificates/revoke"},
	}
	if len(g.EndPoints) != len(wantEndpoints) {
		t.Errorf("%s advertises %d endpoints, want %d: %+v", fgLegacyAuthority, len(g.EndPoints), len(wantEndpoints), g.EndPoints)
	}
	for _, want := range wantEndpoints {
		if !hasEndpoint(g, want.name, want.method, want.context) {
			t.Errorf("%s endPoints missing %s %s %s (required=false): %+v", fgLegacyAuthority, want.name, want.method, want.context, g.EndPoints)
		}
	}

	// The quirk, explicitly: the group code is legacyAuthorityProvider, but no
	// advertised context uses it as a path token.
	for _, e := range g.EndPoints {
		if !strings.HasPrefix(e.Context, "/v1") || strings.HasPrefix(e.Context, "/v1/"+fgLegacyAuthority) {
			t.Errorf("endpoint %s %s: context must start with /v1 and not /v1/%s", e.Method, e.Context, fgLegacyAuthority)
		}
	}

	// Metrics wiring: build info (examples pass commit "dev") and the request
	// counter labelled by the matched route.
	h.AssertMetric(t, `app_build_info{commit="dev",runtime="go`)
	h.AssertMetric(t, `http_requests_total{method="GET",route="/v1/health",status="200"}`)

	h.AssertLogsConform(t)
}

// --- authority instance lifecycle ------------------------------------------

func TestLegacyAuthV1AuthorityLifecycle(t *testing.T) {
	h := startLegacyAuth(t, nil)

	// Empty store lists as [] (shared.EnsureSlice), never null.
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathAuthorities})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var list []mdl.AuthorityProviderInstanceDto
	resp.JSON(t, &list)
	if list == nil || len(list) != 0 {
		t.Errorf("empty authority list = %s, want []", resp.Body)
	}

	id := createAuthority(t, h, "ca-1")
	pathID := pathAuthorities + "/" + id

	// List contains it (find by uuid; the store map is unordered).
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathAuthorities})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	resp.JSON(t, &list)
	// attributes is a required array: [] decodes to a non-nil empty slice,
	// while null on the wire decodes to nil.
	if i := slices.IndexFunc(list, func(a mdl.AuthorityProviderInstanceDto) bool { return a.Uuid == id }); i < 0 {
		t.Errorf("authority list missing %s\nbody: %s", id, resp.Body)
	} else if list[i].Name != "ca-1" || list[i].Attributes == nil {
		t.Errorf("listed authority = name %q attributes %v, want ca-1 and attributes [] (never null)\nbody: %s", list[i].Name, list[i].Attributes, resp.Body)
	}

	// Get round-trips uuid + name; attributes is an array, never null.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathID})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var got mdl.AuthorityProviderInstanceDto
	resp.JSON(t, &got)
	if got.Uuid != id || got.Name != "ca-1" || got.Attributes == nil {
		t.Errorf("get = uuid %q name %q attributes %v, want %q ca-1 []\nbody: %s", got.Uuid, got.Name, got.Attributes, id, resp.Body)
	}

	// Connect -> 204 with no body (routes.go getConnection).
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathID + "/connect"})
	if itest.AssertStatus(t, resp, http.StatusNoContent) && len(resp.Body) != 0 {
		t.Errorf("connect body = %s, want empty", resp.Body)
	}

	// Update (POST on the instance) renames it; re-GET confirms the store applied it.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathID, Body: authorityReq("ca-1-renamed")})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	resp.JSON(t, &got)
	if got.Uuid != id || got.Name != "ca-1-renamed" || got.Attributes == nil {
		t.Errorf("update = uuid %q name %q attributes %v, want %q ca-1-renamed []\nbody: %s", got.Uuid, got.Name, got.Attributes, id, resp.Body)
	}
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathID})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	resp.JSON(t, &got)
	if got.Name != "ca-1-renamed" {
		t.Errorf("get after update name = %q, want ca-1-renamed\nbody: %s", got.Name, resp.Body)
	}

	// Delete -> 204 (routes.go removeAuthorityInstance).
	resp = h.Do(t, itest.Request{Method: http.MethodDelete, Path: pathID})
	itest.AssertStatus(t, resp, http.StatusNoContent)

	// Gone: get carries the sentinel message from provider errors.go.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathID})
	if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgAuthorityNotFound {
		t.Errorf("get deleted message = %q, want %q", msg, msgAuthorityNotFound)
	}

	// Every other instance-scoped operation on the deleted id is 404 too.
	for _, req := range []itest.Request{
		{Method: http.MethodGet, Path: pathID + "/connect"},
		{Method: http.MethodPost, Path: pathID, Body: authorityReq("ca-1-again")},
		{Method: http.MethodDelete, Path: pathID},
	} {
		resp = h.Do(t, req)
		if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgAuthorityNotFound {
			t.Errorf("%s %s message = %q, want %q", req.Method, req.Path, msg, msgAuthorityNotFound)
		}
	}
}

// --- certificate operations ------------------------------------------------

func TestLegacyAuthV1CertificateOperations(t *testing.T) {
	h := startLegacyAuth(t, nil)
	id := createAuthority(t, h, "ca-certs")
	cert := eePath(id) + "/certificates"

	// Issue -> 200 with base64 certificateData (placeholder content).
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: cert + "/issue", Body: mdl.CertificateSignRequestDto{
		Username: "ee-1", Password: "pw", Pkcs10: placeholderCSR,
	}})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var issued mdl.CertificateSignResponseDto
	resp.JSON(t, &issued)
	if issued.CertificateData == "" {
		t.Errorf("issue certificateData is empty\nbody: %s", resp.Body)
	} else if _, err := base64.StdEncoding.DecodeString(issued.CertificateData); err != nil {
		t.Errorf("issue certificateData is not base64: %v\nbody: %s", err, resp.Body)
	}

	// Empty pkcs10 (key present) passes decoding but hits the store guard
	// (store.go IssueCertificate) -> 400 "invalid request".
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: cert + "/issue", Body: mdl.CertificateSignRequestDto{
		Username: "ee-1", Password: "pw", Pkcs10: "",
	}})
	if msg := itest.AssertV1Error(t, resp, http.StatusBadRequest); msg != msgInvalidRequest {
		t.Errorf("issue empty pkcs10 message = %q, want %q", msg, msgInvalidRequest)
	}

	// Absent pkcs10 key: the generated DTO rejects the missing required
	// property. Spec gap: authority-v1.json declares no 422 for
	// issueCertificate (200/400/401/403/404/500 only); this pins the shared
	// codec (shared/codec.go DecodeJSON), which maps every missing required
	// property to 422 []string.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: cert + "/issue", Body: map[string]any{
		"username": "ee-1", "password": "pw",
	}})
	itest.AssertV1ValidationErrors(t, resp)

	// Revoke -> 200 with an empty body (spec: 200, no content schema). The
	// store does not check the authority/serial, so any request succeeds.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: cert + "/revoke", Body: mdl.CertRevocationDto{
		CertificateSN: "01", IssuerDN: "CN=Test CA", Reason: mdl.CERTIFICATEREVOCATIONREASON_KEY_COMPROMISE,
	}})
	if itest.AssertStatus(t, resp, http.StatusOK) && len(resp.Body) != 0 {
		t.Errorf("revoke body = %s, want empty", resp.Body)
	}

	// A reason outside the CertificateRevocationReason enum is rejected by
	// the generated enum decoder -> INVALID_JSON 400 (codec.go fallthrough).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: cert + "/revoke", Body: map[string]any{
		"certificateSN": "01", "issuerDN": "CN=Test CA", "reason": "bogus",
	}})
	itest.AssertV1Error(t, resp, http.StatusBadRequest)

	// CRL -> 200 with the store's placeholder crlData, full and delta alike.
	delta := true
	for _, req := range []mdl.CertificateRevocationListRequestDto{
		{RaProfileAttributes: []mdl.RequestAttribute{}},
		{RaProfileAttributes: []mdl.RequestAttribute{}, Delta: &delta},
	} {
		resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities + "/" + id + "/crl", Body: req})
		if !itest.AssertStatus(t, resp, http.StatusOK) {
			t.FailNow()
		}
		var crl mdl.CertificateRevocationListResponseDto
		resp.JSON(t, &crl)
		if crl.CrlData != placeholderCRL {
			t.Errorf("crl (delta=%v) crlData = %q, want %q\nbody: %s", req.Delta != nil, crl.CrlData, placeholderCRL, resp.Body)
		}
	}

	// CRL without the required raProfileAttributes key -> 422 []string.
	// Spec gap: authority-v1.json declares no 422 for getCrl; this pins the
	// shared codec (shared/codec.go DecodeJSON).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities + "/" + id + "/crl", Body: map[string]any{"delta": true}})
	itest.AssertV1ValidationErrors(t, resp)

	// CA certificates -> 200 with "certificates":[] (never null).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities + "/" + id + "/caCertificates", Body: mdl.CaCertificatesRequestDto{
		RaProfileAttributes: []mdl.RequestAttribute{},
	}})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var cas mdl.CaCertificatesResponseDto
	resp.JSON(t, &cas)
	if cas.Certificates == nil || len(cas.Certificates) != 0 {
		t.Errorf("caCertificates certificates = %v, want []\nbody: %s", cas.Certificates, resp.Body)
	}

	// Provider event names (routes.go event constants) with ok/error outcomes.
	for _, series := range []string{
		`connector_events_total{event="issue_certificate",outcome="ok"}`,
		`connector_events_total{event="issue_certificate",outcome="error"}`,
		`connector_events_total{event="revoke_certificate",outcome="ok"}`,
		`connector_events_total{event="get_crl",outcome="ok"}`,
	} {
		h.AssertMetric(t, series)
	}
}

// --- end-entity lifecycle + profile lookups --------------------------------

func TestLegacyAuthV1EndEntityLifecycle(t *testing.T) {
	h := startLegacyAuth(t, nil)
	id := createAuthority(t, h, "ca-ee")
	ees := eePath(id) + "/endEntities"
	alice := ees + "/alice"

	// Empty profile lists as [] (shared.EnsureSlice), never null.
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: ees})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var list []mdl.EndEntityDto
	resp.JSON(t, &list)
	if list == nil || len(list) != 0 {
		t.Errorf("empty end-entity list = %s, want []", resp.Body)
	}

	// Create -> 200 with an empty body (spec: 200, no content schema).
	email := "alice@example.com"
	raProfile := mdl.RaProfileDto{Uuid: "ra-1", Name: "ra", Enabled: true}
	create := mdl.AddEndEntityRequestDto{RaProfile: raProfile, Username: "alice", Password: "pw", SubjectDN: "CN=alice", Email: &email}
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: ees, Body: create})
	if itest.AssertStatus(t, resp, http.StatusOK) && len(resp.Body) != 0 {
		t.Errorf("create end entity body = %s, want empty", resp.Body)
	}

	// Get round-trips the stored fields; status is the store's "GENERATED".
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: alice})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var ee mdl.EndEntityDto
	resp.JSON(t, &ee)
	if ee.Username != "alice" || ee.SubjectDN != "CN=alice" || ee.Status != "GENERATED" || ee.Email == nil || *ee.Email != email {
		t.Errorf("get end entity = %+v, want username alice, subjectDN CN=alice, status GENERATED, email %s\nbody: %s", ee, email, resp.Body)
	}

	// List contains alice (find by username; the store map is unordered).
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: ees})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	resp.JSON(t, &list)
	if !slices.ContainsFunc(list, func(e mdl.EndEntityDto) bool { return e.Username == "alice" }) {
		t.Errorf("end-entity list missing alice\nbody: %s", resp.Body)
	}

	// Duplicate username in the same profile -> 400 "invalid request" (store guard).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: ees, Body: create})
	if msg := itest.AssertV1Error(t, resp, http.StatusBadRequest); msg != msgInvalidRequest {
		t.Errorf("duplicate create message = %q, want %q", msg, msgInvalidRequest)
	}

	// Absent username key -> 422 []string (generated DTO required property).
	// Spec gap: authority-v1.json declares no 422 for createEndEntity; this
	// pins the shared codec (shared/codec.go DecodeJSON).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: ees, Body: map[string]any{
		"raProfile": raProfile, "password": "pw", "subjectDN": "CN=bob",
	}})
	itest.AssertV1ValidationErrors(t, resp)

	// Update (POST on the end entity) -> 200 empty; the store applies the new
	// subjectDN. It does not copy status, so status is not asserted here.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: alice, Body: mdl.EditEndEntityRequestDto{
		RaProfile: raProfile, Password: "pw2", SubjectDN: "CN=alice,O=Acme", Status: "NEW",
	}})
	if itest.AssertStatus(t, resp, http.StatusOK) && len(resp.Body) != 0 {
		t.Errorf("update end entity body = %s, want empty", resp.Body)
	}
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: alice})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	resp.JSON(t, &ee)
	if ee.SubjectDN != "CN=alice,O=Acme" {
		t.Errorf("get after update subjectDN = %q, want CN=alice,O=Acme\nbody: %s", ee.SubjectDN, resp.Body)
	}

	// Reset password -> 200.
	resp = h.Do(t, itest.Request{Method: http.MethodPut, Path: alice + "/resetPassword"})
	itest.AssertStatus(t, resp, http.StatusOK)

	// Delete -> 200 (not 204: routes.go removeEndEntity; the spec lists 200 only).
	resp = h.Do(t, itest.Request{Method: http.MethodDelete, Path: alice})
	itest.AssertStatus(t, resp, http.StatusOK)

	// Gone: get, reset and delete all 404 with the end-entity sentinel.
	for _, req := range []itest.Request{
		{Method: http.MethodGet, Path: alice},
		{Method: http.MethodPut, Path: alice + "/resetPassword"},
		{Method: http.MethodDelete, Path: alice},
	} {
		resp = h.Do(t, req)
		if msg := itest.AssertV1Error(t, resp, http.StatusNotFound); msg != msgEndEntityNotFound {
			t.Errorf("%s %s message = %q, want %q", req.Method, req.Path, msg, msgEndEntityNotFound)
		}
	}

	// Profile lookups: static store answers decoded into NameAndIdDto.
	profiles := pathAuthorities + "/" + id + "/endEntityProfiles"
	for _, tc := range []struct {
		path string
		want mdl.NameAndIdDto
	}{
		{profiles, mdl.NameAndIdDto{Id: 1, Name: profileName}},
		{profiles + "/1/certificateprofiles", mdl.NameAndIdDto{Id: 1, Name: "default-cert-profile"}},
		{profiles + "/1/cas", mdl.NameAndIdDto{Id: 1, Name: "default-ca"}},
	} {
		resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: tc.path})
		if !itest.AssertStatus(t, resp, http.StatusOK) {
			continue
		}
		var got []mdl.NameAndIdDto
		resp.JSON(t, &got)
		if len(got) != 1 || got[0].Id != tc.want.Id || got[0].Name != tc.want.Name {
			t.Errorf("GET %s = %+v, want [{%d %s}]\nbody: %s", tc.path, got, tc.want.Id, tc.want.Name, resp.Body)
		}
	}

	// A non-integer {endEntityProfileId} -> 400 (shared RequireIntPathValue).
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: profiles + "/abc/cas"})
	if msg := itest.AssertV1Error(t, resp, http.StatusBadRequest); msg != "endEntityProfileId must be an integer" {
		t.Errorf("non-integer profile id message = %q, want %q", msg, "endEntityProfileId must be an integer")
	}
}

// --- attribute endpoints ---------------------------------------------------

func TestLegacyAuthV1Attributes(t *testing.T) {
	h := startLegacyAuth(t, nil)

	// Per-kind attribute schema -> 200, a JSON array (no KindAttributeProvider
	// wired, so []; never null).
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathKindAttrs})
	if itest.AssertStatus(t, resp, http.StatusOK) {
		var attrs []any
		resp.JSON(t, &attrs)
		if attrs == nil || len(attrs) != 0 {
			t.Errorf("GET %s = %s, want []", pathKindAttrs, resp.Body)
		}
	}

	// Validate (no provider wired) -> 200, empty body.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKindAttrs + "/validate", Body: []mdl.RequestAttribute{}})
	if itest.AssertStatus(t, resp, http.StatusOK) && len(resp.Body) != 0 {
		t.Errorf("validate body = %s, want empty", resp.Body)
	}

	// An object where the spec wants an array is a JSON type error -> 422 []string.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathKindAttrs + "/validate", Body: map[string]any{}})
	itest.AssertV1ValidationErrors(t, resp)

	// Attribute routes are mounted per literal kind, so an unknown kind never
	// reaches the provider: the mux answers with its text/plain 404 (not the
	// v1 envelope), hence status only.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: base + "/not-a-kind/attributes"})
	itest.AssertStatus(t, resp, http.StatusNotFound)

	// RA profile attributes: [] and 200 validate. The routes never consult the
	// store (routes.go listRAProfileAttributes / validateRAProfileAttributes,
	// no RAProfileAttributeProvider wired), so an unknown authority answers
	// the same as an existing one.
	id := createAuthority(t, h, "ca-attrs")
	for _, authority := range []string{id, unknownUUID} {
		raAttrs := pathAuthorities + "/" + authority + "/raProfile/attributes"
		resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: raAttrs})
		if itest.AssertStatus(t, resp, http.StatusOK) {
			var attrs []any
			resp.JSON(t, &attrs)
			if attrs == nil || len(attrs) != 0 {
				t.Errorf("GET %s = %s, want []", raAttrs, resp.Body)
			}
		}
		resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: raAttrs + "/validate", Body: []mdl.RequestAttribute{}})
		itest.AssertStatus(t, resp, http.StatusOK)
	}
}

// --- v1 error envelope, correlation and observability ----------------------

func TestLegacyAuthV1ErrorEnvelope(t *testing.T) {
	h := startLegacyAuth(t, nil)

	// Empty name ("name":"", not omitted) passes decoding and hits the store
	// guard -> 400 with exactly {"message": ...} as application/json.
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities, Body: authorityReq("")})
	if msg := itest.AssertV1MessageEnvelope(t, resp, http.StatusBadRequest); msg != msgInvalidRequest {
		t.Errorf("empty-name message = %q, want %q", msg, msgInvalidRequest)
	}

	// Absent name key -> the decode-failure 422 branch: a single-element
	// []string. Spec gap: authority-v1.json declares no 422 for
	// createAuthorityInstance; this and the wrong-type case below pin the
	// shared codec (shared/codec.go DecodeJSON), not a spec contract.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities, Body: map[string]any{
		"kind": authorityKind, "attributes": []any{},
	}})
	if msgs := itest.AssertV1ValidationErrors(t, resp); msgs != nil && len(msgs) != 1 {
		t.Errorf("absent-name 422 = %v, want exactly one message", msgs)
	}

	// Wrong JSON type for name (*json.UnmarshalTypeError) -> 422 []string
	// (same spec gap as above).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities, Body: map[string]any{
		"name": 5, "kind": authorityKind, "attributes": []any{},
	}})
	itest.AssertV1ValidationErrors(t, resp)

	// Malformed JSON -> INVALID_JSON 400, same strict envelope.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities, RawBody: []byte("{not json")})
	itest.AssertV1MessageEnvelope(t, resp, http.StatusBadRequest)

	// No body at all -> EMPTY_BODY 400.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities})
	itest.AssertV1Error(t, resp, http.StatusBadRequest)

	// Correlation: the caller's Correlation-Id is echoed and stamped on the
	// rejection log line, which also carries the provider's error code.
	const correlationID = "legacy-auth-404"
	unknown := pathAuthorities + "/" + unknownUUID
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: unknown, Headers: map[string]string{"Correlation-Id": correlationID}})
	itest.AssertV1Error(t, resp, http.StatusNotFound)
	if got := resp.Header.Get("Correlation-Id"); got != correlationID {
		t.Errorf("Correlation-Id response header = %q, want %q", got, correlationID)
	}
	if line := h.AssertLogged(t, "request rejected", map[string]any{"error_code": "AUTHORITY_NOT_FOUND", "status": 404, "correlation_id": correlationID}); line != nil {
		if svc, _ := line["service"].(map[string]any); svc["name"] != "example-legacy-auth-v1" {
			t.Errorf("request rejected service.name = %v, want example-legacy-auth-v1: %v", svc["name"], line)
		}
	}
	h.AssertLogged(t, "request completed", map[string]any{"method": http.MethodGet, "path": unknown, "status": 404})

	// The failure is counted both as a provider event and as a routed request
	// (route label is the mux pattern, not the concrete path).
	h.AssertMetric(t, `connector_events_total{event="get_authority_instance",outcome="error"}`)
	h.AssertMetric(t, `http_requests_total{method="GET",route="/v1/authorityProvider/authorities/{uuid}",status="404"}`)

	// A method no route registers on an existing path -> stdlib text 405
	// (no catch-all renderer), so status only.
	resp = h.Do(t, itest.Request{Method: http.MethodPatch, Path: unknown})
	itest.AssertStatus(t, resp, http.StatusMethodNotAllowed)
}

// --- kinds from AUTHORITY_KIND ---------------------------------------------

func TestLegacyAuthV1KindsFromEnv(t *testing.T) {
	h := startLegacyAuth(t, map[string]string{"AUTHORITY_KIND": "ejbca,msca"})

	// Kinds are advertised in env order.
	g := getInfo(t, h)
	if want := []string{"ejbca", "msca"}; !slices.Equal(g.Kinds, want) {
		t.Errorf("%s kinds = %v, want %v", fgLegacyAuthority, g.Kinds, want)
	}

	// Each kind gets its own literal attribute route.
	for _, kind := range []string{"msca", "ejbca"} {
		resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: base + "/" + kind + "/attributes"})
		itest.AssertStatus(t, resp, http.StatusOK)
	}
}
