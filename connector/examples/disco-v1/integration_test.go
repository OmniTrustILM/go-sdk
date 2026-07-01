package main_test

// Integration tests for the disco-v1 example (Discovery Provider with
// simulated async work), driven over the public HTTP interface via the
// shared testcontainers harness. Requests/responses use the generated
// connector/model/discovery/v1 types. Skips with no Docker or under -short.
//
// disco-v1 is a v1-family connector: info at GET /v1, health at
// GET /v1/health, v1 ErrorMessageDto envelope — so error paths use
// itest.AssertV1Error.
//
// Async model: the example's POST /discover BLOCKS server-side for a random
// 1–10s (simulated scan) and returns the discovery already in the completed
// state; the server-generated uuid is only known once that call returns. A
// client therefore cannot observe the in-progress→completed transition
// mid-flight (it has no uuid to poll until completion). The lifecycle test
// still drives start → poll-until-complete → fetch-results: the poll loop
// tolerates a non-completed status and would keep working if the example
// later switched to a non-blocking (202-style) start.

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v1"
)

const (
	fgDiscovery   = string(mdl.FUNCTIONGROUPCODE_DISCOVERY_PROVIDER)
	discoveryKind = "localhost-default" // example default (DISCOVERY_KIND)

	base         = "/v1/discoveryProvider"
	pathDiscover = base + "/discover"
)

// terminalStatuses are the discovery states that end a poll loop.
var terminalStatuses = []mdl.DiscoveryStatus{
	mdl.DISCOVERYSTATUS_COMPLETED,
	mdl.DISCOVERYSTATUS_FAILED,
	mdl.DISCOVERYSTATUS_WARNING,
}

func startDisco(t *testing.T) *itest.Harness {
	t.Helper()
	return itest.Start(t, itest.Example{
		Path:       "connector/examples/disco-v1",
		HealthPath: "/v1/health",
	})
}

// v1FunctionGroup is the subset of a listSupportedFunctions entry this suite
// asserts on.
type v1FunctionGroup struct {
	FunctionGroupCode string   `json:"functionGroupCode"`
	Kinds             []string `json:"kinds"`
	EndPoints         []struct {
		Name    string `json:"name"`
		Context string `json:"context"`
		Method  string `json:"method"`
	} `json:"endPoints"`
}

func (g v1FunctionGroup) hasEndpoint(method, context string) bool {
	for _, e := range g.EndPoints {
		if e.Method == method && e.Context == context {
			return true
		}
	}
	return false
}

// --- /v1 info + health -----------------------------------------------------

func TestDiscoV1InfoAndHealth(t *testing.T) {
	h := startDisco(t)

	h.AssertHealthy(t, "/v1/health")

	var groups []v1FunctionGroup
	if status := h.GetJSON(t, http.MethodGet, "/v1", nil, &groups); status != http.StatusOK {
		t.Fatalf("GET /v1 = %d, want 200", status)
	}

	idx := slices.IndexFunc(groups, func(g v1FunctionGroup) bool { return g.FunctionGroupCode == fgDiscovery })
	if idx < 0 {
		t.Fatalf("/v1 missing %q function group: %+v", fgDiscovery, groups)
	}
	disco := groups[idx]
	if !slices.Contains(disco.Kinds, discoveryKind) {
		t.Errorf("%s kinds = %v, want to contain %q", fgDiscovery, disco.Kinds, discoveryKind)
	}

	// The example wires the shared checkHealth + listSupportedFunctions
	// endpoints into the discovery group via WithExtraEndpoints; assert they
	// surface, plus the provider's own discover endpoint.
	for _, want := range []struct{ method, context string }{
		{http.MethodGet, "/v1"},
		{http.MethodGet, "/v1/health"},
		{http.MethodPost, pathDiscover},
	} {
		if !disco.hasEndpoint(want.method, want.context) {
			t.Errorf("%s endPoints missing %s %s: %+v", fgDiscovery, want.method, want.context, disco.EndPoints)
		}
	}

	h.AssertLogsConform(t)
}

// --- async discovery lifecycle ---------------------------------------------

func TestDiscoV1DiscoveryLifecycle(t *testing.T) {
	h := startDisco(t)

	// Start discovery. POST /discover blocks server-side until the simulated
	// scan finishes, so the harness client's 30s timeout comfortably covers
	// the 1–10s work.
	start := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathDiscover, Body: mdl.DiscoveryRequestDto{
		Name: "scan-1", Kind: discoveryKind, Attributes: []mdl.RequestAttribute{},
	}})
	itest.AssertStatus(t, start, http.StatusOK)
	var started mdl.DiscoveryProviderDto
	start.JSON(t, &started)
	if started.Uuid == "" {
		t.Fatalf("discover returned no uuid: %s", start.Body)
	}
	if !validStatus(started.Status) {
		t.Errorf("discover status = %q, not a known DiscoveryStatus", started.Status)
	}

	// Poll status until a terminal state (start → poll → fetch results). The
	// example is already terminal on the first poll; the loop tolerates a
	// non-terminal status for robustness / a future non-blocking start.
	dataReq := mdl.DiscoveryDataRequestDto{Name: "scan-1", Kind: discoveryKind, PageNumber: 1, ItemsPerPage: 100}
	var final mdl.DiscoveryProviderDto
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathDiscover + "/" + started.Uuid, Body: dataReq})
		itest.AssertStatus(t, resp, http.StatusOK)
		resp.JSON(t, &final)
		if slices.Contains(terminalStatuses, final.Status) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("discovery %s did not reach a terminal status within the deadline (last: %q)", started.Uuid, final.Status)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Completed results: status completed, and the totals are self-consistent
	// with the returned certificate list (empty in this example).
	if final.Status != mdl.DISCOVERYSTATUS_COMPLETED {
		t.Errorf("final status = %q, want completed", final.Status)
	}
	if final.CertificateData == nil {
		t.Errorf("certificateData is null, want an array: %+v", final)
	}
	if final.TotalCertificatesDiscovered == nil {
		t.Errorf("totalCertificatesDiscovered is null")
	} else if int(*final.TotalCertificatesDiscovered) != len(final.CertificateData) {
		t.Errorf("totalCertificatesDiscovered = %d, but certificateData has %d entries",
			*final.TotalCertificatesDiscovered, len(final.CertificateData))
	}

	// Delete -> 204, then fetch -> 404.
	del := h.Do(t, itest.Request{Method: http.MethodDelete, Path: pathDiscover + "/" + started.Uuid})
	itest.AssertStatus(t, del, http.StatusNoContent)

	gone := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathDiscover + "/" + started.Uuid, Body: dataReq})
	itest.AssertV1Error(t, gone, http.StatusNotFound)
}

// --- error paths -----------------------------------------------------------

func TestDiscoV1Errors(t *testing.T) {
	h := startDisco(t)

	// Missing name -> 400 (v1 envelope).
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathDiscover, Body: mdl.DiscoveryRequestDto{
		Kind: discoveryKind,
	}})
	itest.AssertV1Error(t, resp, http.StatusBadRequest)

	// Fetch unknown discovery -> 404.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathDiscover + "/00000000-0000-0000-0000-000000000000", Body: mdl.DiscoveryDataRequestDto{
		Name: "x", Kind: discoveryKind, PageNumber: 1, ItemsPerPage: 10,
	}})
	itest.AssertV1Error(t, resp, http.StatusNotFound)
}

// --- attribute endpoints ---------------------------------------------------

func TestDiscoV1Attributes(t *testing.T) {
	h := startDisco(t)

	// Per-kind attribute schema -> 200, a JSON array (never null).
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: base + "/" + discoveryKind + "/attributes"})
	itest.AssertStatus(t, resp, http.StatusOK)
	var attrs []any
	resp.JSON(t, &attrs)
	if attrs == nil {
		t.Errorf("%s/attributes returned null, want a JSON array", discoveryKind)
	}

	// Validate attributes (no provider wired -> 200).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: base + "/" + discoveryKind + "/attributes/validate", Body: []mdl.RequestAttribute{}})
	itest.AssertStatus(t, resp, http.StatusOK)
}

func validStatus(s mdl.DiscoveryStatus) bool {
	return slices.Contains([]mdl.DiscoveryStatus{
		mdl.DISCOVERYSTATUS_IN_PROGRESS, mdl.DISCOVERYSTATUS_PROCESSING,
		mdl.DISCOVERYSTATUS_FAILED, mdl.DISCOVERYSTATUS_COMPLETED, mdl.DISCOVERYSTATUS_WARNING,
	}, s)
}
