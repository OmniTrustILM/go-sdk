package main_test

// Integration tests for the multi-v1 example — Discovery v1 + Authority v2
// registered on a single shared.Connector — driven over the public HTTP
// interface via the shared testcontainers harness. Focus: multi-provider
// composition. Both function groups must be listed, both reachable, and the
// shared /v1 info + /v1/health served once for the combined connector with
// no route collisions. Skips with no Docker or under -short.
//
// multi-v1 is a v1-family connector: info at GET /v1 (listSupportedFunctions),
// health at GET /v1/health, v1 error envelope.

import (
	"net/http"
	"slices"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
)

const (
	// Function group codes the combined connector advertises.
	fgDiscovery = "discoveryProvider"
	fgAuthority = "authorityProvider"

	// Kinds the example registers for each provider.
	discoveryKind = "localhost-default"
	authorityKind = "placeholder-ca"
)

// startMulti launches the multi-v1 example container. It is a v1-family
// connector, so readiness is gated on /v1/health.
//
// A successful start is itself the core composition assertion: the stdlib
// ServeMux panics at registration on any conflicting route pattern, so if
// the two providers' routes (or the shared endpoints) collided, the
// container would crash before serving and the harness readiness wait would
// fail Start. Reaching the assertions below therefore proves the providers
// compose on one mux without collisions.
func startMulti(t *testing.T) *itest.Harness {
	t.Helper()
	return itest.Start(t, itest.Example{
		Path:       "connector/examples/multi-v1",
		HealthPath: "/v1/health",
	})
}

// v1FunctionGroup is the subset of the listSupportedFunctions entry shape
// this suite asserts on.
type v1FunctionGroup struct {
	FunctionGroupCode string   `json:"functionGroupCode"`
	Kinds             []string `json:"kinds"`
	EndPoints         []struct {
		Name    string `json:"name"`
		Context string `json:"context"`
		Method  string `json:"method"`
	} `json:"endPoints"`
}

// TestMultiV1InfoListsBothProviders verifies the combined /v1
// listSupportedFunctions advertises both function groups exactly once, each
// carrying its registered kind — the info-listing half of composition.
func TestMultiV1InfoListsBothProviders(t *testing.T) {
	h := startMulti(t)

	var groups []v1FunctionGroup
	if status := h.GetJSON(t, http.MethodGet, "/v1", nil, &groups); status != http.StatusOK {
		t.Fatalf("GET /v1 = %d, want 200", status)
	}

	byCode := map[string]v1FunctionGroup{}
	for _, g := range groups {
		if _, dup := byCode[g.FunctionGroupCode]; dup {
			t.Errorf("function group %q listed more than once (shared info not served once)", g.FunctionGroupCode)
		}
		byCode[g.FunctionGroupCode] = g
	}

	disco, ok := byCode[fgDiscovery]
	if !ok {
		t.Errorf("/v1 missing %q function group; got %v", fgDiscovery, byCode)
	} else if !slices.Contains(disco.Kinds, discoveryKind) {
		t.Errorf("%s kinds = %v, want to contain %q", fgDiscovery, disco.Kinds, discoveryKind)
	}

	auth, ok := byCode[fgAuthority]
	if !ok {
		t.Errorf("/v1 missing %q function group; got %v", fgAuthority, byCode)
	} else if !slices.Contains(auth.Kinds, authorityKind) {
		t.Errorf("%s kinds = %v, want to contain %q", fgAuthority, auth.Kinds, authorityKind)
	}

	// Container logs conform to the connector.log v1 contract.
	h.AssertLogsConform(t)
}

// TestMultiV1SharedHealth verifies the shared /v1/health endpoint is served
// once and correctly for the combined connector.
func TestMultiV1SharedHealth(t *testing.T) {
	h := startMulti(t)
	h.AssertHealthy(t, "/v1/health")
}

// TestMultiV1BothProvidersReachable exercises at least one operation from
// each provider against the single server, proving both are wired and
// reachable on the same mux.
func TestMultiV1BothProvidersReachable(t *testing.T) {
	h := startMulti(t)

	// Discovery: per-kind attribute schema -> 200 (array).
	discoAttrs := h.Do(t, itest.Request{
		Method: http.MethodGet,
		Path:   "/v1/discoveryProvider/" + discoveryKind + "/attributes",
	})
	itest.AssertStatus(t, discoAttrs, http.StatusOK)

	// Authority v2: list authority instances -> 200 (array, possibly empty).
	authList := h.Do(t, itest.Request{
		Method: http.MethodGet,
		Path:   "/v1/authorityProvider/authorities",
	})
	itest.AssertStatus(t, authList, http.StatusOK)
}

// TestMultiV1SharedMetrics verifies the shared Prometheus endpoint is served
// once for the combined connector.
func TestMultiV1SharedMetrics(t *testing.T) {
	h := startMulti(t)
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: "/v1/metrics"})
	itest.AssertStatus(t, resp, http.StatusOK)
}
