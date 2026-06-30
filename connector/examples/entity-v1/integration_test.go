package main_test

// Integration tests for the entity-v1 example (in-memory entity store;
// placeholder location ops), driven over the public HTTP interface via the
// shared testcontainers harness. Requests/responses use the generated
// connector/model/entity/v1 types. Skips with no Docker or under -short.
//
// entity-v1 is a v1-family connector: info at GET /v1, health at
// GET /v1/health, and the v1 ErrorMessageDto error envelope — so error paths
// use itest.AssertV1Error, not the RFC 9457 AssertProblem.

import (
	"net/http"
	"slices"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
)

const (
	// Function group code from the generated enum so the test tracks the
	// OpenAPI value.
	fgEntity   = string(mdl.FUNCTIONGROUPCODE_ENTITY_PROVIDER)
	entityKind = "default" // example default (ENTITY_KIND)

	base          = "/v1/entityProvider"
	pathEntities  = base + "/entities"
	unknownEntity = "00000000-0000-0000-0000-000000000000"
)

func startEntity(t *testing.T) *itest.Harness {
	t.Helper()
	return itest.Start(t, itest.Example{
		Path:       "connector/examples/entity-v1",
		HealthPath: "/v1/health",
	})
}

func entityReq(name, kind string) mdl.EntityInstanceRequestDto {
	return mdl.EntityInstanceRequestDto{Name: name, Kind: kind, Attributes: []mdl.RequestAttribute{}}
}

// createEntity creates an entity instance and returns its assigned uuid.
func createEntity(t *testing.T, h *itest.Harness, name string) string {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathEntities, Body: entityReq(name, entityKind)})
	itest.AssertStatus(t, resp, http.StatusOK)
	var inst mdl.EntityInstanceDto
	resp.JSON(t, &inst)
	if inst.Uuid == "" {
		t.Fatalf("create returned no uuid\nbody: %s", resp.Body)
	}
	if inst.Name != name {
		t.Errorf("created name = %q, want %q", inst.Name, name)
	}
	return inst.Uuid
}

// --- /v1 info + health -----------------------------------------------------

func TestEntityV1InfoAndHealth(t *testing.T) {
	h := startEntity(t)

	h.AssertHealthy(t, "/v1/health")

	var groups []struct {
		FunctionGroupCode string   `json:"functionGroupCode"`
		Kinds             []string `json:"kinds"`
	}
	if status := h.GetJSON(t, http.MethodGet, "/v1", nil, &groups); status != http.StatusOK {
		t.Fatalf("GET /v1 = %d, want 200", status)
	}
	var found bool
	for _, g := range groups {
		if g.FunctionGroupCode == fgEntity {
			found = true
			if !slices.Contains(g.Kinds, entityKind) {
				t.Errorf("%s kinds = %v, want to contain %q", fgEntity, g.Kinds, entityKind)
			}
		}
	}
	if !found {
		t.Errorf("/v1 missing %q function group: %+v", fgEntity, groups)
	}

	h.AssertLogsConform(t)
}

// --- entity store CRUD -----------------------------------------------------

func TestEntityV1InstanceLifecycle(t *testing.T) {
	h := startEntity(t)

	uuid := createEntity(t, h, "edge-vault")

	// get
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathEntities + "/" + uuid})
	itest.AssertStatus(t, resp, http.StatusOK)
	var got mdl.EntityInstanceDto
	resp.JSON(t, &got)
	if got.Uuid != uuid || got.Name != "edge-vault" {
		t.Errorf("get = %+v, want uuid %q name edge-vault", got, uuid)
	}

	// list contains it
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathEntities})
	itest.AssertStatus(t, resp, http.StatusOK)
	var list []mdl.EntityInstanceDto
	resp.JSON(t, &list)
	if !slices.ContainsFunc(list, func(e mdl.EntityInstanceDto) bool { return e.Uuid == uuid }) {
		t.Errorf("list does not contain created entity %q: %+v", uuid, list)
	}

	// update
	resp = h.Do(t, itest.Request{Method: http.MethodPut, Path: pathEntities + "/" + uuid, Body: entityReq("edge-vault-renamed", entityKind)})
	itest.AssertStatus(t, resp, http.StatusOK)
	var updated mdl.EntityInstanceDto
	resp.JSON(t, &updated)
	if updated.Name != "edge-vault-renamed" {
		t.Errorf("updated name = %q, want edge-vault-renamed", updated.Name)
	}

	// delete -> 204
	resp = h.Do(t, itest.Request{Method: http.MethodDelete, Path: pathEntities + "/" + uuid})
	itest.AssertStatus(t, resp, http.StatusNoContent)

	// get after delete -> 404 (v1 envelope)
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathEntities + "/" + uuid})
	itest.AssertV1Error(t, resp, http.StatusNotFound)
}

// --- location operations ---------------------------------------------------

func TestEntityV1LocationOperations(t *testing.T) {
	h := startEntity(t)
	uuid := createEntity(t, h, "loc-host")
	loc := pathEntities + "/" + uuid + "/locations"

	// Location detail -> 200 with the contract shape (placeholder content).
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: loc, Body: mdl.LocationDetailRequestDto{
		LocationAttributes: []mdl.RequestAttribute{},
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
	var detail mdl.LocationDetailResponseDto
	resp.JSON(t, &detail)
	if detail.Certificates == nil {
		t.Errorf("location detail certificates is null, want an array: %s", resp.Body)
	}

	// Push certificate -> 200; missing certificate -> 400.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: loc + "/push", Body: mdl.PushCertificateRequestDto{
		Certificate:        "cGxhY2Vob2xkZXItY2VydA==", // base64 "placeholder-cert"
		LocationAttributes: []mdl.RequestAttribute{},
		PushAttributes:     []mdl.RequestAttribute{},
	}})
	itest.AssertStatus(t, resp, http.StatusOK)

	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: loc + "/push", Body: mdl.PushCertificateRequestDto{
		LocationAttributes: []mdl.RequestAttribute{}, PushAttributes: []mdl.RequestAttribute{},
	}})
	itest.AssertV1Error(t, resp, http.StatusBadRequest)

	// Remove certificate -> 200.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: loc + "/remove", Body: mdl.RemoveCertificateRequestDto{
		CertificateMetadata: []mdl.MetadataAttribute{}, LocationAttributes: []mdl.RequestAttribute{},
	}})
	itest.AssertStatus(t, resp, http.StatusOK)

	// Generate CSR -> 200, returns a non-empty CSR placeholder.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: loc + "/csr", Body: mdl.GenerateCsrRequestDto{
		LocationAttributes: []mdl.RequestAttribute{}, CsrAttributes: []mdl.RequestAttribute{},
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
	var csr mdl.GenerateCsrResponseDto
	resp.JSON(t, &csr)
	if csr.Csr == "" {
		t.Errorf("generateCsr returned empty csr: %s", resp.Body)
	}

	// Location op against an unknown entity -> 404.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathEntities + "/" + unknownEntity + "/locations", Body: mdl.LocationDetailRequestDto{
		LocationAttributes: []mdl.RequestAttribute{},
	}})
	itest.AssertV1Error(t, resp, http.StatusNotFound)
}

// --- attribute + validation endpoints --------------------------------------

func TestEntityV1Attributes(t *testing.T) {
	h := startEntity(t)

	// Per-kind attribute schema -> 200, a JSON array (never null).
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: base + "/" + entityKind + "/attributes"})
	itest.AssertStatus(t, resp, http.StatusOK)
	var attrs []any
	resp.JSON(t, &attrs)
	if attrs == nil {
		t.Errorf("%s/attributes returned null, want a JSON array", entityKind)
	}

	// Validate per-kind attributes (no provider wired -> 200).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: base + "/" + entityKind + "/attributes/validate", Body: []mdl.RequestAttribute{}})
	itest.AssertStatus(t, resp, http.StatusOK)

	// Per-entity location attribute schemas -> 200.
	uuid := createEntity(t, h, "attr-host")
	loc := pathEntities + "/" + uuid
	for _, p := range []string{
		loc + "/location/attributes",
		loc + "/locations/push/attributes",
		loc + "/locations/csr/attributes",
	} {
		resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: p})
		itest.AssertStatus(t, resp, http.StatusOK)
	}
}

// --- error path: create validation -----------------------------------------

func TestEntityV1CreateInvalid(t *testing.T) {
	h := startEntity(t)
	// Explicit empty/blank kind (sent as "", not omitted) -> 400.
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathEntities, Body: entityReq("blank-kind", "")})
	itest.AssertV1Error(t, resp, http.StatusBadRequest)
}
