package main_test

// Integration tests for the notification-v1 example (in-memory instance
// store), driven over the public HTTP interface via the shared
// testcontainers harness. Requests/responses use the generated
// connector/model/notification/v1 types. Skips with no Docker or under
// -short.
//
// notification-v1 is a v1-family connector: info at GET /v1
// (listSupportedFunctions), health at GET /v1/health, and the v1 error
// envelope (ErrorMessageDto) — so error paths use itest.AssertV1Error, not
// the RFC 9457 AssertProblem.

import (
	"net/http"
	"slices"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/notification/v1"
)

const (
	fgNotification   = "notificationProvider"
	notificationKind = "email"

	base          = "/v1/notificationProvider"
	pathInstances = base + "/notifications"
)

func startNotification(t *testing.T) *itest.Harness {
	t.Helper()
	return itest.Start(t, itest.Example{
		Path:       "connector/examples/notification-v1",
		HealthPath: "/v1/health",
	})
}

func instanceReq(name, kind string) mdl.NotificationProviderInstanceRequestDto {
	return mdl.NotificationProviderInstanceRequestDto{
		Name:       name,
		Kind:       kind,
		Attributes: []mdl.RequestAttribute{},
	}
}

// createInstance creates an instance and returns its assigned uuid.
func createInstance(t *testing.T, h *itest.Harness, name string) string {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathInstances, Body: instanceReq(name, notificationKind)})
	itest.AssertStatus(t, resp, http.StatusOK)
	var inst mdl.NotificationProviderInstanceDto
	resp.JSON(t, &inst)
	if inst.Uuid == "" {
		t.Fatalf("create returned no uuid\nbody: %s", resp.Body)
	}
	if inst.Name != name {
		t.Errorf("created name = %q, want %q", inst.Name, name)
	}
	return inst.Uuid
}

// --- info + health ---------------------------------------------------------

func TestNotificationV1InfoAndHealth(t *testing.T) {
	h := startNotification(t)

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
		if g.FunctionGroupCode == fgNotification {
			found = true
			if !slices.Contains(g.Kinds, notificationKind) {
				t.Errorf("%s kinds = %v, want to contain %q", fgNotification, g.Kinds, notificationKind)
			}
		}
	}
	if !found {
		t.Errorf("/v1 missing %q function group: %+v", fgNotification, groups)
	}

	h.AssertLogsConform(t)
}

// --- instance store lifecycle ----------------------------------------------

func TestNotificationV1InstanceLifecycle(t *testing.T) {
	h := startNotification(t)

	uuid := createInstance(t, h, "alerts")

	// get
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathInstances + "/" + uuid})
	itest.AssertStatus(t, resp, http.StatusOK)
	var got mdl.NotificationProviderInstanceDto
	resp.JSON(t, &got)
	if got.Uuid != uuid || got.Name != "alerts" {
		t.Errorf("get = %+v, want uuid %q name alerts", got, uuid)
	}

	// list contains it
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathInstances})
	itest.AssertStatus(t, resp, http.StatusOK)
	var list []mdl.NotificationProviderInstanceDto
	resp.JSON(t, &list)
	if !slices.ContainsFunc(list, func(i mdl.NotificationProviderInstanceDto) bool { return i.Uuid == uuid }) {
		t.Errorf("list does not contain created instance %q: %+v", uuid, list)
	}

	// update
	resp = h.Do(t, itest.Request{Method: http.MethodPut, Path: pathInstances + "/" + uuid, Body: instanceReq("alerts-renamed", notificationKind)})
	itest.AssertStatus(t, resp, http.StatusOK)
	var updated mdl.NotificationProviderInstanceDto
	resp.JSON(t, &updated)
	if updated.Name != "alerts-renamed" {
		t.Errorf("updated name = %q, want alerts-renamed", updated.Name)
	}

	// delete -> 204
	resp = h.Do(t, itest.Request{Method: http.MethodDelete, Path: pathInstances + "/" + uuid})
	itest.AssertStatus(t, resp, http.StatusNoContent)

	// get after delete -> 404 (v1 error envelope)
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: pathInstances + "/" + uuid})
	itest.AssertV1Error(t, resp, http.StatusNotFound)
}

// --- send notification -----------------------------------------------------

func TestNotificationV1Send(t *testing.T) {
	h := startNotification(t)
	uuid := createInstance(t, h, "send-target")

	email := "ops@example.test"
	notify := mdl.NotificationProviderNotifyRequestDto{
		EventType: "certificate-expiring",
		Recipients: []mdl.NotificationRecipientDto{
			{Name: "ops-team", Email: &email},
		},
	}
	// send -> 204
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathInstances + "/" + uuid + "/notify", Body: notify})
	itest.AssertStatus(t, resp, http.StatusNoContent)

	// send to unknown instance -> 404
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathInstances + "/00000000-0000-0000-0000-000000000000/notify", Body: notify})
	itest.AssertV1Error(t, resp, http.StatusNotFound)
}

// --- attribute + mapping endpoints -----------------------------------------

func TestNotificationV1Attributes(t *testing.T) {
	h := startNotification(t)

	// Per-kind attribute schema -> 200 (array).
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: base + "/" + notificationKind + "/attributes"})
	itest.AssertStatus(t, resp, http.StatusOK)
	var attrs []any
	resp.JSON(t, &attrs)

	// Mapping attributes -> 200 (array).
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: base + "/" + notificationKind + "/attributes/mapping"})
	itest.AssertStatus(t, resp, http.StatusOK)
	var mapping []any
	resp.JSON(t, &mapping)

	// Validate attributes (no attribute provider wired -> 200).
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: base + "/" + notificationKind + "/attributes/validate", Body: []mdl.RequestAttribute{}})
	itest.AssertStatus(t, resp, http.StatusOK)
}

// --- error path: create validation -----------------------------------------

func TestNotificationV1CreateInvalid(t *testing.T) {
	h := startNotification(t)

	// Missing kind -> 400 INVALID_REQUEST (v1 envelope).
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathInstances, Body: instanceReq("no-kind", "")})
	itest.AssertV1Error(t, resp, http.StatusBadRequest)
}
