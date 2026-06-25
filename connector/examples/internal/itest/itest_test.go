package itest_test

import (
	"net/http"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
)

// TestHarnessSmoke is the harness's own acceptance test: it starts a real
// example (secret-v1) in a container through the harness, asserts the health
// endpoint is 200/conformant, exercises the HTTP + JSON helpers against
// /v2/info, and checks the captured logs satisfy the connector.log contract.
// Skips cleanly with no Docker or under -short.
func TestHarnessSmoke(t *testing.T) {
	h := itest.Start(t, itest.Example{
		Path: "connector/examples/secret-v1",
		Env: map[string]string{
			"APP_USERNAME": "u",
			"APP_PASSWORD": "p",
		},
	})

	// Health body conforms (mandatory liveness/readiness components present).
	h.AssertHealthy(t, "/v2/health")

	// HTTP + JSON helpers work against a real endpoint.
	var info map[string]any
	status := h.GetJSON(t, http.MethodGet, "/v2/info", nil, &info)
	itest.AssertStatus(t, itest.Response{Status: status}, http.StatusOK)
	conn, _ := info["connector"].(map[string]any)
	if conn == nil || conn["id"] == nil {
		t.Errorf("/v2/info missing connector.id: %v", info)
	}

	// Correlation-Id is echoed; trace context headers are not propagated back.
	resp := h.Do(t, itest.Request{
		Method:  http.MethodGet,
		Path:    "/v2/health",
		Headers: map[string]string{"Correlation-Id": "smoke-corr"},
	})
	if got := resp.Header.Get("Correlation-Id"); got != "smoke-corr" {
		t.Errorf("Correlation-Id = %q, want echo of inbound", got)
	}

	// Captured container logs are conformant connector.log v1.
	h.AssertLogsConform(t)
}
