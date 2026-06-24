package itest

import (
	"encoding/json"
	"regexp"
	"testing"
)

// AssertStatus fails the test when resp.Status != want, printing the body
// (the most useful context for a wrong status).
func AssertStatus(t *testing.T, resp Response, want int) {
	t.Helper()
	if resp.Status != want {
		t.Errorf("status = %d, want %d\nbody: %s", resp.Status, want, resp.Body)
	}
}

// AssertHealthy fetches path and verifies the response is a conformant
// health body for the spec version implied by the path:
//
//   - /v2/health* : status 200, JSON status "UP", and — for the aggregate
//     /v2/health — the mandatory liveness and readiness components present.
//   - /v1/health  : status 200, JSON status "ok".
//
// It returns the decoded body for any further example-specific assertions.
func (h *Harness) AssertHealthy(t *testing.T, path string) map[string]any {
	t.Helper()
	resp := h.Do(t, Request{Method: "GET", Path: path})
	AssertStatus(t, resp, 200)

	var body map[string]any
	resp.JSON(t, &body)

	switch {
	case path == "/v2/health":
		if body["status"] != "UP" {
			t.Errorf("health status = %v, want UP\nbody: %s", body["status"], resp.Body)
		}
		comps, _ := body["components"].(map[string]any)
		for _, name := range []string{"liveness", "readiness"} {
			if _, ok := comps[name]; !ok {
				t.Errorf("aggregate /v2/health missing mandatory component %q\nbody: %s", name, resp.Body)
			}
		}
	case len(path) >= 9 && path[:9] == "/v2/healt":
		// probe endpoints (/v2/health/liveness|readiness): status only.
		if body["status"] == nil {
			t.Errorf("health body has no status\nbody: %s", resp.Body)
		}
	default: // v1
		if body["status"] != "ok" {
			t.Errorf("v1 health status = %v, want ok\nbody: %s", body["status"], resp.Body)
		}
	}
	return body
}

// connectorLogLine matches the connector.log v1 envelope's defining marker.
var connectorLogSchema = regexp.MustCompile(`"schema":\{"name":"connector\.log","version":1\}`)

// LogLine is one parsed connector.log v1 entry from the container's output.
type LogLine map[string]any

// LogLines parses the container stdout captured so far into connector.log v1
// entries, skipping any non-JSON or non-envelope lines. Use it to assert the
// logging/tracing contract (schema, severity, trace_id/span_id/correlation_id).
func (h *Harness) LogLines(t *testing.T) []LogLine {
	t.Helper()
	var out []LogLine
	for _, raw := range splitLines(h.Logs()) {
		if !connectorLogSchema.MatchString(raw) {
			continue
		}
		var m LogLine
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			continue
		}
		out = append(out, m)
	}
	return out
}

// AssertLogsConform verifies every connector.log line carries the required
// envelope fields (schema/@timestamp/severity/message/service.name) and that
// each satisfies the trace-or-correlation invariant: trace_id+span_id, or
// correlation_id, or both. Fails the test on any violation. Returns the
// parsed lines for further assertions.
func (h *Harness) AssertLogsConform(t *testing.T) []LogLine {
	t.Helper()
	lines := h.LogLines(t)
	if len(lines) == 0 {
		t.Error("itest: no connector.log lines captured")
	}
	hex32 := regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex16 := regexp.MustCompile(`^[0-9a-f]{16}$`)
	for i, l := range lines {
		if l["@timestamp"] == nil || l["message"] == nil {
			t.Errorf("log line %d missing @timestamp/message: %v", i, l)
		}
		if sev, _ := l["severity"].(string); !validSeverity(sev) {
			t.Errorf("log line %d severity = %q, not in connector.log enum", i, sev)
		}
		if svc, _ := l["service"].(map[string]any); svc == nil || svc["name"] == nil {
			t.Errorf("log line %d missing service.name: %v", i, l)
		}
		tid, _ := l["trace_id"].(string)
		sid, _ := l["span_id"].(string)
		cid, _ := l["correlation_id"].(string)
		hasTrace := hex32.MatchString(tid) && hex16.MatchString(sid)
		if !hasTrace && cid == "" {
			t.Errorf("log line %d violates trace-or-correlation invariant: %v", i, l)
		}
	}
	return lines
}

func validSeverity(s string) bool {
	switch s {
	case "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL":
		return true
	}
	return false
}

// splitLines splits on newlines, dropping the trailing empty element.
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
