package itest

import (
	"encoding/json"
	"mime"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// AssertStatus fails the test when resp.Status != want, printing the body
// (the most useful context for a wrong status). Returns whether the status
// matched, so callers can bail before further assertions on the body.
func AssertStatus(t *testing.T, resp Response, want int) bool {
	t.Helper()
	if resp.Status != want {
		t.Errorf("status = %d, want %d\nbody: %s", resp.Status, want, resp.Body)
		return false
	}
	return true
}

// AssertProblem asserts an RFC 9457 problem response: both the HTTP status
// and the ProblemDetail errorCode extension (the v2-family error envelope
// emitted by shared.WriteProblem). Asserting the code alongside the status
// catches spec/model/handler drift that a status-only check would miss.
//
// On a status mismatch it stops before parsing the body — a wrong-status
// response is often non-JSON (or empty), and a secondary "not JSON" error
// would only mask the primary status failure.
func AssertProblem(t *testing.T, resp Response, wantStatus int, wantCode string) {
	t.Helper()
	if !AssertStatus(t, resp, wantStatus) {
		return
	}
	var pd struct {
		ErrorCode string `json:"errorCode"`
	}
	if err := json.Unmarshal(resp.Body, &pd); err != nil {
		t.Errorf("error response body is not JSON: %v\nbody: %s", err, resp.Body)
		return
	}
	if pd.ErrorCode != wantCode {
		t.Errorf("errorCode = %q, want %q\nbody: %s", pd.ErrorCode, wantCode, resp.Body)
	}
}

// AssertV1Error asserts a v1-family error response: the HTTP status and a
// non-empty ErrorMessageDto `message` field (the shape shared.WriteV1Error
// emits for 4xx/5xx other than 422). This is the v1 analog of AssertProblem;
// v1-family connectors render their own message-based envelope rather than
// the RFC 9457 ProblemDetail used by v2-family specs. Returns the message
// (empty on failure).
//
// Note: 422 validation responses use a bare []string body, not this shape —
// use AssertV1ValidationErrors for those.
func AssertV1Error(t *testing.T, resp Response, wantStatus int) string {
	t.Helper()
	if !AssertStatus(t, resp, wantStatus) {
		return ""
	}
	var em struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(resp.Body, &em); err != nil {
		t.Errorf("v1 error body is not JSON: %v\nbody: %s", err, resp.Body)
		return ""
	}
	if em.Message == "" {
		t.Errorf("v1 error body has empty message\nbody: %s", resp.Body)
	}
	return em.Message
}

// AssertV1MessageEnvelope is the strict form of AssertV1Error: status, a
// Content-Type of exactly application/json (never application/problem+json),
// and a body that is exactly {"message": "<non-empty>"} — no RFC 9457 keys
// (type/status/errorCode/...). Use it once per example to pin the v1-family
// envelope; use AssertV1Error for the remaining error paths. Returns the message.
func AssertV1MessageEnvelope(t *testing.T, resp Response, wantStatus int) string {
	t.Helper()
	if !AssertStatus(t, resp, wantStatus) {
		return ""
	}
	assertV1ContentType(t, resp, "v1 ErrorMessageDto, not problem+json")
	var m map[string]any
	if err := json.Unmarshal(resp.Body, &m); err != nil {
		t.Errorf("v1 error body is not a JSON object: %v\nbody: %s", err, resp.Body)
		return ""
	}
	msg, _ := m["message"].(string)
	if len(m) != 1 || msg == "" {
		t.Errorf("v1 error body = %s, want exactly {\"message\": \"<non-empty>\"}", resp.Body)
	}
	return msg
}

// AssertV1ValidationErrors asserts the v1-family 422 shape: HTTP 422, a
// Content-Type of exactly application/json, and a non-empty JSON string array
// body (shared.WriteV1ValidationErrors, and the 422 branch of
// shared.WriteV1Error for decode failures). Returns the messages, or nil
// after reporting a failure.
func AssertV1ValidationErrors(t *testing.T, resp Response) []string {
	t.Helper()
	if !AssertStatus(t, resp, http.StatusUnprocessableEntity) {
		return nil
	}
	assertV1ContentType(t, resp, "v1 422 []string, not problem+json")
	var msgs []string
	if err := json.Unmarshal(resp.Body, &msgs); err != nil {
		t.Errorf("v1 422 body is not a JSON string array: %v\nbody: %s", err, resp.Body)
		return nil
	}
	if len(msgs) == 0 {
		t.Errorf("v1 422 body is an empty array, want at least one message\nbody: %s", resp.Body)
	}
	return msgs
}

// assertV1ContentType fails unless the response media type is exactly
// application/json, the only error content type the v1-family specs declare.
func assertV1ContentType(t *testing.T, resp Response, what string) {
	t.Helper()
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (%s)", resp.Header.Get("Content-Type"), what)
	}
}

// AssertHealthy fetches path and verifies the response is a conformant
// health body for the spec version implied by the path:
//
//   - /v2/health* : status 200, JSON status "UP", and the mandatory components.
//   - /v1/health  : status 200, JSON status "ok", and parts.liveness.status
//     and parts.readiness.status both "ok". The v1 specs make parts optional;
//     the parts check pins the shared layer (shared/health.go marshalHealth),
//     which every v1-family example uses, not a spec mandate.
//
// It returns the decoded body for any further example-specific assertions.
func (h *Harness) AssertHealthy(t *testing.T, path string) map[string]any {
	t.Helper()
	resp := h.Do(t, Request{Method: "GET", Path: path})
	AssertStatus(t, resp, 200)

	var body map[string]any
	resp.JSON(t, &body)

	switch {
	case strings.HasPrefix(path, "/v2/health"):
		if body["status"] != "UP" {
			t.Errorf("health status = %v, want UP\nbody: %s", body["status"], resp.Body)
		}
		comps, _ := body["components"].(map[string]any)
		for _, name := range mandatoryComponents(path) {
			if _, ok := comps[name]; !ok {
				t.Errorf("%s missing mandatory component %q\nbody: %s", path, name, resp.Body)
			}
		}
	default: // v1
		if body["status"] != "ok" {
			t.Errorf("v1 health status = %v, want ok\nbody: %s", body["status"], resp.Body)
		}
		parts, _ := body["parts"].(map[string]any)
		for _, name := range []string{"liveness", "readiness"} {
			part, _ := parts[name].(map[string]any)
			if part["status"] != "ok" {
				t.Errorf("%s parts.%s.status = %v, want ok\nbody: %s", path, name, part["status"], resp.Body)
			}
		}
	}
	return body
}

// AssertNotServed asserts that GET on each path is the router's own 404 for
// an unmatched route: status 404 and no JSON body (the stdlib mux answers
// text/plain; a JSON 404 would mean a mounted handler rendered it). Use it for
// surfaces an example must not expose, e.g. /v2/info on a v1-family connector.
func (h *Harness) AssertNotServed(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		resp := h.Do(t, Request{Method: http.MethodGet, Path: path})
		if resp.Status != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404 (route not served)\nbody: %s", path, resp.Status, resp.Body)
			continue
		}
		if ct := resp.Header.Get("Content-Type"); isJSONMediaType(ct) {
			t.Errorf("GET %s 404 Content-Type = %q, want the mux's non-JSON 404 (a mounted handler answered)\nbody: %s", path, ct, resp.Body)
		}
	}
}

func mandatoryComponents(path string) []string {
	if probe, ok := strings.CutPrefix(path, "/v2/health/"); ok {
		return []string{probe}
	}
	return []string{"liveness", "readiness"}
}

// connectorLogSchema matches the connector.log v1 envelope's defining marker.
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
		if l, ok := parseLogLine(raw); ok {
			out = append(out, l)
		}
	}
	return out
}

// parseLogLine decodes one raw output line as a connector.log v1 entry,
// reporting false for non-JSON or non-envelope lines.
func parseLogLine(raw string) (LogLine, bool) {
	if !connectorLogSchema.MatchString(raw) {
		return nil, false
	}
	var l LogLine
	if err := json.Unmarshal([]byte(raw), &l); err != nil {
		return nil, false
	}
	return l, true
}

// logWaitTimeout bounds AssertLogged's wait for container output: the log
// consumer receives lines asynchronously, so a line written while serving a
// request can arrive shortly after the client has its response.
const logWaitTimeout = 5 * time.Second

// logTailLines bounds AssertLogged's failure diagnostic: it reports how many
// lines carried the message but prints only the last few of them.
const logTailLines = 3

// AssertLogged returns the first connector.log line whose "message" equals
// message and that carries every key in want. A want key is looked up among
// the line's top-level fields first (e.g. correlation_id, trace_id) and, when
// absent there, inside "attributes" (e.g. error_code, status). Values are
// compared after normalising want through a JSON round-trip, so a Go int 404
// matches the decoded JSON number while a string "404" does not. It polls the
// captured logs for up to logWaitTimeout, parsing only the complete lines
// added since the previous poll, then fails with the number of lines that
// carried the message and the last logTailLines of them, so the mismatch is
// visible. Returns nil on failure.
func (h *Harness) AssertLogged(t *testing.T, message string, want map[string]any) LogLine {
	t.Helper()
	want = normalizeJSON(t, want)
	deadline := time.Now().Add(logWaitTimeout)
	var (
		cursor      int       // bytes of h.Logs() already parsed (whole lines only)
		sameCount   int       // lines seen so far carrying message
		sameMessage []LogLine // the last logTailLines of them
	)
	for {
		logs := h.Logs() // append-only, so earlier offsets stay valid
		// Parse up to the last newline; a partial trailing line waits for
		// its newline on a later poll.
		if end := strings.LastIndexByte(logs[cursor:], '\n'); end >= 0 {
			chunk := logs[cursor : cursor+end+1]
			cursor += end + 1
			for _, raw := range splitLines(chunk) {
				l, ok := parseLogLine(raw)
				if !ok || l["message"] != message {
					continue
				}
				if lineMatches(l, want) {
					return l
				}
				sameCount++
				sameMessage = append(sameMessage, l)
				if len(sameMessage) > logTailLines {
					sameMessage = sameMessage[1:]
				}
			}
		}
		if time.Now().After(deadline) {
			t.Errorf("no connector.log line with message %q and fields %v within %s; %d line(s) with that message, last %d: %v",
				message, want, logWaitTimeout, sameCount, len(sameMessage), sameMessage)
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// lineMatches reports whether l carries every key in want (top-level field
// first, then "attributes") with a deeply equal value. want must already be
// JSON-normalised (normalizeJSON).
func lineMatches(l LogLine, want map[string]any) bool {
	attrs, _ := l["attributes"].(map[string]any)
	for k, v := range want {
		got, ok := l[k]
		if !ok {
			got, ok = attrs[k]
		}
		if !ok || !reflect.DeepEqual(got, v) {
			return false
		}
	}
	return true
}

// normalizeJSON round-trips want through encoding/json so its values have the
// same dynamic types as a decoded log line (float64 numbers, []any, ...).
func normalizeJSON(t *testing.T, want map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("itest: marshal log match keys %v: %v", want, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("itest: normalise log match keys %v: %v", want, err)
	}
	return out
}

// AssertMetric fetches GET /v1/metrics (expects 200) and fails unless some
// exposition line starts with series, e.g.
// `connector_events_total{event="get_rules",outcome="ok"}` (labels are
// rendered sorted by name). The match is a plain prefix match: pass the full
// label set including the closing `}` (or the full line prefix you mean),
// otherwise `{a="x"` also matches `{a="xy"}`. Leave the `}` off only when a
// prefix match is intended (e.g. `app_build_info{commit="dev"`). It asserts
// the series is present, not its value; for counter vectors that are never
// pre-initialised, presence proves at least one increment. On failure it
// prints the lines of the same metric family for context. Returns the full
// exposition for further checks.
func (h *Harness) AssertMetric(t *testing.T, series string) string {
	t.Helper()
	resp := h.Do(t, Request{Method: http.MethodGet, Path: "/v1/metrics"})
	if !AssertStatus(t, resp, http.StatusOK) {
		return ""
	}
	body := string(resp.Body)
	family, _, _ := strings.Cut(series, "{")
	var related []string
	for _, line := range splitLines(body) {
		if strings.HasPrefix(line, series) {
			return body
		}
		if strings.HasPrefix(line, family) {
			related = append(related, line)
		}
	}
	t.Errorf("/v1/metrics has no series starting with %q\n%s lines:\n%s", series, family, strings.Join(related, "\n"))
	return body
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
