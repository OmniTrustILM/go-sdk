package shared

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// decodeProblem renders err via WriteProblem against a fresh request/recorder
// and decodes the body into a generic map (so presence/absence of optional
// fields can be asserted directly) alongside the recorder for status/header
// checks.
func decodeProblem(t *testing.T, err error, path string) (map[string]any, *httptest.ResponseRecorder) {
	t.Helper()
	if path == "" {
		path = "/v3/certificates/123"
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	WriteProblem(rec, req, err)

	var body map[string]any
	if decErr := json.Unmarshal(rec.Body.Bytes(), &body); decErr != nil {
		t.Fatalf("decode problem body: %v (body=%s)", decErr, rec.Body.String())
	}
	return body, rec
}

func TestWriteProblemRequiredFieldsAlwaysPresent(t *testing.T) {
	err := NotFound("CERTIFICATE_NOT_FOUND", "certificate not found")
	body, rec := decodeProblem(t, err, "/v3/certificates/abc")

	if got := rec.Header().Get("Content-Type"); got != ProblemContentType {
		t.Errorf("Content-Type = %q, want %q", got, ProblemContentType)
	}

	for _, field := range []string{"type", "title", "status", "detail", "errorCode", "timestamp", "retryable"} {
		if _, ok := body[field]; !ok {
			t.Errorf("required field %q missing from problem document: %v", field, body)
		}
	}

	typ, _ := body["type"].(string)
	const wantPrefix = "https://docs.otilm.com/problems/"
	if len(typ) < len(wantPrefix) || typ[:len(wantPrefix)] != wantPrefix {
		t.Errorf("type = %q, want a URI with prefix %q", typ, wantPrefix)
	}

	if _, ok := body["retryable"].(bool); !ok {
		t.Errorf("retryable field is not a bool: %v", body["retryable"])
	}

	ts, _ := body["timestamp"].(string)
	if ts == "" {
		t.Error("timestamp is empty, want a non-zero RFC3339 timestamp")
	}

	title, ok := body["title"].(string)
	if !ok || title == "" {
		t.Errorf("title = %v, want a non-empty string", body["title"])
	}
	detail, ok := body["detail"].(string)
	if !ok || detail == "" {
		t.Errorf("detail = %v, want a non-empty string", body["detail"])
	}
}

// TestProblemDetailTitleDetailArePointers locks in the source-compatible
// field types on the exported ProblemDetail struct: Title and Detail must
// remain *string, not string, so that existing external callers assigning
// &s or doing nil checks keep compiling. WriteProblem must still
// populate them with non-nil pointers to non-empty strings.
func TestProblemDetailTitleDetailArePointers(t *testing.T) {
	var pd ProblemDetail
	var _ *string = pd.Title
	var _ *string = pd.Detail

	err := NotFound("CERTIFICATE_NOT_FOUND", "certificate not found")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v3/certificates/abc", nil)
	WriteProblem(rec, req, err)

	var wire ProblemDetail
	if decErr := json.Unmarshal(rec.Body.Bytes(), &wire); decErr != nil {
		t.Fatalf("decode problem body into ProblemDetail: %v (body=%s)", decErr, rec.Body.String())
	}
	if wire.Title == nil || *wire.Title == "" {
		t.Errorf("Title = %v, want non-nil pointer to a non-empty string", wire.Title)
	}
	if wire.Detail == nil || *wire.Detail == "" {
		t.Errorf("Detail = %v, want non-nil pointer to a non-empty string", wire.Detail)
	}
}

func TestWriteProblemOptionalFieldsOmittedWhenUnset(t *testing.T) {
	err := Invalid("VALIDATION_FAILED", "bad input")
	body, _ := decodeProblem(t, err, "/v3/certificates")

	if _, ok := body["retryAfterSeconds"]; ok {
		t.Errorf("retryAfterSeconds present for a non-retryable error: %v", body["retryAfterSeconds"])
	}
	if _, ok := body["causes"]; ok {
		t.Errorf("causes present when none were set: %v", body["causes"])
	}
	instance, ok := body["instance"].(string)
	if !ok {
		t.Fatalf("instance missing: %v", body)
	}
	if instance != "/v3/certificates" {
		t.Errorf("instance = %q, want request path %q", instance, "/v3/certificates")
	}
}

func TestWithRetryablePromotesTopLevel(t *testing.T) {
	err := Unavailable("UPSTREAM_ERROR", "backend down").WithRetryable(true)
	body, _ := decodeProblem(t, err, "")

	if v, ok := body["retryable"].(bool); !ok || !v {
		t.Errorf("retryable = %v, want top-level true", body["retryable"])
	}
	ras, ok := body["retryAfterSeconds"].(float64)
	if !ok {
		t.Fatalf("retryAfterSeconds missing/wrong type: %v", body["retryAfterSeconds"])
	}
	if ras != 30 {
		t.Errorf("retryAfterSeconds = %v, want default 30", ras)
	}
	if props, ok := body["properties"].(map[string]any); ok {
		if _, leaked := props["retryable"]; leaked {
			t.Error("retryable leaked into properties")
		}
	}
}

func TestWithRetryAfterSecondsOverridesDefault(t *testing.T) {
	err := Unavailable("UPSTREAM_ERROR", "backend down").WithRetryable(true).WithRetryAfterSeconds(5)
	body, _ := decodeProblem(t, err, "")

	ras, ok := body["retryAfterSeconds"].(float64)
	if !ok || ras != 5 {
		t.Errorf("retryAfterSeconds = %v, want 5", body["retryAfterSeconds"])
	}
}

// TestWithRetryAfterSecondsOnNonRetryableStaysInProperties proves an
// explicit backoff hint on a non-retryable problem is not silently lost: it
// is not promoted top-level (a non-retryable problem advertises no retry
// delay) but remains visible under "properties".
func TestWithRetryAfterSecondsOnNonRetryableStaysInProperties(t *testing.T) {
	err := Invalid("VALIDATION_FAILED", "bad input").WithRetryAfterSeconds(10)
	body, _ := decodeProblem(t, err, "")

	if _, ok := body["retryAfterSeconds"]; ok {
		t.Errorf("retryAfterSeconds promoted top-level on a non-retryable problem: %v", body["retryAfterSeconds"])
	}
	props, ok := body["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties absent; the unpromoted hint must stay visible there")
	}
	if got, _ := props["retryAfterSeconds"].(float64); got != 10 {
		t.Errorf("properties.retryAfterSeconds = %v, want 10", props["retryAfterSeconds"])
	}
}

// TestWithRetryableFalseOverridesRetryableDefault proves an explicit
// WithRetryable(false) wins over a registry default of retryable=true, and
// that no retryAfterSeconds renders for the now non-retryable problem.
func TestWithRetryableFalseOverridesRetryableDefault(t *testing.T) {
	err := Unavailable("SERVICE_UNAVAILABLE", "down for maintenance").WithRetryable(false)
	body, _ := decodeProblem(t, err, "")

	v, ok := body["retryable"].(bool)
	if !ok || v {
		t.Errorf("retryable = %v (present=%v), want explicit false to override the registry default", body["retryable"], ok)
	}
	if _, ok := body["retryAfterSeconds"]; ok {
		t.Errorf("retryAfterSeconds present on a non-retryable problem: %v", body["retryAfterSeconds"])
	}
	if _, ok := body["properties"]; ok {
		t.Errorf("properties present: the consumed retryable key must be stripped, got %v", body["properties"])
	}
}

func TestWithCausesPromotesTopLevel(t *testing.T) {
	causes := []Cause{{Name: "csr", Reason: "malformed PEM", Rule: "pem-decodable"}}
	err := Invalid("VALIDATION_FAILED", "bad csr").WithCauses(causes)
	body, _ := decodeProblem(t, err, "")

	rawCauses, ok := body["causes"].([]any)
	if !ok || len(rawCauses) != 1 {
		t.Fatalf("causes = %v, want one entry", body["causes"])
	}
	entry, ok := rawCauses[0].(map[string]any)
	if !ok {
		t.Fatalf("causes[0] is not an object: %v", rawCauses[0])
	}
	if entry["name"] != "csr" || entry["reason"] != "malformed PEM" || entry["rule"] != "pem-decodable" {
		t.Errorf("causes[0] = %v, want name/reason/rule from Cause", entry)
	}
	if props, ok := body["properties"].(map[string]any); ok {
		if _, leaked := props["causes"]; leaked {
			t.Error("causes leaked into properties")
		}
	}
}

// TestWithCausesTypedEmptyIsStrippedNotLeaked exercises a correctly-typed but
// empty []Cause (WithCauses([]Cause{})): len==0 means "causes" itself must
// not render at top level, but the key's value still has the expected type,
// so it must be stripped from "properties" rather than leaking there as
// causes:[].
func TestWithCausesTypedEmptyIsStrippedNotLeaked(t *testing.T) {
	err := Invalid("VALIDATION_FAILED", "bad csr").WithCauses([]Cause{})
	body, _ := decodeProblem(t, err, "")

	if _, ok := body["causes"]; ok {
		t.Errorf("causes = %v, want omitted at top level for an empty slice", body["causes"])
	}
	if props, ok := body["properties"].(map[string]any); ok {
		if _, leaked := props["causes"]; leaked {
			t.Errorf("typed-empty causes leaked into properties: %v", props)
		}
	}
}

func TestWithPropertyStillNestsArbitraryKeys(t *testing.T) {
	err := Invalid("VALIDATION_FAILED", "bad body").
		WithProperty("field", "csr").
		WithProperty("expected_type", "string")
	body, _ := decodeProblem(t, err, "")

	props, ok := body["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing/wrong type: %v", body["properties"])
	}
	if props["field"] != "csr" {
		t.Errorf("properties[field] = %v, want %q", props["field"], "csr")
	}
	if props["expected_type"] != "string" {
		t.Errorf("properties[expected_type] = %v, want %q", props["expected_type"], "string")
	}
	for _, known := range []string{"retryable", "retryAfterSeconds", "causes"} {
		if _, leaked := props[known]; leaked {
			t.Errorf("known key %q leaked into properties: %v", known, props)
		}
	}
}

func TestWithPropertyMistypedRetryableFallsBackAndIsPreserved(t *testing.T) {
	// SERVICE_UNAVAILABLE's registry default is retryable: true, so the
	// mistyped string property must fall back to that default rather than
	// being coerced or defaulting to false.
	err := Unavailable("SERVICE_UNAVAILABLE", "backend down").WithProperty("retryable", "yes-please")
	body, _ := decodeProblem(t, err, "")

	if v, ok := body["retryable"].(bool); !ok || !v {
		t.Errorf("retryable = %v, want top-level registry default true", body["retryable"])
	}
	props, ok := body["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing/wrong type: %v", body["properties"])
	}
	if props["retryable"] != "yes-please" {
		t.Errorf(`properties["retryable"] = %v, want the preserved string "yes-please"`, props["retryable"])
	}
}

func TestWithPropertyMistypedCausesIsPreserved(t *testing.T) {
	err := Invalid("VALIDATION_FAILED", "bad csr").WithProperty("causes", "oops")
	body, _ := decodeProblem(t, err, "")

	if _, ok := body["causes"]; ok {
		t.Errorf("causes present at top level for a mistyped value: %v", body["causes"])
	}
	props, ok := body["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing/wrong type: %v", body["properties"])
	}
	if props["causes"] != "oops" {
		t.Errorf(`properties["causes"] = %v, want the preserved string "oops"`, props["causes"])
	}
}

func TestWithPropertyMixedKnownAndArbitraryKeys(t *testing.T) {
	err := Invalid("VALIDATION_FAILED", "bad body").WithProperty("field", "x").WithRetryable(true)
	body, _ := decodeProblem(t, err, "")

	if v, ok := body["retryable"].(bool); !ok || !v {
		t.Errorf("retryable = %v, want top-level true", body["retryable"])
	}
	props, ok := body["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing/wrong type: %v", body["properties"])
	}
	if len(props) != 1 {
		t.Errorf("properties = %v, want exactly one entry (field)", props)
	}
	if props["field"] != "x" {
		t.Errorf(`properties["field"] = %v, want "x"`, props["field"])
	}
	if _, leaked := props["retryable"]; leaked {
		t.Error("retryable leaked into properties")
	}
}

func TestPropertiesOmittedWhenOnlyKnownKeysSet(t *testing.T) {
	err := Unavailable("UPSTREAM_ERROR", "backend down").WithRetryable(true).WithCauses([]Cause{{Name: "x", Reason: "y"}})
	body, _ := decodeProblem(t, err, "")

	if _, ok := body["properties"]; ok {
		t.Errorf("properties present when only known keys were set: %v", body["properties"])
	}
}

func TestResolveProblemTypeURI(t *testing.T) {
	cases := []struct {
		name      string
		errorCode string
		typeURI   string
		want      string
	}{
		{name: "registered common code", errorCode: "VALIDATION_FAILED", want: "https://docs.otilm.com/problems/common/VALIDATION_FAILED"},
		{name: "registered authority code", errorCode: "CSR_MALFORMED", want: "https://docs.otilm.com/problems/connector/authority/CSR_MALFORMED"},
		{name: "unregistered code falls back to common", errorCode: "WIDGET_EXPLODED", want: "https://docs.otilm.com/problems/common/WIDGET_EXPLODED"},
		{name: "about:blank resolves", errorCode: "VALIDATION_FAILED", typeURI: "about:blank", want: "https://docs.otilm.com/problems/common/VALIDATION_FAILED"},
		{name: "empty error code falls back to internal server error", errorCode: "", want: "https://docs.otilm.com/problems/common/INTERNAL_SERVER_ERROR"},
		{name: "explicit type URI takes precedence over the registry", errorCode: "VALIDATION_FAILED", typeURI: "https://example.com/custom-problem", want: "https://example.com/custom-problem"},
		{name: "unregistered code with unsafe characters is path-escaped", errorCode: "BAD CODE", want: "https://docs.otilm.com/problems/common/BAD%20CODE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveProblemTypeURI(tc.typeURI, tc.errorCode)
			if got != tc.want {
				t.Errorf("resolveProblemTypeURI(%q, %q) = %q, want %q", tc.typeURI, tc.errorCode, got, tc.want)
			}
			if got == "about:blank" {
				t.Errorf("resolveProblemTypeURI(%q, %q) resolved to about:blank", tc.typeURI, tc.errorCode)
			}
		})
	}
}

func TestRegistryDefaultsRetryable(t *testing.T) {
	retryableCodes := []string{"SERVICE_UNAVAILABLE", "REQUEST_TIMEOUT", "RATE_LIMIT_EXCEEDED", "GATEWAY_TIMEOUT"}
	for _, code := range retryableCodes {
		t.Run(code, func(t *testing.T) {
			body, _ := decodeProblem(t, Unavailable(code, "transient failure"), "")
			if v, _ := body["retryable"].(bool); !v {
				t.Errorf("%s: retryable = %v, want true", code, body["retryable"])
			}
			if v, ok := body["retryAfterSeconds"].(float64); !ok || v != 30 {
				t.Errorf("%s: retryAfterSeconds = %v, want 30", code, body["retryAfterSeconds"])
			}
		})
	}

	nonRetryableCodes := []string{"VALIDATION_FAILED", "RESOURCE_NOT_FOUND"}
	for _, code := range nonRetryableCodes {
		t.Run(code, func(t *testing.T) {
			body, _ := decodeProblem(t, Invalid(code, "not retryable"), "")
			if v, _ := body["retryable"].(bool); v {
				t.Errorf("%s: retryable = %v, want false", code, body["retryable"])
			}
			if _, ok := body["retryAfterSeconds"]; ok {
				t.Errorf("%s: retryAfterSeconds present, want omitted", code)
			}
		})
	}
}

func TestConstructorsStatusUnchanged(t *testing.T) {
	cases := []struct {
		name       string
		err        *Error
		wantStatus int
	}{
		{name: "BadRequest", err: BadRequest("BAD_REQUEST", "bad"), wantStatus: http.StatusBadRequest},
		{name: "Invalid", err: Invalid("VALIDATION_FAILED", "invalid"), wantStatus: http.StatusUnprocessableEntity},
		{name: "NotFound", err: NotFound("RESOURCE_NOT_FOUND", "missing"), wantStatus: http.StatusNotFound},
		{name: "Internal", err: Internal("INTERNAL_SERVER_ERROR", "boom"), wantStatus: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Status != tc.wantStatus {
				t.Errorf("%s.Status = %d, want %d", tc.name, tc.err.Status, tc.wantStatus)
			}
			body, rec := decodeProblem(t, tc.err, "")
			if rec.Code != tc.wantStatus {
				t.Errorf("%s: response status = %d, want %d", tc.name, rec.Code, tc.wantStatus)
			}
			for _, field := range []string{"type", "title", "status", "detail", "errorCode", "timestamp", "retryable"} {
				if _, ok := body[field]; !ok {
					t.Errorf("%s: required field %q missing: %v", tc.name, field, body)
				}
			}
		})
	}
}

func TestRegisterProblemCode(t *testing.T) {
	// The registry is package-global: remove the test's registration on
	// cleanup so no state leaks into other tests in this package.
	t.Cleanup(func() {
		problemCodeMu.Lock()
		delete(problemCodeRegistry, "DLM_UNREACHABLE")
		problemCodeMu.Unlock()
	})
	if err := RegisterProblemCode("DLM_UNREACHABLE", CategoryConnector, "", true); err != nil {
		t.Fatalf("RegisterProblemCode(valid) returned error: %v", err)
	}

	body, _ := decodeProblem(t, Unavailable("DLM_UNREACHABLE", "dlm unreachable"), "")

	if got := body["type"]; got != "https://docs.otilm.com/problems/connector/DLM_UNREACHABLE" {
		t.Errorf("type = %v, want connector/DLM_UNREACHABLE URI", got)
	}
	if v, _ := body["retryable"].(bool); !v {
		t.Errorf("retryable = %v, want true", body["retryable"])
	}
}

func TestRegisterProblemCodeValidation(t *testing.T) {
	cases := []struct {
		name     string
		code     string
		category ProblemCategory
		iface    string
	}{
		{name: "lowercase code", code: "dlm_bad", category: CategoryConnector, iface: ""},
		{name: "code with slash", code: "A/B", category: CategoryConnector, iface: ""},
		{name: "empty code", code: "", category: CategoryConnector, iface: ""},
		{name: "iface with slash", code: "DLM_BAD_IFACE", category: CategoryConnector, iface: "auth/x"},
		{name: "iface uppercase", code: "DLM_BAD_IFACE2", category: CategoryConnector, iface: "Authority"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RegisterProblemCode(tc.code, tc.category, tc.iface, true)
			if err == nil {
				t.Fatalf("RegisterProblemCode(%q, %v, %q) = nil error, want non-nil", tc.code, tc.category, tc.iface)
			}

			// The rejected code must not have been registered: its type URI
			// falls back to common/{code} (path-escaped, so an invalid code
			// cannot smuggle extra path segments), never resolving through
			// the rejected category/iface.
			if tc.code == "" {
				return
			}
			got := resolveProblemTypeURI("about:blank", tc.code)
			want := "https://docs.otilm.com/problems/common/" + url.PathEscape(tc.code)
			if got != want {
				t.Errorf("resolveProblemTypeURI(%q) = %q after rejected registration, want fallback %q", tc.code, got, want)
			}
		})
	}
}

func TestWriteProblemNonSharedErrorStillCompliant(t *testing.T) {
	body, rec := decodeProblem(t, errPlain("boom"), "")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if body["errorCode"] != "INTERNAL_SERVER_ERROR" {
		t.Errorf("errorCode = %v, want INTERNAL_SERVER_ERROR", body["errorCode"])
	}
	for _, field := range []string{"type", "title", "status", "detail", "errorCode", "timestamp", "retryable"} {
		if _, ok := body[field]; !ok {
			t.Errorf("required field %q missing: %v", field, body)
		}
	}
	if typ, _ := body["type"].(string); typ != "https://docs.otilm.com/problems/common/INTERNAL_SERVER_ERROR" {
		t.Errorf("type = %q, want https://docs.otilm.com/problems/common/INTERNAL_SERVER_ERROR", typ)
	}
}

// errPlain is a minimal error type distinct from *Error, used to exercise
// the errors.As fallback path in WriteProblem.
type errPlain string

func (e errPlain) Error() string { return string(e) }
