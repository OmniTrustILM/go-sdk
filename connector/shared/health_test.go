package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubChecker returns fixed statuses per probe.
type stubChecker struct {
	live, ready, health HealthStatus
}

func (s stubChecker) Liveness(context.Context) HealthStatus  { return s.live }
func (s stubChecker) Readiness(context.Context) HealthStatus { return s.ready }
func (s stubChecker) Health(context.Context) HealthStatus    { return s.health }

// upChecker is the all-UP stub.
func upChecker() stubChecker {
	return stubChecker{
		live:   HealthStatus{Status: HealthUp},
		ready:  HealthStatus{Status: HealthUp},
		health: HealthStatus{Status: HealthUp},
	}
}

// serveHealth mounts the v2 health endpoints for hc and GETs path.
func serveHealth(t *testing.T, hc HealthChecker, path string) (int, map[string]any) {
	t.Helper()
	mux := http.NewServeMux()
	mountHealth(newMuxRouter(mux), hc, VersionV2)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("health body is not JSON: %v\n%s", err, rr.Body.String())
	}
	return rr.Code, body
}

func TestAggregateHealthAlwaysIncludesMandatoryComponents(t *testing.T) {
	// Default checker supplies no components at all — the SDK must still
	// emit liveness and readiness.
	code, body := serveHealth(t, defaultHealthChecker{}, "/v2/health")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	comps, _ := body["components"].(map[string]any)
	if comps == nil {
		t.Fatal("components missing from aggregate health response")
	}
	for _, name := range []string{"liveness", "readiness"} {
		c, _ := comps[name].(map[string]any)
		if c == nil || c["status"] != "UP" {
			t.Errorf("components.%s = %v, want status UP", name, comps[name])
		}
	}
	if body["status"] != "UP" {
		t.Errorf("status = %v, want UP", body["status"])
	}
}

func TestAggregateHealthMergesCallerComponents(t *testing.T) {
	hc := upChecker()
	hc.health = HealthStatus{
		Status: HealthUp,
		Components: map[string]ComponentStatus{
			"database": {Status: HealthDegraded, Description: "slow"},
		},
	}
	code, body := serveHealth(t, hc, "/v2/health")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (DEGRADED component, UP probes)", code)
	}
	comps, _ := body["components"].(map[string]any)
	db, _ := comps["database"].(map[string]any)
	if db == nil || db["status"] != "DEGRADED" {
		t.Errorf("components.database = %v", comps["database"])
	}
	if _, ok := comps["liveness"]; !ok {
		t.Error("liveness dropped when caller supplied components")
	}
	if _, ok := comps["readiness"]; !ok {
		t.Error("readiness dropped when caller supplied components")
	}
}

// TestAggregateHealthSDKOwnsMandatoryKeys: caller-supplied components named
// liveness/readiness must be overwritten by the real probe results — the
// aggregate must never report a lie under the mandatory keys.
func TestAggregateHealthSDKOwnsMandatoryKeys(t *testing.T) {
	hc := upChecker()
	hc.live = HealthStatus{Status: HealthDown, Description: "real down"}
	hc.health = HealthStatus{
		Status: HealthUp,
		Components: map[string]ComponentStatus{
			"liveness":  {Status: HealthUp, Description: "caller lie"},
			"readiness": {Status: HealthDown, Description: "caller lie"},
		},
	}
	_, body := serveHealth(t, hc, "/v2/health")
	comps, _ := body["components"].(map[string]any)
	live, _ := comps["liveness"].(map[string]any)
	if live == nil || live["status"] != "DOWN" || live["description"] != "real down" {
		t.Errorf("components.liveness = %v, want real probe result, not caller value", comps["liveness"])
	}
	ready, _ := comps["readiness"].(map[string]any)
	if ready == nil || ready["status"] != "UP" {
		t.Errorf("components.readiness = %v, want real probe result UP", comps["readiness"])
	}
}

// panicChecker panics in every probe.
type panicChecker struct{}

func (panicChecker) Liveness(context.Context) HealthStatus  { panic("liveness boom") }
func (panicChecker) Readiness(context.Context) HealthStatus { panic("readiness boom") }
func (panicChecker) Health(context.Context) HealthStatus    { panic("health boom") }

// TestPanickingCheckerYields500 drives the panic through the full wired
// Connector handler: the recover middleware must turn it into a 500, per the
// spec's "internal errors -> 500" mapping.
func TestPanickingCheckerYields500(t *testing.T) {
	var buf bytes.Buffer
	c, err := New(
		WithLogger(slog.New(NewLogHandler(&buf, &LogHandlerOptions{ServiceName: "t"}))),
		WithHealthCheck(panicChecker{}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, path := range []string{"/v2/health", "/v2/health/liveness", "/v2/health/readiness"} {
		rr := httptest.NewRecorder()
		c.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("GET %s with panicking checker = %d, want 500", path, rr.Code)
		}
	}
}

func TestAggregateHealthWorstStatusWins(t *testing.T) {
	hc := upChecker()
	hc.ready = HealthStatus{Status: HealthDown, Description: "queue full"}
	code, body := serveHealth(t, hc, "/v2/health")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when readiness is DOWN", code)
	}
	if body["status"] != "DOWN" {
		t.Errorf("aggregate status = %v, want DOWN (worst of probes)", body["status"])
	}
	comps, _ := body["components"].(map[string]any)
	ready, _ := comps["readiness"].(map[string]any)
	if ready == nil || ready["status"] != "DOWN" {
		t.Errorf("components.readiness = %v", comps["readiness"])
	}
}

func TestHealthStatusToHTTPMapping(t *testing.T) {
	cases := []struct {
		level HealthLevel
		want  int
	}{
		{HealthUp, http.StatusOK},
		{HealthDegraded, http.StatusOK},
		{HealthUnknown, http.StatusOK}, // aggregate: connector reachable, body says unknown
		{HealthDown, http.StatusServiceUnavailable},
		{HealthOutOfService, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		hc := upChecker()
		hc.health = HealthStatus{Status: tc.level}
		// keep probes at the same level so worst-of doesn't mask the case
		hc.live = HealthStatus{Status: tc.level}
		hc.ready = HealthStatus{Status: tc.level}
		code, _ := serveHealth(t, hc, "/v2/health")
		if code != tc.want {
			t.Errorf("aggregate %s -> %d, want %d", tc.level, code, tc.want)
		}
	}
}

func TestProbeEndpointsStrictMapping(t *testing.T) {
	cases := []struct {
		level HealthLevel
		want  int
	}{
		{HealthUp, http.StatusOK},
		{HealthDegraded, http.StatusOK},
		{HealthUnknown, http.StatusServiceUnavailable}, // strict probes
		{HealthDown, http.StatusServiceUnavailable},
		{HealthOutOfService, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		hc := upChecker()
		hc.ready = HealthStatus{Status: tc.level}
		code, _ := serveHealth(t, hc, "/v2/health/readiness")
		if code != tc.want {
			t.Errorf("readiness %s -> %d, want %d", tc.level, code, tc.want)
		}
	}
}

func TestHealthV1Mapping(t *testing.T) {
	cases := []struct {
		level HealthLevel
		want  string
	}{
		{HealthUp, "ok"},
		{HealthDegraded, "ok"},
		{HealthDown, "nok"},
		{HealthOutOfService, "nok"},
		{HealthUnknown, "unknown"},
	}
	for _, tc := range cases {
		if got := healthStatusV1(tc.level); got != tc.want {
			t.Errorf("healthStatusV1(%s) = %q, want %q", tc.level, got, tc.want)
		}
	}
}

func TestWorstHealthOrdering(t *testing.T) {
	if got := worstHealth(HealthUp, HealthDegraded, HealthUnknown); got != HealthUnknown {
		t.Errorf("worst = %s, want UNKNOWN", got)
	}
	if got := worstHealth(HealthOutOfService, HealthUnknown); got != HealthOutOfService {
		t.Errorf("worst = %s, want OUT_OF_SERVICE", got)
	}
	if got := worstHealth(HealthDown, HealthOutOfService); got != HealthDown {
		t.Errorf("worst = %s, want DOWN", got)
	}
	if got := worstHealth(); got != HealthUp {
		t.Errorf("worst() = %s, want UP", got)
	}
}
