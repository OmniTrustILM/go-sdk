package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	authorityv3 "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
	cryptographyv2 "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	secretv1 "github.com/OmniTrustILM/go-sdk/connector/model/secret/v1"
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

// recordHealth mounts the health endpoints of version for hc and GETs path.
func recordHealth(t *testing.T, hc HealthChecker, version, path string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mountHealth(newMuxRouter(mux), hc, version)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr
}

// serveHealth mounts the v2 health endpoints for hc and GETs path.
func serveHealth(t *testing.T, hc HealthChecker, path string) (int, map[string]any) {
	t.Helper()
	rr := recordHealth(t, hc, VersionV2, path)
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
	liveDetails, _ := live["details"].(map[string]any)
	if live == nil || live["status"] != "DOWN" || liveDetails["description"] != "real down" {
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

// healthInfoModels decode a body into each spec's generated HealthInfo.
var healthInfoModels = map[string]func([]byte) (any, error){
	"authority v3":    decodeAs[authorityv3.HealthInfo],
	"cryptography v2": decodeAs[cryptographyv2.HealthInfo],
	"secret v1":       decodeAs[secretv1.HealthInfo],
}

func decodeAs[T any](body []byte) (any, error) {
	var v T
	err := json.Unmarshal(body, &v)
	return v, err
}

// unknownFields lists the fields outside its schema that a generated
// HealthInfo or one of its components collected.
func unknownFields(info any) []string {
	v := reflect.ValueOf(info)
	fields := mapKeys(v.FieldByName("AdditionalProperties"))
	components := v.FieldByName("Components")
	for _, name := range components.MapKeys() {
		for _, field := range mapKeys(components.MapIndex(name).FieldByName("AdditionalProperties")) {
			fields = append(fields, name.String()+"."+field)
		}
	}
	return fields
}

func mapKeys(m reflect.Value) []string {
	keys := make([]string, 0, m.Len())
	for _, k := range m.MapKeys() {
		keys = append(keys, k.String())
	}
	return keys
}

// describedChecker sets a Description on every answer and component.
func describedChecker() stubChecker {
	return stubChecker{
		live:  HealthStatus{Status: HealthUp, Description: "process alive"},
		ready: HealthStatus{Status: HealthUp, Description: "accepting requests"},
		health: HealthStatus{
			Status:      HealthDegraded,
			Description: "a dependency is slow",
			Components: map[string]ComponentStatus{
				"database": {Status: HealthDegraded, Description: "slow", Details: map[string]any{"latencyMs": 45}},
			},
		},
	}
}

func TestV2HealthAnswersDecodeAsHealthInfo(t *testing.T) {
	for _, path := range []string{"/v2/health", "/v2/health/liveness", "/v2/health/readiness"} {
		body := recordHealth(t, describedChecker(), VersionV2, path).Body.Bytes()
		for spec, decode := range healthInfoModels {
			info, err := decode(body)
			if err != nil {
				t.Fatalf("%s as %s HealthInfo: %v\n%s", path, spec, err, body)
			}
			if fields := unknownFields(info); len(fields) > 0 {
				t.Errorf("%s carries fields outside %s HealthInfo: %v\n%s", path, spec, fields, body)
			}
		}
	}
}

// componentDetails is the details of the named component in a decoded v2 answer.
func componentDetails(body map[string]any, name string) map[string]any {
	comps, _ := body["components"].(map[string]any)
	c, _ := comps[name].(map[string]any)
	details, _ := c["details"].(map[string]any)
	return details
}

func TestComponentDescriptionMovesIntoDetails(t *testing.T) {
	_, body := serveHealth(t, describedChecker(), "/v2/health")
	want := map[string]any{"description": "slow", "latencyMs": float64(45)}
	if got := componentDetails(body, "database"); !reflect.DeepEqual(got, want) {
		t.Errorf("components.database.details = %v, want %v", got, want)
	}
}

func TestComponentDescriptionReplacesADetailOfTheSameName(t *testing.T) {
	hc := upChecker()
	hc.health = HealthStatus{
		Status: HealthUp,
		Components: map[string]ComponentStatus{
			"database": {Status: HealthDegraded, Description: "slow", Details: map[string]any{"description": "stale"}},
		},
	}
	_, body := serveHealth(t, hc, "/v2/health")
	if got := componentDetails(body, "database")["description"]; got != "slow" {
		t.Errorf("components.database.details.description = %v, want the component's Description", got)
	}
}

func TestV2HealthLeavesTheCheckersAnswerUnchanged(t *testing.T) {
	hc := describedChecker()
	hc.live.Components = map[string]ComponentStatus{"cache": {Status: HealthUp}}
	details := hc.health.Components["database"].Details
	wantDetails := maps.Clone(details)
	wantLive := maps.Clone(hc.live.Components)
	serveHealth(t, hc, "/v2/health")
	serveHealth(t, hc, "/v2/health/liveness")
	if !maps.Equal(details, wantDetails) {
		t.Errorf("checker's details = %v after serving, want %v", details, wantDetails)
	}
	if !reflect.DeepEqual(hc.live.Components, wantLive) {
		t.Errorf("checker's liveness components = %v after serving, want %v", hc.live.Components, wantLive)
	}
}

func TestV1HealthKeepsDescriptions(t *testing.T) {
	var body map[string]any
	if err := json.Unmarshal(recordHealth(t, describedChecker(), VersionV1, "/v1/health").Body.Bytes(), &body); err != nil {
		t.Fatalf("v1 health body is not JSON: %v", err)
	}
	if body["description"] != "a dependency is slow" {
		t.Errorf("description = %v, want the answer's Description", body["description"])
	}
	parts, _ := body["parts"].(map[string]any)
	db, _ := parts["database"].(map[string]any)
	if db["description"] != "slow" {
		t.Errorf("parts.database = %v, want the component's Description", parts["database"])
	}
}

func TestProbeAnswersCarryTheirOwnComponent(t *testing.T) {
	for path, name := range map[string]string{
		"/v2/health/liveness":  livenessComponent,
		"/v2/health/readiness": readinessComponent,
	} {
		_, body := serveHealth(t, defaultHealthChecker{}, path)
		comps, _ := body["components"].(map[string]any)
		if c, _ := comps[name].(map[string]any); c == nil || c["status"] != "UP" {
			t.Errorf("%s components.%s = %v, want status UP", path, name, comps[name])
		}
	}
}

func TestProbeComponentCarriesTheAnswersDescription(t *testing.T) {
	hc := upChecker()
	hc.live = HealthStatus{Status: HealthDown, Description: "cache corrupt"}
	code, body := serveHealth(t, hc, "/v2/health/liveness")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 for a DOWN liveness", code)
	}
	want := map[string]any{
		"status":     "DOWN",
		"components": map[string]any{"liveness": map[string]any{"status": "DOWN", "details": map[string]any{"description": "cache corrupt"}}},
	}
	if !reflect.DeepEqual(body, want) {
		t.Errorf("body = %v, want %v", body, want)
	}
}

func TestProbeAnswerKeepsItsOwnComponent(t *testing.T) {
	hc := upChecker()
	hc.ready = HealthStatus{
		Status:     HealthUp,
		Components: map[string]ComponentStatus{readinessComponent: {Status: HealthUp, Details: map[string]any{"queue": "empty"}}},
	}
	_, body := serveHealth(t, hc, "/v2/health/readiness")
	want := map[string]any{
		"status":     "UP",
		"components": map[string]any{"readiness": map[string]any{"status": "UP", "details": map[string]any{"queue": "empty"}}},
	}
	if !reflect.DeepEqual(body, want) {
		t.Errorf("body = %v, want %v", body, want)
	}
}

func TestAggregateHealthKeepsAProbesOwnComponent(t *testing.T) {
	hc := upChecker()
	hc.ready = HealthStatus{
		Status:     HealthUp,
		Components: map[string]ComponentStatus{readinessComponent: {Status: HealthUp, Details: map[string]any{"queue": "empty"}}},
	}
	_, body := serveHealth(t, hc, "/v2/health")
	if got := componentDetails(body, readinessComponent); !reflect.DeepEqual(got, map[string]any{"queue": "empty"}) {
		t.Errorf("components.readiness.details = %v, want the readiness answer's own component", got)
	}
}
