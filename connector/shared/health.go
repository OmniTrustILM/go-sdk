package shared

import (
	"context"
	"encoding/json"
	"net/http"
)

// HealthLevel is the aggregated state reported by HealthChecker. The value
// set matches the spec's HealthStatus enum (UP / DEGRADED / DOWN /
// OUT_OF_SERVICE / UNKNOWN); the wire format is emitted as-is for v2 specs
// and translated to the lowercase ok/nok/unknown enum for v1 specs.
type HealthLevel string

const (
	HealthUp           HealthLevel = "UP"
	HealthDegraded     HealthLevel = "DEGRADED"
	HealthDown         HealthLevel = "DOWN"
	HealthOutOfService HealthLevel = "OUT_OF_SERVICE"
	HealthUnknown      HealthLevel = "UNKNOWN"
)

// healthSeverity orders levels for worst-of aggregation. Higher is worse.
func healthSeverity(l HealthLevel) int {
	switch l {
	case HealthUp:
		return 0
	case HealthDegraded:
		return 1
	case HealthUnknown:
		return 2
	case HealthOutOfService:
		return 3
	case HealthDown:
		return 4
	default:
		// Unrecognized values rank as worse than UP but better than the
		// explicit failure states, like UNKNOWN.
		return 2
	}
}

// worstHealth returns the most severe of the supplied levels.
func worstHealth(levels ...HealthLevel) HealthLevel {
	out := HealthUp
	for _, l := range levels {
		if healthSeverity(l) > healthSeverity(out) {
			out = l
		}
	}
	return out
}

// HealthStatus is what each probe returns. Description is optional free-form
// text; Components carries per-dependency state (DB, vault backend, HSM, ...).
type HealthStatus struct {
	Status      HealthLevel                `json:"status"`
	Description string                     `json:"description,omitempty"`
	Components  map[string]ComponentStatus `json:"components,omitempty"`
}

// ComponentStatus reports a single dependency.
type ComponentStatus struct {
	Status      HealthLevel    `json:"status"`
	Description string         `json:"description,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

// HealthChecker is implemented by callers and supplied via WithHealthCheck.
//
//	Liveness  -> "is the process alive"           (used by orchestrator restart)
//	Readiness -> "ready to accept requests"       (used by load balancer)
//	Health    -> aggregate of liveness + readiness + dependencies
//
// Probes must be cheap and bounded; the connector serves them on the same
// HTTP server as the provider routes.
type HealthChecker interface {
	Liveness(ctx context.Context) HealthStatus
	Readiness(ctx context.Context) HealthStatus
	Health(ctx context.Context) HealthStatus
}

// defaultHealthChecker reports UP for every probe. Used when WithHealthCheck
// is not supplied; suitable for trivial connectors with no external deps.
type defaultHealthChecker struct{}

func (defaultHealthChecker) Liveness(context.Context) HealthStatus {
	return HealthStatus{Status: HealthUp}
}
func (defaultHealthChecker) Readiness(context.Context) HealthStatus {
	return HealthStatus{Status: HealthUp}
}
func (defaultHealthChecker) Health(context.Context) HealthStatus {
	return HealthStatus{Status: HealthUp}
}

// probeKind controls how the health handler maps HealthLevel onto an HTTP
// status. Aggregate probes treat UNKNOWN as 200 (the connector itself is
// reachable; the operator can read the body to decide). Readiness and
// liveness probes treat UNKNOWN as 503 because orchestrators interpret a
// non-200 response as "do not send traffic" / "restart" — receiving a 200
// when state is genuinely unknown can cause routing to half-broken pods.
type probeKind int

const (
	probeAggregate probeKind = iota
	probeStrict
)

// mountHealth attaches the health endpoints for the configured version.
//
// Version v1 mounts only GET /v1/health (aggregate). Version v2 mounts the
// three GET /v2/health{,/readiness,/liveness} endpoints. Status DOWN and
// OUT_OF_SERVICE always map to 503; readiness and liveness additionally
// treat UNKNOWN as 503.
//
// The aggregate endpoint always composes the liveness and readiness probes
// into the response (see aggregateHealth) — the spec marks those two
// components mandatory in every health response, with no caller wiring
// required.
func mountHealth(r Router, hc HealthChecker, version string) {
	aggregate := func(ctx context.Context) HealthStatus { return aggregateHealth(ctx, hc) }
	switch version {
	case VersionV1:
		r.Handle(http.MethodGet, "/v1/health", healthHandler(aggregate, version, probeAggregate))
	default: // v2
		r.Handle(http.MethodGet, "/v2/health", healthHandler(aggregate, version, probeAggregate))
		r.Handle(http.MethodGet, "/v2/health/readiness", healthHandler(hc.Readiness, version, probeStrict))
		r.Handle(http.MethodGet, "/v2/health/liveness", healthHandler(hc.Liveness, version, probeStrict))
	}
}

// aggregateHealth builds the aggregate health body: the caller's Health()
// result with the mandatory liveness and readiness components always
// present, and the overall status raised to the worst of the three. Caller
// components keep their entries; "liveness" and "readiness" keys are owned
// by the SDK and reflect the actual probe results.
func aggregateHealth(ctx context.Context, hc HealthChecker) HealthStatus {
	h := hc.Health(ctx)
	live := hc.Liveness(ctx)
	ready := hc.Readiness(ctx)

	components := make(map[string]ComponentStatus, len(h.Components)+2)
	for k, c := range h.Components {
		components[k] = c
	}
	components["liveness"] = ComponentStatus{Status: live.Status, Description: live.Description}
	components["readiness"] = ComponentStatus{Status: ready.Status, Description: ready.Description}

	h.Components = components
	h.Status = worstHealth(h.Status, live.Status, ready.Status)
	return h
}

func healthHandler(probe func(context.Context) HealthStatus, version string, kind probeKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := probe(r.Context())
		code := http.StatusOK
		switch {
		case s.Status == HealthDown, s.Status == HealthOutOfService:
			code = http.StatusServiceUnavailable
		case kind == probeStrict && s.Status == HealthUnknown:
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if err := json.NewEncoder(w).Encode(marshalHealth(s, version)); err != nil {
			LoggerFromContext(r.Context()).Error("write health failed", "err", err)
		}
	}
}

// healthV1Wire is the v1 spec response shape: lowercase status enum, parts
// map. Component details are dropped (v1 schema has no equivalent field).
type healthV1Wire struct {
	Status      string                  `json:"status"`
	Description string                  `json:"description,omitempty"`
	Parts       map[string]healthV1Wire `json:"parts,omitempty"`
}

// healthV2Wire is the v2 spec response shape: uppercase status enum,
// components map, optional per-component details.
type healthV2Wire struct {
	Status      string                     `json:"status"`
	Description string                     `json:"description,omitempty"`
	Components  map[string]componentV2Wire `json:"components,omitempty"`
}

type componentV2Wire struct {
	Status      string         `json:"status"`
	Description string         `json:"description,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

// marshalHealth translates the internal HealthStatus into the wire shape
// matching the configured spec version.
func marshalHealth(s HealthStatus, version string) any {
	if version == VersionV1 {
		out := healthV1Wire{
			Status:      healthStatusV1(s.Status),
			Description: s.Description,
		}
		if len(s.Components) > 0 {
			out.Parts = make(map[string]healthV1Wire, len(s.Components))
			for k, c := range s.Components {
				out.Parts[k] = healthV1Wire{
					Status:      healthStatusV1(c.Status),
					Description: c.Description,
				}
			}
		}
		return out
	}
	out := healthV2Wire{
		Status:      healthStatusV2(s.Status),
		Description: s.Description,
	}
	if len(s.Components) > 0 {
		out.Components = make(map[string]componentV2Wire, len(s.Components))
		for k, c := range s.Components {
			out.Components[k] = componentV2Wire{
				Status:      healthStatusV2(c.Status),
				Description: c.Description,
				Details:     c.Details,
			}
		}
	}
	return out
}

// healthStatusV1 maps the canonical HealthLevel onto the v1 wire enum
// (ok / nok / unknown). DEGRADED still serves traffic and maps to ok;
// OUT_OF_SERVICE maps to nok.
func healthStatusV1(l HealthLevel) string {
	switch l {
	case HealthUp, HealthDegraded:
		return "ok"
	case HealthDown, HealthOutOfService:
		return "nok"
	default:
		return "unknown"
	}
}

// healthStatusV2 maps the canonical HealthLevel onto the v2 wire enum
// (UP / DEGRADED / DOWN / OUT_OF_SERVICE / UNKNOWN). The canonical values
// already match the spec enum; values outside it would only come from
// misuse, so we let them pass through as-is rather than masking the bug.
func healthStatusV2(l HealthLevel) string {
	return string(l)
}
