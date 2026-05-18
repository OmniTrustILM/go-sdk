package shared

import (
	"context"
	"encoding/json"
	"net/http"
)

// HealthLevel is the aggregated state reported by HealthChecker. The
// internal value set is canonical (UP/DOWN/UNKNOWN); the wire format is
// translated to the spec's enum at render time — uppercase UP/DOWN for v2
// specs, lowercase ok/nok for v1 specs.
type HealthLevel string

const (
	HealthUp      HealthLevel = "UP"
	HealthDown    HealthLevel = "DOWN"
	HealthUnknown HealthLevel = "UNKNOWN"
)

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

// mountHealth attaches the health endpoints for the configured version.
//
// Version v1 mounts only GET /v1/health (aggregate). Version v2 mounts the
// three GET /v2/health{,/readiness,/liveness} endpoints. Status DOWN maps to
// HTTP 503; UP/UNKNOWN to 200 in every case.
func mountHealth(r Router, hc HealthChecker, version string) {
	switch version {
	case VersionV1:
		r.Handle(http.MethodGet, "/v1/health", healthHandler(hc.Health, version))
	default: // v2
		r.Handle(http.MethodGet, "/v2/health", healthHandler(hc.Health, version))
		r.Handle(http.MethodGet, "/v2/health/readiness", healthHandler(hc.Readiness, version))
		r.Handle(http.MethodGet, "/v2/health/liveness", healthHandler(hc.Liveness, version))
	}
}

func healthHandler(probe func(context.Context) HealthStatus, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := probe(r.Context())
		code := http.StatusOK
		if s.Status == HealthDown {
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
	Status      string                       `json:"status"`
	Description string                       `json:"description,omitempty"`
	Components  map[string]componentV2Wire   `json:"components,omitempty"`
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
// (ok / nok / unknown).
func healthStatusV1(l HealthLevel) string {
	switch l {
	case HealthUp:
		return "ok"
	case HealthDown:
		return "nok"
	default:
		return "unknown"
	}
}

// healthStatusV2 maps the canonical HealthLevel onto the v2 wire enum
// (UP / DOWN / UNKNOWN).
func healthStatusV2(l HealthLevel) string {
	switch l {
	case HealthUp, HealthDown, HealthUnknown:
		return string(l)
	default:
		return "UNKNOWN"
	}
}
