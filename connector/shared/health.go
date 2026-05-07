package shared

import (
	"context"
	"encoding/json"
	"net/http"
)

// HealthLevel is the aggregated state reported by HealthChecker.
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
//   Liveness  -> "is the process alive"           (used by orchestrator restart)
//   Readiness -> "ready to accept requests"       (used by load balancer)
//   Health    -> aggregate of liveness + readiness + dependencies
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

// mountHealth attaches the v2 health endpoints. Status DOWN maps to HTTP 503,
// UP/UNKNOWN map to 200 (callers can distinguish by reading the body).
func mountHealth(r Router, hc HealthChecker) {
	r.Handle(http.MethodGet, "/v2/health", healthHandler(hc.Health))
	r.Handle(http.MethodGet, "/v2/health/readiness", healthHandler(hc.Readiness))
	r.Handle(http.MethodGet, "/v2/health/liveness", healthHandler(hc.Liveness))
}

func healthHandler(probe func(context.Context) HealthStatus) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := probe(r.Context())
		code := http.StatusOK
		if s.Status == HealthDown {
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if err := json.NewEncoder(w).Encode(s); err != nil {
			LoggerFromContext(r.Context()).Error("write health failed", "err", err)
		}
	}
}
