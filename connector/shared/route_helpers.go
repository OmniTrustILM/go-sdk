package shared

import (
	"context"
	"net/http"
	"strconv"
)

// Route-handler helpers used by every provider package. Hoisted here so the
// same emit / ensureSlice / requireXxxPathValue patterns do not appear in
// each provider's routes.go.

// EmitEvent records a single connector event via the request-scoped metrics
// collector. outcome is "ok" when err is nil, "error" otherwise. Always
// safe to call — MetricsFromContext returns a no-op when metrics are
// disabled.
func EmitEvent(ctx context.Context, event string, err error) {
	mc := MetricsFromContext(ctx)
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	mc.IncConnectorEvent(event, outcome)
}

// EnsureSlice converts a nil slice into an empty one so JSON encoders emit
// "[]" instead of "null". Spec responses are array-typed; null surprises
// strict clients.
func EnsureSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// RequirePathValue extracts a required path parameter and renders a 400
// INVALID_REQUEST via the configured error renderer when it is empty.
// Returns the value and a boolean the caller should branch on.
func RequirePathValue(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	v := r.PathValue(name)
	if v == "" {
		RenderError(w, r, BadRequest("INVALID_REQUEST", "%s is required", name))
		return "", false
	}
	return v, true
}

// RequireIntPathValue extracts a required path parameter and parses it as
// an int32. Renders a 400 when missing or non-numeric. Used for path
// parameters that the spec types as integer (e.g. endEntityProfileId in
// authority v1).
func RequireIntPathValue(w http.ResponseWriter, r *http.Request, name string) (int32, bool) {
	raw := r.PathValue(name)
	if raw == "" {
		RenderError(w, r, BadRequest("INVALID_REQUEST", "%s is required", name))
		return 0, false
	}
	v, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		RenderError(w, r, BadRequest("INVALID_REQUEST", "%s must be an integer", name).
			WithCause(err).
			WithProperty("value", raw))
		return 0, false
	}
	return int32(v), true
}
