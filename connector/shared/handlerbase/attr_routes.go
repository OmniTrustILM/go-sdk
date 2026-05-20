package handlerbase

import (
	"context"
	"net/http"

	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Per-instance attribute route helpers shared by every provider that exposes
// "list + validate" attribute endpoints scoped to a single instance UUID.
// Each provider's typed sub-interface plugs in via the generic fn argument;
// the helper takes care of path-param extraction, body decode, metric
// emission, empty-list-on-absent convention, and validation-error rendering.

// ListInstanceAttributes builds the GET handler. cfg supplies request-body
// limits and the logger override; pathParam is the path-value name
// (e.g. "uuid", "entityUuid"); fn fetches the attributes — pass nil when
// the optional sub-provider is unregistered to honour the
// empty-list-on-absent convention.
func ListInstanceAttributes[T any](
	cfg *Config,
	event, pathParam string,
	fn func(ctx context.Context, id string) ([]T, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := shared.RequirePathValue(w, r, pathParam)
		if !ok {
			return
		}
		var out []T
		var err error
		if fn != nil {
			out, err = fn(r.Context(), id)
		}
		shared.EmitEvent(r.Context(), event, err)
		if err != nil {
			shared.RenderError(w, r, err)
			return
		}
		if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
			cfg.LoggerFor(r).Error("write attribute list response", "err", writeErr, "event", event)
		}
	}
}

// ValidateInstanceAttributes builds the POST handler. fn returns validation
// errors that the helper renders as 422 when non-empty. When fn is nil
// (sub-provider absent), the handler decodes the body and returns 200 —
// nothing to validate.
func ValidateInstanceAttributes[A any](
	cfg *Config,
	event, pathParam string,
	fn func(ctx context.Context, id string, attrs []A) ([]string, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := shared.RequirePathValue(w, r, pathParam)
		if !ok {
			return
		}
		var attrs []A
		if err := shared.DecodeJSON(w, r, &attrs, cfg.MaxBytes, cfg.Strict); err != nil {
			shared.EmitEvent(r.Context(), event, err)
			shared.RenderError(w, r, err)
			return
		}
		if fn == nil {
			shared.EmitEvent(r.Context(), event, nil)
			w.WriteHeader(http.StatusOK)
			return
		}
		vErrs, err := fn(r.Context(), id, attrs)
		shared.EmitEvent(r.Context(), event, err)
		if err != nil {
			shared.RenderError(w, r, err)
			return
		}
		if len(vErrs) > 0 {
			shared.WriteV1ValidationErrors(w, r, vErrs)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
