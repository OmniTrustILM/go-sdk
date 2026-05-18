package discovery

import (
	"context"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Connector event names emitted to connector_events_total{event,outcome}.
const (
	eventDiscoverCertificate = "discover_certificate"
	eventGetDiscovery        = "get_discovery"
	eventDeleteDiscovery     = "delete_discovery"
	eventListAttributes      = "list_attributes"
	eventValidateAttributes  = "validate_attributes"
)

func emit(ctx context.Context, event string, err error) {
	mc := shared.MetricsFromContext(ctx)
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	mc.IncConnectorEvent(event, outcome)
}

// validateFunctionalGroup checks the {functionalGroup} path parameter against
// the discoveryProvider literal. Routes a 404 when another provider's group
// is requested so collisions across mounted handlers are explicit.
func (h *Handler) validateFunctionalGroup(w http.ResponseWriter, r *http.Request) bool {
	got := r.PathValue("functionalGroup")
	if got != FunctionGroupCode {
		shared.RenderError(w, r, shared.NotFound("FUNCTION_GROUP_NOT_FOUND",
			"unknown functional group: %s", got).WithProperty("functionalGroup", got))
		return false
	}
	return true
}

// --- Discovery routes ------------------------------------------------------

// POST /v1/discoveryProvider/discover
func (h *Handler) discoverCertificate(w http.ResponseWriter, r *http.Request) {
	var in mdl.DiscoveryRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventDiscoverCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.DiscoverCertificate(r.Context(), &in)
	emit(r.Context(), eventDiscoverCertificate, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write discoverCertificate response", "err", writeErr)
	}
}

// POST /v1/discoveryProvider/discover/{uuid}
func (h *Handler) getDiscovery(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if uuid == "" {
		shared.RenderError(w, r, ErrInvalidRequest.WithProperty("reason", "uuid is required"))
		return
	}
	var in mdl.DiscoveryDataRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventGetDiscovery, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.GetDiscovery(r.Context(), uuid, &in)
	emit(r.Context(), eventGetDiscovery, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getDiscovery response", "err", writeErr)
	}
}

// DELETE /v1/discoveryProvider/discover/{uuid}
func (h *Handler) deleteDiscovery(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if uuid == "" {
		shared.RenderError(w, r, ErrInvalidRequest.WithProperty("reason", "uuid is required"))
		return
	}
	if err := h.provider.DeleteDiscovery(r.Context(), uuid); err != nil {
		emit(r.Context(), eventDeleteDiscovery, err)
		shared.RenderError(w, r, err)
		return
	}
	emit(r.Context(), eventDeleteDiscovery, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Attribute routes -----------------------------------------------------

// GET /v1/{functionalGroup}/{kind}/attributes
func (h *Handler) listAttributes(w http.ResponseWriter, r *http.Request) {
	if !h.validateFunctionalGroup(w, r) {
		return
	}
	kind := r.PathValue("kind")
	var out []mdl.BaseAttributeDto
	var err error
	if h.attrs != nil {
		out, err = h.attrs.Attributes(r.Context(), kind)
	}
	emit(r.Context(), eventListAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listAttributes response", "err", writeErr)
	}
}

// POST /v1/{functionalGroup}/{kind}/attributes/validate
func (h *Handler) validateAttributes(w http.ResponseWriter, r *http.Request) {
	if !h.validateFunctionalGroup(w, r) {
		return
	}
	kind := r.PathValue("kind")
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventValidateAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if h.attrs == nil {
		// No registered provider: treat as nothing to validate.
		emit(r.Context(), eventValidateAttributes, nil)
		w.WriteHeader(http.StatusOK)
		return
	}
	vErrs, err := h.attrs.ValidateAttributes(r.Context(), kind, attrs)
	emit(r.Context(), eventValidateAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if len(vErrs) > 0 {
		WriteValidationErrors(w, r, vErrs)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ensureSlice converts a nil slice into an empty one so JSON encodes "[]"
// instead of "null". Spec response is array-typed; clients hate null.
func ensureSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
