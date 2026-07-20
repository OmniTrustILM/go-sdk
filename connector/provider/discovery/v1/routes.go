package discovery

import (
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

// --- Discovery routes ------------------------------------------------------

// POST /v1/discoveryProvider/discover
func (h *Handler) discoverCertificate(w http.ResponseWriter, r *http.Request) {
	var in mdl.DiscoveryRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventDiscoverCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.DiscoverCertificate(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventDiscoverCertificate, err)
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
		shared.EmitEvent(r.Context(), eventGetDiscovery, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.GetDiscovery(r.Context(), uuid, &in)
	shared.EmitEvent(r.Context(), eventGetDiscovery, err)
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
		shared.EmitEvent(r.Context(), eventDeleteDiscovery, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventDeleteDiscovery, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Attribute routes -----------------------------------------------------

// GET /v1/discoveryProvider/{kind}/attributes
func (h *Handler) listAttributes(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	var out []mdl.BaseAttributeDto
	var err error
	if h.attrs != nil {
		out, err = h.attrs.Attributes(r.Context(), kind)
	}
	shared.EmitEvent(r.Context(), eventListAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listAttributes response", "err", writeErr)
	}
}

// POST /v1/discoveryProvider/{kind}/attributes/validate
func (h *Handler) validateAttributes(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventValidateAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if h.attrs == nil {
		// No registered provider: treat as nothing to validate.
		shared.EmitEvent(r.Context(), eventValidateAttributes, nil)
		w.WriteHeader(http.StatusOK)
		return
	}
	vErrs, err := h.attrs.ValidateAttributes(r.Context(), kind, attrs)
	shared.EmitEvent(r.Context(), eventValidateAttributes, err)
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
