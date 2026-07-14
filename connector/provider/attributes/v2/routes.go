package attributes

import (
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/attributes/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Connector event names emitted to connector_events_total{event,outcome}.
const (
	eventListDefinitions   = "list_definitions"
	eventGetDefinition     = "get_definition"
	eventAttributeCallback = "attribute_callback"
)

// GET /v2/attributes[?uuids=...]
// The definition registry, optionally filtered to the repeated ?uuids= set.
// Always 200 with a (possibly empty) registry — an empty collection is the
// correct answer for a connector with no matching definitions.
func (h *Handler) listDefinitions(w http.ResponseWriter, r *http.Request) {
	// Build a fresh response; never mutate the handler's registry slice.
	out := &mdl.AttributeDefinitionsDto{
		ConnectorVersion: h.reg.connectorVersion,
		Definitions:      []mdl.BaseAttributeDto{},
	}
	if want := r.URL.Query()["uuids"]; len(want) > 0 {
		set := make(map[string]struct{}, len(want))
		for _, u := range want {
			if u != "" {
				set[u] = struct{}{}
			}
		}
		for _, def := range h.reg.defs {
			if _, ok := set[DefinitionUUID(def)]; ok {
				out.Definitions = append(out.Definitions, def)
			}
		}
	} else {
		out.Definitions = append(out.Definitions, h.reg.defs...)
	}
	shared.EmitEvent(r.Context(), eventListDefinitions, nil)
	if err := shared.WriteJSON(w, http.StatusOK, out); err != nil {
		h.LoggerFor(r).Error("write listDefinitions response", "err", err)
	}
}

// GET /v2/attributes/{uuid}
// One definition by connector-global UUID, or 404 ATTRIBUTE_DEFINITION_NOT_FOUND.
func (h *Handler) getDefinition(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	idx, found := h.reg.byUUID[uuid]
	if !found {
		err := ErrDefinitionNotFound.WithProperty("uuid", uuid)
		shared.EmitEvent(r.Context(), eventGetDefinition, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventGetDefinition, nil)
	def := h.reg.defs[idx]
	if err := shared.WriteJSON(w, http.StatusOK, &def); err != nil {
		h.LoggerFor(r).Error("write getDefinition response", "err", err)
	}
}

// POST /v2/attributes/callback
// Dispatches by the request's attributeUuid to the registered callback. 404
// ATTRIBUTE_DEFINITION_NOT_FOUND when the attribute has no callback, 500 when a
// callback returns a nil response.
func (h *Handler) attributeCallback(w http.ResponseWriter, r *http.Request) {
	var in mdl.AttributeCallbackRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventAttributeCallback, err)
		shared.RenderError(w, r, err)
		return
	}
	cb, ok := h.reg.callbacks[in.AttributeUuid]
	if !ok {
		err := ErrDefinitionNotFound.
			WithProperty("attributeUuid", in.AttributeUuid).
			WithProperty("attributeName", in.AttributeName)
		shared.EmitEvent(r.Context(), eventAttributeCallback, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := cb(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventAttributeCallback, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	// Enforce the exactly-one-arm contract (XOR on which arm is present); a
	// response with both or neither set is a provider bug.
	if (out.Content == nil) == (out.Attributes == nil) {
		shared.RenderError(w, r, ErrInvalidCallbackResponse)
		return
	}
	if err := shared.WriteJSON(w, http.StatusOK, out); err != nil {
		h.LoggerFor(r).Error("write attributeCallback response", "err", err)
	}
}
