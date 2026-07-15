package attributes

import (
	"net/http"
	"strings"

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
// Dispatches by the request's attributeUuid to the registered callback. 422
// VALIDATION_FAILED on a malformed request, 404 ATTRIBUTE_DEFINITION_NOT_FOUND
// when the attribute has no callback, 500 when a callback returns a nil or
// both/neither-arm response.
func (h *Handler) attributeCallback(w http.ResponseWriter, r *http.Request) {
	var in mdl.AttributeCallbackRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventAttributeCallback, err)
		shared.RenderError(w, r, err)
		return
	}
	// Semantic validation beyond the decoder's key-presence/type checks:
	// reject blank identifiers and out-of-bounds pagination before dispatch,
	// as 422 rather than a downstream 404/500. (Full JSR-380-equivalent
	// validation of the nested DTO graph is a broader SDK gap, tracked
	// separately.)
	if err := validateCallbackRequest(&in); err != nil {
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
	if err == nil {
		// Validate the callback's output before declaring success, so the
		// nil/both-arms failure paths below are recorded as errors, not "ok".
		switch {
		case out == nil:
			err = ErrNilResponse
		case (out.Content == nil) == (out.Attributes == nil):
			// Exactly-one-arm contract (XOR on which arm is present); both or
			// neither set is a provider bug.
			err = ErrInvalidCallbackResponse
		}
	}
	shared.EmitEvent(r.Context(), eventAttributeCallback, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if err := shared.WriteJSON(w, http.StatusOK, out); err != nil {
		h.LoggerFor(r).Error("write attributeCallback response", "err", err)
	}
}

// validateCallbackRequest enforces the callback envelope's semantic constraints
// that the JSON decoder (key presence + types only) does not: non-blank
// dispatch identifiers and in-range pagination. Returns a 422 shared.Error.
func validateCallbackRequest(in *mdl.AttributeCallbackRequestDto) error {
	if strings.TrimSpace(in.AttributeUuid) == "" {
		return shared.Invalid("VALIDATION_FAILED", "attributeUuid must not be blank")
	}
	if strings.TrimSpace(in.AttributeName) == "" {
		return shared.Invalid("VALIDATION_FAILED", "attributeName must not be blank")
	}
	if p := in.Pagination; p != nil {
		if p.PageNumber != nil && *p.PageNumber < 1 {
			return shared.Invalid("VALIDATION_FAILED", "pagination.pageNumber must be >= 1")
		}
		if p.ItemsPerPage != nil && (*p.ItemsPerPage < 1 || *p.ItemsPerPage > 1000) {
			return shared.Invalid("VALIDATION_FAILED", "pagination.itemsPerPage must be in [1, 1000]")
		}
	}
	return nil
}
