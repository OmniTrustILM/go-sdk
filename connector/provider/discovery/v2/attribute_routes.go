package discovery

import (
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const (
	eventListDefinitions   = "discovery_list_definitions"
	eventGetDefinition     = "discovery_get_definition"
	eventAttributeCallback = "discovery_attribute_callback"
)

func (h *Handler) listDefinitions(w http.ResponseWriter, r *http.Request) {
	var src *mdl.AttributeDefinitionsDto
	var err error
	if h.attributeDefs != nil {
		src, err = h.attributeDefs.ListDefinitions(r.Context())
	}
	shared.EmitEvent(r.Context(), eventListDefinitions, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	// Build a fresh response rather than mutating the value the provider
	// returned: a provider may cache and share a single DTO/slice across
	// requests, so filtering in place would narrow its set permanently and
	// race under concurrency. A nil result (unwired, or a provider that
	// returned (nil, nil)) degrades to an empty definition set.
	out := &mdl.AttributeDefinitionsDto{Definitions: []mdl.BaseAttributeDto{}}
	if src != nil {
		out.ConnectorVersion = src.ConnectorVersion
		// Optional repeated ?uuids= filter (spec GET /v2/attributes): when
		// present, return only the definitions whose connector-global UUID
		// was requested.
		if want := r.URL.Query()["uuids"]; len(want) > 0 {
			set := make(map[string]struct{}, len(want))
			for _, u := range want {
				if u != "" {
					set[u] = struct{}{}
				}
			}
			for _, def := range src.Definitions {
				if _, ok := set[DefinitionUUID(def)]; ok {
					out.Definitions = append(out.Definitions, def)
				}
			}
		} else {
			out.Definitions = append(out.Definitions, src.Definitions...)
		}
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write listDefinitions response", "err", writeErr)
	}
}

// GET /v2/attributes/{uuid}
// 200 with one definition | 404 when unknown or no provider is wired.
func (h *Handler) getDefinition(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	if h.attributeDefs == nil {
		err := ErrDefinitionNotFound.WithProperty("uuid", uuid)
		shared.EmitEvent(r.Context(), eventGetDefinition, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.attributeDefs.GetDefinition(r.Context(), uuid)
	shared.EmitEvent(r.Context(), eventGetDefinition, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getDefinition response", "err", writeErr)
	}
}

// POST /v2/attributes/callback
// 200 with the resolved callback content | 404 when no provider is wired.
func (h *Handler) attributeCallback(w http.ResponseWriter, r *http.Request) {
	var in mdl.AttributeCallbackRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventAttributeCallback, err)
		shared.RenderError(w, r, err)
		return
	}
	if h.attributeDefs == nil {
		err := ErrDefinitionNotFound.WithProperty("attributeName", in.AttributeName)
		shared.EmitEvent(r.Context(), eventAttributeCallback, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.attributeDefs.Callback(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventAttributeCallback, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write attributeCallback response", "err", writeErr)
	}
}
