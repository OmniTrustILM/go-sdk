package credential

import (
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/credential/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const (
	eventListAttributes     = "list_attributes"
	eventValidateAttributes = "validate_attributes"
)

// GET /v1/credentialProvider/{kind}/attributes
func (h *Handler) listAttributes(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	out, err := h.provider.Attributes(r.Context(), kind)
	shared.EmitEvent(r.Context(), eventListAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listAttributes response", "err", writeErr)
	}
}

// POST /v1/credentialProvider/{kind}/attributes/validate
func (h *Handler) validateAttributes(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventValidateAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	vErrs, err := h.provider.ValidateAttributes(r.Context(), kind, attrs)
	shared.EmitEvent(r.Context(), eventValidateAttributes, err)
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
