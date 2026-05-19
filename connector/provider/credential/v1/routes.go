package credential

import (
	"context"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/credential/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const (
	eventListAttributes     = "list_attributes"
	eventValidateAttributes = "validate_attributes"
)

func emit(ctx context.Context, event string, err error) {
	mc := shared.MetricsFromContext(ctx)
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	mc.IncConnectorEvent(event, outcome)
}

func ensureSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// GET /v1/credentialProvider/{kind}/attributes
func (h *Handler) listAttributes(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	out, err := h.provider.Attributes(r.Context(), kind)
	emit(r.Context(), eventListAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listAttributes response", "err", writeErr)
	}
}

// POST /v1/credentialProvider/{kind}/attributes/validate
func (h *Handler) validateAttributes(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventValidateAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	vErrs, err := h.provider.ValidateAttributes(r.Context(), kind, attrs)
	emit(r.Context(), eventValidateAttributes, err)
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
