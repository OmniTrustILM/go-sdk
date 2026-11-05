package discovery

import (
	"encoding/json"
	"errors"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/google/uuid"
)

const MaxResultBytes int64 = 10 * 1024 * 1024

func validate(run string, resources []mdl.Resource, cp []mdl.MetadataAttribute) error {
	if _, e := uuid.Parse(run); e != nil {
		return ErrInvalidRequest
	}
	if len(resources) == 0 {
		return ErrInvalidRequest
	}
	seen := map[mdl.Resource]bool{}
	for _, r := range resources {
		if !r.IsValid() || seen[r] {
			return ErrInvalidRequest
		}
		seen[r] = true
	}
	b, e := json.Marshal(cp)
	if e != nil || len(b) > 65536 {
		return ErrInvalidRequest
	}
	return nil
}
func (h *Handler) decode(w http.ResponseWriter, r *http.Request, v any) error {
	e := shared.DecodeJSON(w, r, v, h.MaxBytes, h.Strict)
	var se *shared.Error
	if errors.As(e, &se) && se.Status == 400 {
		return ErrInvalidRequest.WithCause(e)
	}
	return e
}
func (h *Handler) reply(w http.ResponseWriter, r *http.Request, event string, status int, out any, err error) {
	shared.EmitEvent(r.Context(), event, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	if err := shared.WriteJSON(w, status, out); err != nil {
		h.LoggerFor(r).Error("write discovery response", "err", err, "event", event)
	}
}
