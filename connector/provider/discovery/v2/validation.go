package discovery

import (
	"encoding/json"
	"errors"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/google/uuid"
)

// MaxResultBytes is the transport cap on a results response: the largest maxBytes
// a drain may ask for.
const MaxResultBytes int64 = 10 * 1024 * 1024

// invalid is a 422 VALIDATION_FAILED naming the broken rule; a checkpointed
// run ends on one, so the reason must reach the operator.
func invalid(format string, args ...any) *shared.Error {
	return shared.Invalid("VALIDATION_FAILED", format, args...)
}

func validate(run string, resources []mdl.Resource, cp []mdl.MetadataAttribute) error {
	if _, e := uuid.Parse(run); e != nil {
		return invalid("runId must be a UUID")
	}
	if len(resources) == 0 {
		return invalid("resources must not be empty")
	}
	seen := map[mdl.Resource]bool{}
	for _, r := range resources {
		if !r.IsValid() {
			return invalid("resources holds an unknown resource type %q", string(r))
		}
		if seen[r] {
			return invalid("resources lists %q more than once", string(r))
		}
		seen[r] = true
	}
	b, e := json.Marshal(cp)
	if e != nil {
		return invalid("checkpoint cannot be serialized").WithCause(e)
	}
	if len(b) > MaxCheckpointBytes {
		return invalid("checkpoint exceeds %d bytes", MaxCheckpointBytes)
	}
	return nil
}

// validateDrainBounds checks the paging bounds of a results call.
func validateDrainBounds(in *mdl.DiscoveryDrainRequestDto) error {
	switch {
	case in.AfterSequence != nil && *in.AfterSequence < 0:
		return invalid("afterSequence must not be negative")
	case in.MaxItems != nil && *in.MaxItems < 1:
		return invalid("maxItems must be at least 1")
	case in.MaxBytes != nil && (*in.MaxBytes < 1 || *in.MaxBytes > MaxResultBytes):
		return invalid("maxBytes must be between 1 and %d", MaxResultBytes)
	}
	return nil
}

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, v any) error {
	e := shared.DecodeJSON(w, r, v, h.MaxBytes, h.Strict)
	var se *shared.Error
	if errors.As(e, &se) && se.Status == 400 {
		return invalid("%s", se.Detail).WithCause(e)
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
