package discovery

import (
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

func (h *Handler) initiate(w http.ResponseWriter, r *http.Request) {
	var in mdl.DiscoveryInitiateRequestDto
	err := h.decode(w, r, &in)
	if err == nil {
		err = validate(in.RunId, in.Resources, in.Checkpoint)
	}
	if err != nil {
		h.reply(w, r, "discovery_initiate", 202, nil, err)
		return
	}
	out, err := h.provider.Initiate(r.Context(), &in)
	if out == nil && err == nil {
		err = ErrNilResponse
	}
	h.reply(w, r, "discovery_initiate", 202, out, err)
}
func (h *Handler) resume(w http.ResponseWriter, r *http.Request) {
	var in mdl.DiscoveryRunRequestDto
	err := h.decode(w, r, &in)
	if err == nil {
		err = validate(in.RunId, in.Resources, in.Checkpoint)
	}
	if err != nil {
		h.reply(w, r, "discovery_resume", 202, nil, err)
		return
	}
	out, err := h.provider.Resume(r.Context(), &in)
	if out == nil && err == nil {
		err = ErrNilResponse
	}
	h.reply(w, r, "discovery_resume", 202, out, err)
}
func (h *Handler) stop(w http.ResponseWriter, r *http.Request) {
	var in mdl.DiscoveryRunRequestDto
	err := h.decode(w, r, &in)
	if err == nil {
		err = validate(in.RunId, in.Resources, in.Checkpoint)
	}
	if err != nil {
		h.reply(w, r, "discovery_stop", 200, nil, err)
		return
	}
	out, err := h.provider.Stop(r.Context(), &in)
	if out == nil && err == nil {
		err = ErrNilResponse
	}
	h.reply(w, r, "discovery_stop", 200, out, err)
}
func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	var in mdl.DiscoveryRunRequestDto
	err := h.decode(w, r, &in)
	if err == nil {
		err = validate(in.RunId, in.Resources, in.Checkpoint)
	}
	if err != nil {
		h.reply(w, r, "discovery_status", 200, nil, err)
		return
	}
	out, err := h.provider.Status(r.Context(), &in)
	if out == nil && err == nil {
		err = ErrNilResponse
	}
	h.reply(w, r, "discovery_status", 200, out, err)
}
func (h *Handler) results(w http.ResponseWriter, r *http.Request) {
	var in mdl.DiscoveryDrainRequestDto
	err := h.decode(w, r, &in)
	if err == nil {
		err = validate(in.RunId, in.Resources, in.Checkpoint)
	}
	if err == nil && ((in.AfterSequence != nil && *in.AfterSequence < 0) || (in.MaxItems != nil && *in.MaxItems < 1) || (in.MaxBytes != nil && (*in.MaxBytes < 1 || *in.MaxBytes > MaxResultBytes))) {
		err = ErrInvalidRequest
	}
	if err != nil {
		h.reply(w, r, "discovery_results", 200, nil, err)
		return
	}
	out, err := h.provider.Results(r.Context(), &in)
	if out != nil {
		copyOut := *out
		copyOut.Items = shared.EnsureSlice(copyOut.Items)
		out = &copyOut
	}
	if out == nil && err == nil {
		err = ErrNilResponse
	}
	h.reply(w, r, "discovery_results", 200, out, err)
}
func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	var in mdl.DiscoveryRunRequestDto
	err := h.decode(w, r, &in)
	if err == nil {
		err = validate(in.RunId, in.Resources, in.Checkpoint)
	}
	if err != nil {
		h.reply(w, r, "discovery_cancel", 204, nil, err)
		return
	}
	err = h.provider.Cancel(r.Context(), &in)
	var out any
	h.reply(w, r, "discovery_cancel", 204, out, err)
}
func (h *Handler) resources(w http.ResponseWriter, r *http.Request) {
	out, err := h.provider.SupportedResources(r.Context())
	h.reply(w, r, "discovery_resources", 200, shared.EnsureSlice(out), err)
}
func (h *Handler) runAttributes(w http.ResponseWriter, r *http.Request) {
	out, err := h.provider.RunAttributes(r.Context())
	h.reply(w, r, "discovery_run_attributes", 200, shared.EnsureSlice(out), err)
}
func (h *Handler) resourceAttributes(w http.ResponseWriter, r *http.Request) {
	resource, e := mdl.NewResourceFromValue(r.PathValue("resource"))
	if e != nil {
		h.reply(w, r, "discovery_resource_attributes", 422, nil, ErrInvalidRequest)
		return
	}
	out, err := h.provider.ResourceAttributes(r.Context(), *resource)
	h.reply(w, r, "discovery_resource_attributes", 200, shared.EnsureSlice(out), err)
}
