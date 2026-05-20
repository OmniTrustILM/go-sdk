package compliance

import (
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/compliance/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Connector event names emitted to connector_events_total{event,outcome}.
const (
	eventGetRules                = "get_rules"
	eventGetRulesBatch           = "get_rules_batch"
	eventGetRule                 = "get_rule"
	eventGetGroups               = "get_groups"
	eventGetGroup                = "get_group"
	eventGetGroupRules           = "get_group_rules"
	eventCheckCompliance         = "check_compliance"
	eventListKindAttributes      = "list_kind_attributes"
	eventValidateKindAttributes  = "validate_kind_attributes"
)



// requireKind extracts the {kind} path parameter and returns 400 when empty.

// --- v2 compliance management --------------------------------------------

// GET /v2/complianceProvider/{kind}/rules
func (h *Handler) getRules(w http.ResponseWriter, r *http.Request) {
	kind, ok := shared.RequirePathValue(w, r, "kind")
	if !ok {
		return
	}
	out, err := h.provider.GetRules(r.Context(), kind)
	shared.EmitEvent(r.Context(), eventGetRules, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write getRules response", "err", writeErr)
	}
}

// POST /v2/complianceProvider/{kind}/rules
func (h *Handler) getRulesBatch(w http.ResponseWriter, r *http.Request) {
	kind, ok := shared.RequirePathValue(w, r, "kind")
	if !ok {
		return
	}
	var in mdl.ComplianceRulesBatchRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventGetRulesBatch, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.GetRulesBatch(r.Context(), kind, &in)
	shared.EmitEvent(r.Context(), eventGetRulesBatch, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getRulesBatch response", "err", writeErr)
	}
}

// GET /v2/complianceProvider/{kind}/rules/{ruleUuid}
func (h *Handler) getRule(w http.ResponseWriter, r *http.Request) {
	kind, ok := shared.RequirePathValue(w, r, "kind")
	if !ok {
		return
	}
	ruleUuid := r.PathValue("ruleUuid")
	if ruleUuid == "" {
		shared.RenderError(w, r, ErrInvalidRequest.WithProperty("reason", "ruleUuid is required"))
		return
	}
	out, err := h.provider.GetRule(r.Context(), kind, ruleUuid)
	shared.EmitEvent(r.Context(), eventGetRule, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getRule response", "err", writeErr)
	}
}

// GET /v2/complianceProvider/{kind}/groups
func (h *Handler) getGroups(w http.ResponseWriter, r *http.Request) {
	kind, ok := shared.RequirePathValue(w, r, "kind")
	if !ok {
		return
	}
	out, err := h.provider.GetGroups(r.Context(), kind)
	shared.EmitEvent(r.Context(), eventGetGroups, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write getGroups response", "err", writeErr)
	}
}

// GET /v2/complianceProvider/{kind}/groups/{groupUuid}
func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request) {
	kind, ok := shared.RequirePathValue(w, r, "kind")
	if !ok {
		return
	}
	groupUuid := r.PathValue("groupUuid")
	if groupUuid == "" {
		shared.RenderError(w, r, ErrInvalidRequest.WithProperty("reason", "groupUuid is required"))
		return
	}
	out, err := h.provider.GetGroup(r.Context(), kind, groupUuid)
	shared.EmitEvent(r.Context(), eventGetGroup, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getGroup response", "err", writeErr)
	}
}

// GET /v2/complianceProvider/{kind}/groups/{groupUuid}/rules
func (h *Handler) getGroupRules(w http.ResponseWriter, r *http.Request) {
	kind, ok := shared.RequirePathValue(w, r, "kind")
	if !ok {
		return
	}
	groupUuid := r.PathValue("groupUuid")
	if groupUuid == "" {
		shared.RenderError(w, r, ErrInvalidRequest.WithProperty("reason", "groupUuid is required"))
		return
	}
	out, err := h.provider.GetGroupRules(r.Context(), kind, groupUuid)
	shared.EmitEvent(r.Context(), eventGetGroupRules, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write getGroupRules response", "err", writeErr)
	}
}

// POST /v2/complianceProvider/{kind}/compliance
func (h *Handler) checkCompliance(w http.ResponseWriter, r *http.Request) {
	kind, ok := shared.RequirePathValue(w, r, "kind")
	if !ok {
		return
	}
	var in mdl.ComplianceRequestDtoV2
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCheckCompliance, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.CheckCompliance(r.Context(), kind, &in)
	shared.EmitEvent(r.Context(), eventCheckCompliance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write checkCompliance response", "err", writeErr)
	}
}

// --- v1 generic kind attribute routes ------------------------------------

// GET /v1/complianceProviderV2/{kind}/attributes
func (h *Handler) listKindAttributes(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	var out []mdl.BaseAttributeDto
	var err error
	if h.kindAttrs != nil {
		out, err = h.kindAttrs.Attributes(r.Context(), kind)
	}
	shared.EmitEvent(r.Context(), eventListKindAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listKindAttributes response", "err", writeErr)
	}
}

// POST /v1/complianceProviderV2/{kind}/attributes/validate
func (h *Handler) validateKindAttributes(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventValidateKindAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if h.kindAttrs == nil {
		shared.EmitEvent(r.Context(), eventValidateKindAttributes, nil)
		w.WriteHeader(http.StatusOK)
		return
	}
	vErrs, err := h.kindAttrs.ValidateAttributes(r.Context(), kind, attrs)
	shared.EmitEvent(r.Context(), eventValidateKindAttributes, err)
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
