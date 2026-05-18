package authority

import (
	"context"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Connector event names emitted to connector_events_total{event,outcome}.
const (
	eventListAuthorityInstances             = "list_authority_instances"
	eventCreateAuthorityInstance            = "create_authority_instance"
	eventGetAuthorityInstance               = "get_authority_instance"
	eventUpdateAuthorityInstance            = "update_authority_instance"
	eventRemoveAuthorityInstance            = "remove_authority_instance"
	eventGetConnection                      = "get_connection"
	eventGetCaCertificates                  = "get_ca_certificates"
	eventGetCrl                             = "get_crl"
	eventIssueCertificate                   = "issue_certificate"
	eventRenewCertificate                   = "renew_certificate"
	eventRevokeCertificate                  = "revoke_certificate"
	eventIdentifyCertificate                = "identify_certificate"
	eventListKindAttributes                 = "list_kind_attributes"
	eventValidateKindAttributes             = "validate_kind_attributes"
	eventListRAProfileAttributes            = "list_ra_profile_attributes"
	eventValidateRAProfileAttributes        = "validate_ra_profile_attributes"
	eventListIssueCertificateAttributes     = "list_issue_certificate_attributes"
	eventValidateIssueCertificateAttributes = "validate_issue_certificate_attributes"
	eventListRevokeCertificateAttributes    = "list_revoke_certificate_attributes"
	eventValidateRevokeCertificateAttributes = "validate_revoke_certificate_attributes"
)

func emit(ctx context.Context, event string, err error) {
	mc := shared.MetricsFromContext(ctx)
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	mc.IncConnectorEvent(event, outcome)
}

// ensureSlice converts a nil slice into an empty one so JSON encoders emit
// "[]" instead of "null". Spec response bodies are array-typed; clients hate
// null.
func ensureSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// requireUUID extracts the {uuid} path parameter and returns 400 when empty.
func (h *Handler) requireUUID(w http.ResponseWriter, r *http.Request) (string, bool) {
	uuid := r.PathValue("uuid")
	if uuid == "" {
		shared.RenderError(w, r, ErrInvalidRequest.WithProperty("reason", "uuid is required"))
		return "", false
	}
	return uuid, true
}

// --- Authority Management routes ------------------------------------------

// GET /v1/authorityProvider/authorities
func (h *Handler) listAuthorityInstances(w http.ResponseWriter, r *http.Request) {
	out, err := h.provider.ListAuthorityInstances(r.Context())
	emit(r.Context(), eventListAuthorityInstances, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listAuthorityInstances response", "err", writeErr)
	}
}

// POST /v1/authorityProvider/authorities
func (h *Handler) createAuthorityInstance(w http.ResponseWriter, r *http.Request) {
	var in mdl.AuthorityProviderInstanceRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventCreateAuthorityInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.CreateAuthorityInstance(r.Context(), &in)
	emit(r.Context(), eventCreateAuthorityInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write createAuthorityInstance response", "err", writeErr)
	}
}

// GET /v1/authorityProvider/authorities/{uuid}
func (h *Handler) getAuthorityInstance(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	out, err := h.provider.GetAuthorityInstance(r.Context(), uuid)
	emit(r.Context(), eventGetAuthorityInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getAuthorityInstance response", "err", writeErr)
	}
}

// POST /v1/authorityProvider/authorities/{uuid}
func (h *Handler) updateAuthorityInstance(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var in mdl.AuthorityProviderInstanceRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventUpdateAuthorityInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.UpdateAuthorityInstance(r.Context(), uuid, &in)
	emit(r.Context(), eventUpdateAuthorityInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write updateAuthorityInstance response", "err", writeErr)
	}
}

// DELETE /v1/authorityProvider/authorities/{uuid}
func (h *Handler) removeAuthorityInstance(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	if err := h.provider.RemoveAuthorityInstance(r.Context(), uuid); err != nil {
		emit(r.Context(), eventRemoveAuthorityInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	emit(r.Context(), eventRemoveAuthorityInstance, nil)
	w.WriteHeader(http.StatusNoContent)
}

// GET /v1/authorityProvider/authorities/{uuid}/connect
func (h *Handler) getConnection(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	if err := h.provider.GetConnection(r.Context(), uuid); err != nil {
		emit(r.Context(), eventGetConnection, err)
		shared.RenderError(w, r, err)
		return
	}
	emit(r.Context(), eventGetConnection, nil)
	w.WriteHeader(http.StatusOK)
}

// POST /v1/authorityProvider/authorities/{uuid}/caCertificates
func (h *Handler) getCaCertificates(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var in mdl.CaCertificatesRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventGetCaCertificates, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.GetCaCertificates(r.Context(), uuid, &in)
	emit(r.Context(), eventGetCaCertificates, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getCaCertificates response", "err", writeErr)
	}
}

// POST /v1/authorityProvider/authorities/{uuid}/crl
func (h *Handler) getCrl(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var in mdl.CertificateRevocationListRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventGetCrl, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.GetCrl(r.Context(), uuid, &in)
	emit(r.Context(), eventGetCrl, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getCrl response", "err", writeErr)
	}
}

// --- Certificate Management (v2) routes -----------------------------------

// POST /v2/authorityProvider/authorities/{uuid}/certificates/issue
func (h *Handler) issueCertificate(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var in mdl.CertificateSignRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventIssueCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.IssueCertificate(r.Context(), uuid, &in)
	emit(r.Context(), eventIssueCertificate, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write issueCertificate response", "err", writeErr)
	}
}

// POST /v2/authorityProvider/authorities/{uuid}/certificates/renew
func (h *Handler) renewCertificate(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var in mdl.CertificateRenewRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventRenewCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.RenewCertificate(r.Context(), uuid, &in)
	emit(r.Context(), eventRenewCertificate, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write renewCertificate response", "err", writeErr)
	}
}

// POST /v2/authorityProvider/authorities/{uuid}/certificates/revoke
func (h *Handler) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var in mdl.CertRevocationDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventRevokeCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.RevokeCertificate(r.Context(), uuid, &in); err != nil {
		emit(r.Context(), eventRevokeCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	emit(r.Context(), eventRevokeCertificate, nil)
	w.WriteHeader(http.StatusNoContent)
}

// POST /v2/authorityProvider/authorities/{uuid}/certificates/identify
func (h *Handler) identifyCertificate(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var in mdl.CertificateIdentificationRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventIdentifyCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.IdentifyCertificate(r.Context(), uuid, &in)
	emit(r.Context(), eventIdentifyCertificate, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write identifyCertificate response", "err", writeErr)
	}
}

// --- Generic kind attribute routes ----------------------------------------
//
// These are mounted by Handler.Mount once per declared kind with the kind
// name as a literal path segment (see Mount's doc comment for the conflict
// reason). The kind is captured into a closure by Mount and passed in
// directly here, so r.PathValue("kind") would return "" — do not rely on
// it.

// GET /v1/authorityProvider/<kind>/attributes
func (h *Handler) listKindAttributesFor(w http.ResponseWriter, r *http.Request, kind string) {
	var out []mdl.BaseAttributeDto
	var err error
	if h.kindAttrs != nil {
		out, err = h.kindAttrs.Attributes(r.Context(), kind)
	}
	emit(r.Context(), eventListKindAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listKindAttributes response", "err", writeErr)
	}
}

// POST /v1/authorityProvider/<kind>/attributes/validate
func (h *Handler) validateKindAttributesFor(w http.ResponseWriter, r *http.Request, kind string) {
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventValidateKindAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if h.kindAttrs == nil {
		emit(r.Context(), eventValidateKindAttributes, nil)
		w.WriteHeader(http.StatusOK)
		return
	}
	vErrs, err := h.kindAttrs.ValidateAttributes(r.Context(), kind, attrs)
	emit(r.Context(), eventValidateKindAttributes, err)
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

// --- RA Profile attribute routes ------------------------------------------

// GET /v1/authorityProvider/authorities/{uuid}/raProfile/attributes
func (h *Handler) listRAProfileAttributes(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.raProfileAttrs != nil {
		out, err = h.raProfileAttrs.RAProfileAttributes(r.Context(), uuid)
	}
	emit(r.Context(), eventListRAProfileAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listRAProfileAttributes response", "err", writeErr)
	}
}

// POST /v1/authorityProvider/authorities/{uuid}/raProfile/attributes/validate
func (h *Handler) validateRAProfileAttributes(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventValidateRAProfileAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if h.raProfileAttrs == nil {
		emit(r.Context(), eventValidateRAProfileAttributes, nil)
		w.WriteHeader(http.StatusOK)
		return
	}
	vErrs, err := h.raProfileAttrs.ValidateRAProfileAttributes(r.Context(), uuid, attrs)
	emit(r.Context(), eventValidateRAProfileAttributes, err)
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

// --- Issue-certificate attribute routes -----------------------------------

// GET /v2/authorityProvider/authorities/{uuid}/certificates/issue/attributes
func (h *Handler) listIssueCertificateAttributes(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.issueAttrs != nil {
		out, err = h.issueAttrs.IssueCertificateAttributes(r.Context(), uuid)
	}
	emit(r.Context(), eventListIssueCertificateAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listIssueCertificateAttributes response", "err", writeErr)
	}
}

// POST /v2/authorityProvider/authorities/{uuid}/certificates/issue/attributes/validate
func (h *Handler) validateIssueCertificateAttributes(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventValidateIssueCertificateAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if h.issueAttrs == nil {
		emit(r.Context(), eventValidateIssueCertificateAttributes, nil)
		w.WriteHeader(http.StatusOK)
		return
	}
	vErrs, err := h.issueAttrs.ValidateIssueCertificateAttributes(r.Context(), uuid, attrs)
	emit(r.Context(), eventValidateIssueCertificateAttributes, err)
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

// --- Revoke-certificate attribute routes ----------------------------------

// GET /v2/authorityProvider/authorities/{uuid}/certificates/revoke/attributes
func (h *Handler) listRevokeCertificateAttributes(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.revokeAttrs != nil {
		out, err = h.revokeAttrs.RevokeCertificateAttributes(r.Context(), uuid)
	}
	emit(r.Context(), eventListRevokeCertificateAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listRevokeCertificateAttributes response", "err", writeErr)
	}
}

// POST /v2/authorityProvider/authorities/{uuid}/certificates/revoke/attributes/validate
func (h *Handler) validateRevokeCertificateAttributes(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventValidateRevokeCertificateAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if h.revokeAttrs == nil {
		emit(r.Context(), eventValidateRevokeCertificateAttributes, nil)
		w.WriteHeader(http.StatusOK)
		return
	}
	vErrs, err := h.revokeAttrs.ValidateRevokeCertificateAttributes(r.Context(), uuid, attrs)
	emit(r.Context(), eventValidateRevokeCertificateAttributes, err)
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
