package authority

import (
	"context"
	"net/http"
	"strconv"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Connector event names emitted to connector_events_total{event,outcome}.
const (
	eventListAuthorityInstances      = "list_authority_instances"
	eventCreateAuthorityInstance     = "create_authority_instance"
	eventGetAuthorityInstance        = "get_authority_instance"
	eventUpdateAuthorityInstance     = "update_authority_instance"
	eventRemoveAuthorityInstance     = "remove_authority_instance"
	eventGetConnection               = "get_connection"
	eventGetCaCertificates           = "get_ca_certificates"
	eventGetCrl                      = "get_crl"
	eventListEndEntities             = "list_end_entities"
	eventCreateEndEntity             = "create_end_entity"
	eventGetEndEntity                = "get_end_entity"
	eventUpdateEndEntity             = "update_end_entity"
	eventRemoveEndEntity             = "remove_end_entity"
	eventResetPassword               = "reset_password"
	eventIssueCertificate            = "issue_certificate"
	eventRevokeCertificate           = "revoke_certificate"
	eventListEntityProfiles          = "list_entity_profiles"
	eventListCertificateProfiles     = "list_certificate_profiles"
	eventListCAsInProfile            = "list_cas_in_profile"
	eventListKindAttributes          = "list_kind_attributes"
	eventValidateKindAttributes      = "validate_kind_attributes"
	eventListRAProfileAttributes     = "list_ra_profile_attributes"
	eventValidateRAProfileAttributes = "validate_ra_profile_attributes"
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

// requireUUID extracts the {uuid} path parameter and returns 400 when empty.
func (h *Handler) requireUUID(w http.ResponseWriter, r *http.Request) (string, bool) {
	uuid := r.PathValue("uuid")
	if uuid == "" {
		shared.RenderError(w, r, ErrInvalidRequest.WithProperty("reason", "uuid is required"))
		return "", false
	}
	return uuid, true
}

// requireProfileName extracts the {endEntityProfileName} path parameter.
func (h *Handler) requireProfileName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("endEntityProfileName")
	if name == "" {
		shared.RenderError(w, r, ErrInvalidRequest.WithProperty("reason", "endEntityProfileName is required"))
		return "", false
	}
	return name, true
}

// requireProfileID extracts and parses the {endEntityProfileId} int path parameter.
func (h *Handler) requireProfileID(w http.ResponseWriter, r *http.Request) (int32, bool) {
	raw := r.PathValue("endEntityProfileId")
	if raw == "" {
		shared.RenderError(w, r, ErrInvalidRequest.WithProperty("reason", "endEntityProfileId is required"))
		return 0, false
	}
	v, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		shared.RenderError(w, r, ErrInvalidRequest.
			WithCause(err).
			WithProperty("reason", "endEntityProfileId must be an integer").
			WithProperty("value", raw))
		return 0, false
	}
	return int32(v), true
}

// requireEndEntityName extracts the {endEntityName} path parameter.
func (h *Handler) requireEndEntityName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("endEntityName")
	if name == "" {
		shared.RenderError(w, r, ErrInvalidRequest.WithProperty("reason", "endEntityName is required"))
		return "", false
	}
	return name, true
}

// --- Authority management routes -----------------------------------------

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

// --- End entity management routes ----------------------------------------

func (h *Handler) listEndEntities(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	prof, ok := h.requireProfileName(w, r)
	if !ok {
		return
	}
	out, err := h.provider.ListEndEntities(r.Context(), uuid, prof)
	emit(r.Context(), eventListEndEntities, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listEndEntities response", "err", writeErr)
	}
}

func (h *Handler) createEndEntity(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	prof, ok := h.requireProfileName(w, r)
	if !ok {
		return
	}
	var in mdl.AddEndEntityRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventCreateEndEntity, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.CreateEndEntity(r.Context(), uuid, prof, &in); err != nil {
		emit(r.Context(), eventCreateEndEntity, err)
		shared.RenderError(w, r, err)
		return
	}
	emit(r.Context(), eventCreateEndEntity, nil)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) getEndEntity(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	prof, ok := h.requireProfileName(w, r)
	if !ok {
		return
	}
	name, ok := h.requireEndEntityName(w, r)
	if !ok {
		return
	}
	out, err := h.provider.GetEndEntity(r.Context(), uuid, prof, name)
	emit(r.Context(), eventGetEndEntity, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getEndEntity response", "err", writeErr)
	}
}

func (h *Handler) updateEndEntity(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	prof, ok := h.requireProfileName(w, r)
	if !ok {
		return
	}
	name, ok := h.requireEndEntityName(w, r)
	if !ok {
		return
	}
	var in mdl.EditEndEntityRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventUpdateEndEntity, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.UpdateEndEntity(r.Context(), uuid, prof, name, &in); err != nil {
		emit(r.Context(), eventUpdateEndEntity, err)
		shared.RenderError(w, r, err)
		return
	}
	emit(r.Context(), eventUpdateEndEntity, nil)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) removeEndEntity(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	prof, ok := h.requireProfileName(w, r)
	if !ok {
		return
	}
	name, ok := h.requireEndEntityName(w, r)
	if !ok {
		return
	}
	if err := h.provider.RemoveEndEntity(r.Context(), uuid, prof, name); err != nil {
		emit(r.Context(), eventRemoveEndEntity, err)
		shared.RenderError(w, r, err)
		return
	}
	emit(r.Context(), eventRemoveEndEntity, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) resetPassword(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	prof, ok := h.requireProfileName(w, r)
	if !ok {
		return
	}
	name, ok := h.requireEndEntityName(w, r)
	if !ok {
		return
	}
	if err := h.provider.ResetPassword(r.Context(), uuid, prof, name); err != nil {
		emit(r.Context(), eventResetPassword, err)
		shared.RenderError(w, r, err)
		return
	}
	emit(r.Context(), eventResetPassword, nil)
	w.WriteHeader(http.StatusOK)
}

// --- Certificate management routes ---------------------------------------

func (h *Handler) issueCertificate(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	prof, ok := h.requireProfileName(w, r)
	if !ok {
		return
	}
	var in mdl.CertificateSignRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventIssueCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.IssueCertificate(r.Context(), uuid, prof, &in)
	emit(r.Context(), eventIssueCertificate, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write issueCertificate response", "err", writeErr)
	}
}

func (h *Handler) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	prof, ok := h.requireProfileName(w, r)
	if !ok {
		return
	}
	var in mdl.CertRevocationDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventRevokeCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.RevokeCertificate(r.Context(), uuid, prof, &in); err != nil {
		emit(r.Context(), eventRevokeCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	emit(r.Context(), eventRevokeCertificate, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Profile listing routes ----------------------------------------------

func (h *Handler) listEntityProfiles(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	out, err := h.provider.ListEntityProfiles(r.Context(), uuid)
	emit(r.Context(), eventListEntityProfiles, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listEntityProfiles response", "err", writeErr)
	}
}

func (h *Handler) listCertificateProfiles(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	profID, ok := h.requireProfileID(w, r)
	if !ok {
		return
	}
	out, err := h.provider.ListCertificateProfiles(r.Context(), uuid, profID)
	emit(r.Context(), eventListCertificateProfiles, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listCertificateProfiles response", "err", writeErr)
	}
}

func (h *Handler) listCAsInProfile(w http.ResponseWriter, r *http.Request) {
	uuid, ok := h.requireUUID(w, r)
	if !ok {
		return
	}
	profID, ok := h.requireProfileID(w, r)
	if !ok {
		return
	}
	out, err := h.provider.ListCAsInProfile(r.Context(), uuid, profID)
	emit(r.Context(), eventListCAsInProfile, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listCAsInProfile response", "err", writeErr)
	}
}

// --- Generic kind attribute routes (per-literal-kind via closure) --------

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

// --- RA Profile attribute routes -----------------------------------------

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
