package authority

import (
	"net/http"

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



// requireUUID extracts the {uuid} path parameter and returns 400 when empty.

// requireProfileName extracts the {endEntityProfileName} path parameter.

// requireProfileID extracts and parses the {endEntityProfileId} int path parameter.

// requireEndEntityName extracts the {endEntityName} path parameter.

// --- Authority management routes -----------------------------------------

func (h *Handler) listAuthorityInstances(w http.ResponseWriter, r *http.Request) {
	out, err := h.provider.ListAuthorityInstances(r.Context())
	shared.EmitEvent(r.Context(), eventListAuthorityInstances, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listAuthorityInstances response", "err", writeErr)
	}
}

func (h *Handler) createAuthorityInstance(w http.ResponseWriter, r *http.Request) {
	var in mdl.AuthorityProviderInstanceRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCreateAuthorityInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.CreateAuthorityInstance(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventCreateAuthorityInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write createAuthorityInstance response", "err", writeErr)
	}
}

func (h *Handler) getAuthorityInstance(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	out, err := h.provider.GetAuthorityInstance(r.Context(), uuid)
	shared.EmitEvent(r.Context(), eventGetAuthorityInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getAuthorityInstance response", "err", writeErr)
	}
}

func (h *Handler) updateAuthorityInstance(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	var in mdl.AuthorityProviderInstanceRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventUpdateAuthorityInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.UpdateAuthorityInstance(r.Context(), uuid, &in)
	shared.EmitEvent(r.Context(), eventUpdateAuthorityInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write updateAuthorityInstance response", "err", writeErr)
	}
}

func (h *Handler) removeAuthorityInstance(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	if err := h.provider.RemoveAuthorityInstance(r.Context(), uuid); err != nil {
		shared.EmitEvent(r.Context(), eventRemoveAuthorityInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventRemoveAuthorityInstance, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getConnection(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	if err := h.provider.GetConnection(r.Context(), uuid); err != nil {
		shared.EmitEvent(r.Context(), eventGetConnection, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventGetConnection, nil)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) getCaCertificates(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	var in mdl.CaCertificatesRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventGetCaCertificates, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.GetCaCertificates(r.Context(), uuid, &in)
	shared.EmitEvent(r.Context(), eventGetCaCertificates, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getCaCertificates response", "err", writeErr)
	}
}

func (h *Handler) getCrl(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	var in mdl.CertificateRevocationListRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventGetCrl, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.GetCrl(r.Context(), uuid, &in)
	shared.EmitEvent(r.Context(), eventGetCrl, err)
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
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	prof, ok := shared.RequirePathValue(w, r, "endEntityProfileName")
	if !ok {
		return
	}
	out, err := h.provider.ListEndEntities(r.Context(), uuid, prof)
	shared.EmitEvent(r.Context(), eventListEndEntities, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listEndEntities response", "err", writeErr)
	}
}

func (h *Handler) createEndEntity(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	prof, ok := shared.RequirePathValue(w, r, "endEntityProfileName")
	if !ok {
		return
	}
	var in mdl.AddEndEntityRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCreateEndEntity, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.CreateEndEntity(r.Context(), uuid, prof, &in); err != nil {
		shared.EmitEvent(r.Context(), eventCreateEndEntity, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventCreateEndEntity, nil)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) getEndEntity(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	prof, ok := shared.RequirePathValue(w, r, "endEntityProfileName")
	if !ok {
		return
	}
	name, ok := shared.RequirePathValue(w, r, "endEntityName")
	if !ok {
		return
	}
	out, err := h.provider.GetEndEntity(r.Context(), uuid, prof, name)
	shared.EmitEvent(r.Context(), eventGetEndEntity, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getEndEntity response", "err", writeErr)
	}
}

func (h *Handler) updateEndEntity(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	prof, ok := shared.RequirePathValue(w, r, "endEntityProfileName")
	if !ok {
		return
	}
	name, ok := shared.RequirePathValue(w, r, "endEntityName")
	if !ok {
		return
	}
	var in mdl.EditEndEntityRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventUpdateEndEntity, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.UpdateEndEntity(r.Context(), uuid, prof, name, &in); err != nil {
		shared.EmitEvent(r.Context(), eventUpdateEndEntity, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventUpdateEndEntity, nil)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) removeEndEntity(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	prof, ok := shared.RequirePathValue(w, r, "endEntityProfileName")
	if !ok {
		return
	}
	name, ok := shared.RequirePathValue(w, r, "endEntityName")
	if !ok {
		return
	}
	if err := h.provider.RemoveEndEntity(r.Context(), uuid, prof, name); err != nil {
		shared.EmitEvent(r.Context(), eventRemoveEndEntity, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventRemoveEndEntity, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) resetPassword(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	prof, ok := shared.RequirePathValue(w, r, "endEntityProfileName")
	if !ok {
		return
	}
	name, ok := shared.RequirePathValue(w, r, "endEntityName")
	if !ok {
		return
	}
	if err := h.provider.ResetPassword(r.Context(), uuid, prof, name); err != nil {
		shared.EmitEvent(r.Context(), eventResetPassword, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventResetPassword, nil)
	w.WriteHeader(http.StatusOK)
}

// --- Certificate management routes ---------------------------------------

func (h *Handler) issueCertificate(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	prof, ok := shared.RequirePathValue(w, r, "endEntityProfileName")
	if !ok {
		return
	}
	var in mdl.CertificateSignRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventIssueCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.IssueCertificate(r.Context(), uuid, prof, &in)
	shared.EmitEvent(r.Context(), eventIssueCertificate, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write issueCertificate response", "err", writeErr)
	}
}

func (h *Handler) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	prof, ok := shared.RequirePathValue(w, r, "endEntityProfileName")
	if !ok {
		return
	}
	var in mdl.CertRevocationDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventRevokeCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.RevokeCertificate(r.Context(), uuid, prof, &in); err != nil {
		shared.EmitEvent(r.Context(), eventRevokeCertificate, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventRevokeCertificate, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Profile listing routes ----------------------------------------------

func (h *Handler) listEntityProfiles(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	out, err := h.provider.ListEntityProfiles(r.Context(), uuid)
	shared.EmitEvent(r.Context(), eventListEntityProfiles, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listEntityProfiles response", "err", writeErr)
	}
}

func (h *Handler) listCertificateProfiles(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	profID, ok := shared.RequireIntPathValue(w, r, "endEntityProfileId")
	if !ok {
		return
	}
	out, err := h.provider.ListCertificateProfiles(r.Context(), uuid, profID)
	shared.EmitEvent(r.Context(), eventListCertificateProfiles, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listCertificateProfiles response", "err", writeErr)
	}
}

func (h *Handler) listCAsInProfile(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	profID, ok := shared.RequireIntPathValue(w, r, "endEntityProfileId")
	if !ok {
		return
	}
	out, err := h.provider.ListCAsInProfile(r.Context(), uuid, profID)
	shared.EmitEvent(r.Context(), eventListCAsInProfile, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
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
	shared.EmitEvent(r.Context(), eventListKindAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listKindAttributes response", "err", writeErr)
	}
}

func (h *Handler) validateKindAttributesFor(w http.ResponseWriter, r *http.Request, kind string) {
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

// --- RA Profile attribute routes -----------------------------------------

func (h *Handler) listRAProfileAttributes(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.raProfileAttrs != nil {
		out, err = h.raProfileAttrs.RAProfileAttributes(r.Context(), uuid)
	}
	shared.EmitEvent(r.Context(), eventListRAProfileAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listRAProfileAttributes response", "err", writeErr)
	}
}

func (h *Handler) validateRAProfileAttributes(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventValidateRAProfileAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if h.raProfileAttrs == nil {
		shared.EmitEvent(r.Context(), eventValidateRAProfileAttributes, nil)
		w.WriteHeader(http.StatusOK)
		return
	}
	vErrs, err := h.raProfileAttrs.ValidateRAProfileAttributes(r.Context(), uuid, attrs)
	shared.EmitEvent(r.Context(), eventValidateRAProfileAttributes, err)
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
