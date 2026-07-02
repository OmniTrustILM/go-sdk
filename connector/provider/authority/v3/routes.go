package authority

import (
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Connector event names emitted to connector_events_total{event,outcome}.
const (
	eventIssue              = "issue"
	eventIssueStatus        = "issue_status"
	eventCancelIssue        = "cancel_issue"
	eventRenew              = "renew"
	eventRegister           = "register"
	eventRegisterStatus     = "register_status"
	eventCancelRegister     = "cancel_register"
	eventRevoke             = "revoke"
	eventRevokeStatus       = "revoke_status"
	eventCancelRevoke       = "cancel_revoke"
	eventIdentify           = "identify"
	eventCheckConnection    = "check_authority_connection"
	eventGetCrl             = "get_crl"
	eventGetCaCertificates  = "get_ca_certificates"
	eventListAuthorityAttrs = "list_authority_attributes"
	eventListRAProfileAttrs = "list_ra_profile_attributes"
	eventListIssueAttrs     = "list_issue_attributes"
	eventListRevokeAttrs    = "list_revoke_attributes"
	eventListRegisterAttrs  = "list_register_attributes"
	eventListDefinitions    = "list_definitions"
	eventGetDefinition      = "get_definition"
	eventAttributeCallback  = "attribute_callback"
)

// --- Certificate Management: issue family ----------------------------------

// POST /v3/authorityProvider/certificates/issue
// 200 sync (certificate in body) | 202 async (meta tracking handle).
func (h *Handler) issue(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateSignRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventIssue, err)
		shared.RenderError(w, r, err)
		return
	}
	out, accepted, err := h.provider.Issue(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventIssue, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	status := http.StatusOK
	if accepted {
		status = http.StatusAccepted
	}
	if writeErr := shared.WriteJSON(w, status, out); writeErr != nil {
		h.LoggerFor(r).Error("write issue response", "err", writeErr)
	}
}

// POST /v3/authorityProvider/certificates/issue/status
// 200 with the operation status (inProgress / completed / failed).
func (h *Handler) issueStatus(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateOperationStatusRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventIssueStatus, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.IssueStatus(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventIssueStatus, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write issueStatus response", "err", writeErr)
	}
}

// POST /v3/authorityProvider/certificates/issue/cancel
// 204 aborted | 422 ErrCancelRefused | 404 ErrOperationNotFound.
func (h *Handler) cancelIssue(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateOperationCancelRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCancelIssue, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.CancelIssue(r.Context(), &in); err != nil {
		shared.EmitEvent(r.Context(), eventCancelIssue, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventCancelIssue, nil)
	w.WriteHeader(http.StatusNoContent)
}

// POST /v3/authorityProvider/certificates/renew
// 200 sync | 202 async. Shares the issue attribute schema.
func (h *Handler) renew(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateRenewRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventRenew, err)
		shared.RenderError(w, r, err)
		return
	}
	out, accepted, err := h.provider.Renew(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventRenew, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	status := http.StatusOK
	if accepted {
		status = http.StatusAccepted
	}
	if writeErr := shared.WriteJSON(w, status, out); writeErr != nil {
		h.LoggerFor(r).Error("write renew response", "err", writeErr)
	}
}

// --- Certificate Management: register family -------------------------------

// POST /v3/authorityProvider/certificates/register
// 200 sync (meta identifies the registration) | 202 async.
func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateRegistrationRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventRegister, err)
		shared.RenderError(w, r, err)
		return
	}
	out, accepted, err := h.provider.Register(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventRegister, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	status := http.StatusOK
	if accepted {
		status = http.StatusAccepted
	}
	if writeErr := shared.WriteJSON(w, status, out); writeErr != nil {
		h.LoggerFor(r).Error("write register response", "err", writeErr)
	}
}

// POST /v3/authorityProvider/certificates/register/status
// 200 with the operation status (inProgress / completed / failed).
func (h *Handler) registerStatus(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateOperationStatusRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventRegisterStatus, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.RegisterStatus(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventRegisterStatus, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write registerStatus response", "err", writeErr)
	}
}

// POST /v3/authorityProvider/certificates/register/cancel
// 204 aborted | 422 ErrCancelRefused | 404 ErrOperationNotFound.
func (h *Handler) cancelRegister(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateOperationCancelRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCancelRegister, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.CancelRegister(r.Context(), &in); err != nil {
		shared.EmitEvent(r.Context(), eventCancelRegister, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventCancelRegister, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Certificate Management: revoke family ---------------------------------

// POST /v3/authorityProvider/certificates/revoke
// 204 sync (no body — RFC 9110 forbids 204 payloads) | 202 async with meta.
func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateRevocationRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventRevoke, err)
		shared.RenderError(w, r, err)
		return
	}
	out, accepted, err := h.provider.Revoke(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventRevoke, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if !accepted {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusAccepted, out); writeErr != nil {
		h.LoggerFor(r).Error("write revoke response", "err", writeErr)
	}
}

// POST /v3/authorityProvider/certificates/revoke/status
// 200 with the operation status (inProgress / completed / failed).
func (h *Handler) revokeStatus(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateOperationStatusRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventRevokeStatus, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.RevokeStatus(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventRevokeStatus, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write revokeStatus response", "err", writeErr)
	}
}

// POST /v3/authorityProvider/certificates/revoke/cancel
// 204 aborted | 422 ErrCancelRefused | 404 ErrOperationNotFound.
func (h *Handler) cancelRevoke(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateOperationCancelRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCancelRevoke, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.CancelRevoke(r.Context(), &in); err != nil {
		shared.EmitEvent(r.Context(), eventCancelRevoke, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventCancelRevoke, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Certificate Management: identify ---------------------------------------

// POST /v3/authorityProvider/certificates/identify
// 200 identified (meta in body) | 404 ErrCertificateNotFound.
func (h *Handler) identify(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateIdentificationRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventIdentify, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.Identify(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventIdentify, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write identify response", "err", writeErr)
	}
}

// --- Authority Management ----------------------------------------------------

// POST /v3/authorityProvider/authorities
// 204 reachable | error otherwise.
func (h *Handler) checkAuthorityConnection(w http.ResponseWriter, r *http.Request) {
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCheckConnection, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.CheckAuthorityConnection(r.Context(), attrs); err != nil {
		shared.EmitEvent(r.Context(), eventCheckConnection, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventCheckConnection, nil)
	w.WriteHeader(http.StatusNoContent)
}

// POST /v3/authorityProvider/authorities/crl
// 200 CRL data.
func (h *Handler) getCrl(w http.ResponseWriter, r *http.Request) {
	var in mdl.CrlRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventGetCrl, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.GetCrl(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventGetCrl, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getCrl response", "err", writeErr)
	}
}

// POST /v3/authorityProvider/authorities/caCertificates
// 200 CA chain.
func (h *Handler) getCaCertificates(w http.ResponseWriter, r *http.Request) {
	var in mdl.CaCertificatesRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventGetCaCertificates, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.GetCaCertificates(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventGetCaCertificates, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getCaCertificates response", "err", writeErr)
	}
}

// --- Attribute endpoints -----------------------------------------------------

// Attribute endpoints with no registered sub-provider respond 200 with an
// empty list — the SDK-wide convention: missing optional attribute providers
// must not break callers that enumerate them.

// GET /v3/authorityProvider/authorities/attributes
func (h *Handler) listAuthorityAttributes(w http.ResponseWriter, r *http.Request) {
	var out []mdl.BaseAttributeDto
	var err error
	if h.authorityAttrs != nil {
		out, err = h.authorityAttrs.AuthorityAttributes(r.Context())
	}
	shared.EmitEvent(r.Context(), eventListAuthorityAttrs, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listAuthorityAttributes response", "err", writeErr)
	}
}

// POST /v3/authorityProvider/authorities/raProfile/attributes
func (h *Handler) listRAProfileAttributes(w http.ResponseWriter, r *http.Request) {
	var authorityAttrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &authorityAttrs, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventListRAProfileAttrs, err)
		shared.RenderError(w, r, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.raProfileAttrs != nil {
		out, err = h.raProfileAttrs.RAProfileAttributes(r.Context(), authorityAttrs)
	}
	shared.EmitEvent(r.Context(), eventListRAProfileAttrs, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listRAProfileAttributes response", "err", writeErr)
	}
}

// POST /v3/authorityProvider/certificates/issue/attributes
func (h *Handler) listIssueAttributes(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateAttributeListRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventListIssueAttrs, err)
		shared.RenderError(w, r, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.issueAttrs != nil {
		out, err = h.issueAttrs.IssueAttributes(r.Context(), &in)
	}
	shared.EmitEvent(r.Context(), eventListIssueAttrs, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listIssueAttributes response", "err", writeErr)
	}
}

// POST /v3/authorityProvider/certificates/revoke/attributes
func (h *Handler) listRevokeAttributes(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateAttributeListRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventListRevokeAttrs, err)
		shared.RenderError(w, r, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.revokeAttrs != nil {
		out, err = h.revokeAttrs.RevokeAttributes(r.Context(), &in)
	}
	shared.EmitEvent(r.Context(), eventListRevokeAttrs, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listRevokeAttributes response", "err", writeErr)
	}
}

// POST /v3/authorityProvider/certificates/register/attributes
func (h *Handler) listRegisterAttributes(w http.ResponseWriter, r *http.Request) {
	var in mdl.CertificateAttributeListRequestDtoV3
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventListRegisterAttrs, err)
		shared.RenderError(w, r, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.registerAttrs != nil {
		out, err = h.registerAttrs.RegisterAttributes(r.Context(), &in)
	}
	shared.EmitEvent(r.Context(), eventListRegisterAttrs, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listRegisterAttributes response", "err", writeErr)
	}
}

// --- Connector Attributes API (/v2/attributes) ------------------------------

// GET /v2/attributes
// 200 with the connector's attribute-definition set. With no provider wired,
// returns an empty definition set (connectorVersion "", definitions []).
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
