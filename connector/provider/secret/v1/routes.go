package secret

import (
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/secret/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Connector event names emitted to connector_events_total{event,outcome}.
// Outcome is "ok" on success and "error" on any handler failure path.
const (
	eventCreateSecret               = "create_secret"
	eventUpdateSecret               = "update_secret"
	eventDeleteSecret               = "delete_secret"
	eventRotateSecret               = "rotate_secret"
	eventGetSecretContent           = "get_secret_content"
	eventVaultCheck                 = "vault_check"
	eventListVaultAttributes        = "list_vault_attributes"
	eventListVaultProfileAttributes = "list_vault_profile_attributes"
	eventListRotateAttributes       = "list_rotate_attributes"
	eventListSecretAttributes       = "list_secret_attributes"
)

// --- Secret Management -----------------------------------------------------

// POST /v1/secretProvider/secrets
func (h *Handler) createSecret(w http.ResponseWriter, r *http.Request) {
	var in mdl.CreateSecretRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCreateSecret, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.CreateSecret(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventCreateSecret, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusCreated, out); writeErr != nil {
		h.LoggerFor(r).Error("write createSecret response", "err", writeErr)
	}
}

// PUT /v1/secretProvider/secrets
func (h *Handler) updateSecret(w http.ResponseWriter, r *http.Request) {
	var in mdl.UpdateSecretRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventUpdateSecret, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.UpdateSecret(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventUpdateSecret, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write updateSecret response", "err", writeErr)
	}
}

// DELETE /v1/secretProvider/secrets
func (h *Handler) deleteSecret(w http.ResponseWriter, r *http.Request) {
	var in mdl.SecretRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventDeleteSecret, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.DeleteSecret(r.Context(), &in); err != nil {
		shared.EmitEvent(r.Context(), eventDeleteSecret, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventDeleteSecret, nil)
	w.WriteHeader(http.StatusNoContent)
}

// POST /v1/secretProvider/secrets/rotate
func (h *Handler) rotateSecret(w http.ResponseWriter, r *http.Request) {
	var in mdl.SecretRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventRotateSecret, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.RotateSecret(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventRotateSecret, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write rotateSecret response", "err", writeErr)
	}
}

// POST /v1/secretProvider/secrets/content
func (h *Handler) getSecretContent(w http.ResponseWriter, r *http.Request) {
	var in mdl.SecretRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventGetSecretContent, err)
		shared.RenderError(w, r, err)
		return
	}
	version := r.URL.Query().Get("version")
	out, err := h.provider.GetSecretContent(r.Context(), &in, version)
	shared.EmitEvent(r.Context(), eventGetSecretContent, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getSecretContent response", "err", writeErr)
	}
}

// --- Vault Management ------------------------------------------------------

// POST /v1/secretProvider/vaults
func (h *Handler) checkVaultConnection(w http.ResponseWriter, r *http.Request) {
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventVaultCheck, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.CheckVaultConnection(r.Context(), attrs); err != nil {
		shared.EmitEvent(r.Context(), eventVaultCheck, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventVaultCheck, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Attribute endpoints ---------------------------------------------------

// Attribute endpoints with no registered sub-provider respond 200 with an
// empty list. This is the SDK-wide convention: missing optional attribute
// providers must not break callers that enumerate them — they simply see
// no attributes for that surface. Apply the same default in every future
// provider package.

// GET /v1/secretProvider/vaults/attributes
func (h *Handler) listVaultAttributes(w http.ResponseWriter, r *http.Request) {
	var out []mdl.BaseAttributeDto
	var err error
	if h.vaultAttrs != nil {
		out, err = h.vaultAttrs.VaultAttributes(r.Context())
	}
	shared.EmitEvent(r.Context(), eventListVaultAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listVaultAttributes response", "err", writeErr)
	}
}

// POST /v1/secretProvider/vaultProfiles/attributes
func (h *Handler) listVaultProfileAttributes(w http.ResponseWriter, r *http.Request) {
	var ctxAttrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &ctxAttrs, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventListVaultProfileAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.vaultProfileAttrs != nil {
		out, err = h.vaultProfileAttrs.VaultProfileAttributes(r.Context(), ctxAttrs)
	}
	shared.EmitEvent(r.Context(), eventListVaultProfileAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listVaultProfileAttributes response", "err", writeErr)
	}
}

// GET /v1/secretProvider/secrets/rotate/attributes
func (h *Handler) getRotateAttributes(w http.ResponseWriter, r *http.Request) {
	var out []mdl.BaseAttributeDto
	var err error
	if h.rotateAttrs != nil {
		out, err = h.rotateAttrs.RotateAttributes(r.Context())
	}
	shared.EmitEvent(r.Context(), eventListRotateAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write getRotateAttributes response", "err", writeErr)
	}
}

// GET /v1/secretProvider/secrets/{secretType}/attributes
func (h *Handler) getSecretAttributes(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("secretType")
	st := mdl.SecretType(raw)
	if !isValidSecretType(st) {
		err := ErrInvalidSecretType.WithProperty("value", raw)
		shared.EmitEvent(r.Context(), eventListSecretAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.secretAttrs != nil {
		out, err = h.secretAttrs.SecretAttributes(r.Context(), st)
	}
	shared.EmitEvent(r.Context(), eventListSecretAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write getSecretAttributes response", "err", writeErr)
	}
}

// isValidSecretType reports whether s is one of the SecretType enum values.
// Path parameters bypass the model's UnmarshalJSON validation, so we check
// here before handing the value to the provider.
func isValidSecretType(s mdl.SecretType) bool {
	for _, v := range mdl.AllowedSecretTypeEnumValues {
		if v == s {
			return true
		}
	}
	return false
}

// ensureSlice converts a nil slice to an empty one so JSON encoding emits
// "[]" instead of "null". Spec response is array-typed; null would surprise
// callers and break clients that strictly type-check the response.
