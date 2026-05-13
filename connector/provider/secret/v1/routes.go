package secret

import (
	"context"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/secret/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Connector event names emitted to connector_events_total{event,outcome}.
// Outcome is "ok" on success and "error" on any handler failure path.
const (
	eventCreateSecret     = "create_secret"
	eventUpdateSecret     = "update_secret"
	eventDeleteSecret     = "delete_secret"
	eventRotateSecret     = "rotate_secret"
	eventGetSecretContent = "get_secret_content"
	eventVaultCheck       = "vault_check"
)

func emit(ctx context.Context, event string, err error) {
	mc := shared.MetricsFromContext(ctx)
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	mc.IncConnectorEvent(event, outcome)
}

// --- Secret Management -----------------------------------------------------

// POST /v1/secretProvider/secrets
func (h *Handler) createSecret(w http.ResponseWriter, r *http.Request) {
	var in mdl.CreateSecretRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.maxBytes, h.strict); err != nil {
		emit(r.Context(), eventCreateSecret, err)
		shared.WriteProblem(w, r, err)
		return
	}
	out, err := h.provider.CreateSecret(r.Context(), &in)
	emit(r.Context(), eventCreateSecret, err)
	if err != nil {
		shared.WriteProblem(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusCreated, out); writeErr != nil {
		h.loggerFor(r).Error("write createSecret response", "err", writeErr)
	}
}

// PUT /v1/secretProvider/secrets
func (h *Handler) updateSecret(w http.ResponseWriter, r *http.Request) {
	var in mdl.UpdateSecretRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.maxBytes, h.strict); err != nil {
		emit(r.Context(), eventUpdateSecret, err)
		shared.WriteProblem(w, r, err)
		return
	}
	out, err := h.provider.UpdateSecret(r.Context(), &in)
	emit(r.Context(), eventUpdateSecret, err)
	if err != nil {
		shared.WriteProblem(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.loggerFor(r).Error("write updateSecret response", "err", writeErr)
	}
}

// DELETE /v1/secretProvider/secrets
func (h *Handler) deleteSecret(w http.ResponseWriter, r *http.Request) {
	var in mdl.SecretRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.maxBytes, h.strict); err != nil {
		emit(r.Context(), eventDeleteSecret, err)
		shared.WriteProblem(w, r, err)
		return
	}
	if err := h.provider.DeleteSecret(r.Context(), &in); err != nil {
		emit(r.Context(), eventDeleteSecret, err)
		shared.WriteProblem(w, r, err)
		return
	}
	emit(r.Context(), eventDeleteSecret, nil)
	w.WriteHeader(http.StatusNoContent)
}

// POST /v1/secretProvider/secrets/rotate
func (h *Handler) rotateSecret(w http.ResponseWriter, r *http.Request) {
	var in mdl.SecretRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.maxBytes, h.strict); err != nil {
		emit(r.Context(), eventRotateSecret, err)
		shared.WriteProblem(w, r, err)
		return
	}
	out, err := h.provider.RotateSecret(r.Context(), &in)
	emit(r.Context(), eventRotateSecret, err)
	if err != nil {
		shared.WriteProblem(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.loggerFor(r).Error("write rotateSecret response", "err", writeErr)
	}
}

// POST /v1/secretProvider/secrets/content
func (h *Handler) getSecretContent(w http.ResponseWriter, r *http.Request) {
	var in mdl.SecretRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.maxBytes, h.strict); err != nil {
		emit(r.Context(), eventGetSecretContent, err)
		shared.WriteProblem(w, r, err)
		return
	}
	version := r.URL.Query().Get("version")
	out, err := h.provider.GetSecretContent(r.Context(), &in, version)
	emit(r.Context(), eventGetSecretContent, err)
	if err != nil {
		shared.WriteProblem(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.loggerFor(r).Error("write getSecretContent response", "err", writeErr)
	}
}

// --- Vault Management ------------------------------------------------------

// POST /v1/secretProvider/vaults
func (h *Handler) checkVaultConnection(w http.ResponseWriter, r *http.Request) {
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.maxBytes, h.strict); err != nil {
		emit(r.Context(), eventVaultCheck, err)
		shared.WriteProblem(w, r, err)
		return
	}
	if err := h.provider.CheckVaultConnection(r.Context(), attrs); err != nil {
		emit(r.Context(), eventVaultCheck, err)
		shared.WriteProblem(w, r, err)
		return
	}
	emit(r.Context(), eventVaultCheck, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Attribute endpoints ---------------------------------------------------

// GET /v1/secretProvider/vaults/attributes
func (h *Handler) listVaultAttributes(w http.ResponseWriter, r *http.Request) {
	if h.vaultAttrs == nil {
		shared.WriteProblem(w, r, ErrAttributesNotRegistered)
		return
	}
	out, err := h.vaultAttrs.VaultAttributes(r.Context())
	if err != nil {
		shared.WriteProblem(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.loggerFor(r).Error("write listVaultAttributes response", "err", writeErr)
	}
}

// POST /v1/secretProvider/vaultProfiles/attributes
func (h *Handler) listVaultProfileAttributes(w http.ResponseWriter, r *http.Request) {
	if h.vaultProfileAttrs == nil {
		shared.WriteProblem(w, r, ErrAttributesNotRegistered)
		return
	}
	var ctxAttrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &ctxAttrs, h.maxBytes, h.strict); err != nil {
		shared.WriteProblem(w, r, err)
		return
	}
	out, err := h.vaultProfileAttrs.VaultProfileAttributes(r.Context(), ctxAttrs)
	if err != nil {
		shared.WriteProblem(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.loggerFor(r).Error("write listVaultProfileAttributes response", "err", writeErr)
	}
}

// GET /v1/secretProvider/secrets/rotate/attributes
func (h *Handler) getRotateAttributes(w http.ResponseWriter, r *http.Request) {
	if h.rotateAttrs == nil {
		shared.WriteProblem(w, r, ErrAttributesNotRegistered)
		return
	}
	out, err := h.rotateAttrs.RotateAttributes(r.Context())
	if err != nil {
		shared.WriteProblem(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.loggerFor(r).Error("write getRotateAttributes response", "err", writeErr)
	}
}

// GET /v1/secretProvider/secrets/{secretType}/attributes
func (h *Handler) getSecretAttributes(w http.ResponseWriter, r *http.Request) {
	if h.secretAttrs == nil {
		shared.WriteProblem(w, r, ErrAttributesNotRegistered)
		return
	}
	raw := r.PathValue("secretType")
	st := mdl.SecretType(raw)
	if !isValidSecretType(st) {
		shared.WriteProblem(w, r, ErrInvalidSecretType.WithProperty("value", raw))
		return
	}
	out, err := h.secretAttrs.SecretAttributes(r.Context(), st)
	if err != nil {
		shared.WriteProblem(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.loggerFor(r).Error("write getSecretAttributes response", "err", writeErr)
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
func ensureSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
