package cryptography

import (
	"context"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// Connector event names emitted to connector_events_total{event,outcome}.
const (
	eventListTokenInstances              = "list_token_instances"
	eventCreateTokenInstance             = "create_token_instance"
	eventGetTokenInstance                = "get_token_instance"
	eventUpdateTokenInstance             = "update_token_instance"
	eventRemoveTokenInstance             = "remove_token_instance"
	eventGetTokenInstanceStatus          = "get_token_instance_status"
	eventActivateTokenInstance           = "activate_token_instance"
	eventDeactivateTokenInstance         = "deactivate_token_instance"
	eventListKeys                        = "list_keys"
	eventGetKey                          = "get_key"
	eventDestroyKey                      = "destroy_key"
	eventCreateSecretKey                 = "create_secret_key"
	eventCreateKeyPair                   = "create_key_pair"
	eventRandomData                      = "random_data"
	eventSignData                        = "sign_data"
	eventVerifyData                      = "verify_data"
	eventEncryptData                     = "encrypt_data"
	eventDecryptData                     = "decrypt_data"
	eventListKindAttributes              = "list_kind_attributes"
	eventValidateKindAttributes          = "validate_kind_attributes"
	eventListTokenProfileAttributes      = "list_token_profile_attributes"
	eventValidateTokenProfileAttributes  = "validate_token_profile_attributes"
	eventListTokenActivationAttributes   = "list_token_activation_attributes"
	eventValidateTokenActivationAttrs    = "validate_token_activation_attributes"
	eventListCreateSecretKeyAttributes   = "list_create_secret_key_attributes"
	eventValidateCreateSecretKeyAttrs    = "validate_create_secret_key_attributes"
	eventListCreateKeyPairAttributes     = "list_create_key_pair_attributes"
	eventValidateCreateKeyPairAttributes = "validate_create_key_pair_attributes"
	eventListRandomDataAttributes        = "list_random_data_attributes"
	eventValidateRandomDataAttributes    = "validate_random_data_attributes"
)

// --- Token instance management routes ------------------------------------

func (h *Handler) listTokenInstances(w http.ResponseWriter, r *http.Request) {
	out, err := h.provider.ListTokenInstances(r.Context())
	shared.EmitEvent(r.Context(), eventListTokenInstances, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listTokenInstances response", "err", writeErr)
	}
}

func (h *Handler) createTokenInstance(w http.ResponseWriter, r *http.Request) {
	var in mdl.TokenInstanceRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCreateTokenInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.CreateTokenInstance(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventCreateTokenInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write createTokenInstance response", "err", writeErr)
	}
}

func (h *Handler) getTokenInstance(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	out, err := h.provider.GetTokenInstance(r.Context(), uuid)
	shared.EmitEvent(r.Context(), eventGetTokenInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getTokenInstance response", "err", writeErr)
	}
}

func (h *Handler) updateTokenInstance(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	var in mdl.TokenInstanceRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventUpdateTokenInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.UpdateTokenInstance(r.Context(), uuid, &in)
	shared.EmitEvent(r.Context(), eventUpdateTokenInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write updateTokenInstance response", "err", writeErr)
	}
}

func (h *Handler) removeTokenInstance(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	if err := h.provider.RemoveTokenInstance(r.Context(), uuid); err != nil {
		shared.EmitEvent(r.Context(), eventRemoveTokenInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventRemoveTokenInstance, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getTokenInstanceStatus(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	out, err := h.provider.GetTokenInstanceStatus(r.Context(), uuid)
	shared.EmitEvent(r.Context(), eventGetTokenInstanceStatus, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getTokenInstanceStatus response", "err", writeErr)
	}
}

func (h *Handler) activateTokenInstance(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventActivateTokenInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.ActivateTokenInstance(r.Context(), uuid, attrs); err != nil {
		shared.EmitEvent(r.Context(), eventActivateTokenInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventActivateTokenInstance, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) deactivateTokenInstance(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	if err := h.provider.DeactivateTokenInstance(r.Context(), uuid); err != nil {
		shared.EmitEvent(r.Context(), eventDeactivateTokenInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventDeactivateTokenInstance, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Key management routes ----------------------------------------------

func (h *Handler) listKeys(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	out, err := h.provider.ListKeys(r.Context(), uuid)
	shared.EmitEvent(r.Context(), eventListKeys, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listKeys response", "err", writeErr)
	}
}

func (h *Handler) getKey(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	keyUuid, ok := shared.RequirePathValue(w, r, "keyUuid")
	if !ok {
		return
	}
	out, err := h.provider.GetKey(r.Context(), uuid, keyUuid)
	shared.EmitEvent(r.Context(), eventGetKey, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getKey response", "err", writeErr)
	}
}

func (h *Handler) destroyKey(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	keyUuid, ok := shared.RequirePathValue(w, r, "keyUuid")
	if !ok {
		return
	}
	if err := h.provider.DestroyKey(r.Context(), uuid, keyUuid); err != nil {
		shared.EmitEvent(r.Context(), eventDestroyKey, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventDestroyKey, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) createSecretKey(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	var in mdl.CreateKeyRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCreateSecretKey, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.CreateSecretKey(r.Context(), uuid, &in)
	shared.EmitEvent(r.Context(), eventCreateSecretKey, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write createSecretKey response", "err", writeErr)
	}
}

func (h *Handler) createKeyPair(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	var in mdl.CreateKeyRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCreateKeyPair, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.CreateKeyPair(r.Context(), uuid, &in)
	shared.EmitEvent(r.Context(), eventCreateKeyPair, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write createKeyPair response", "err", writeErr)
	}
}

func (h *Handler) randomData(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	var in mdl.RandomDataRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventRandomData, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.RandomData(r.Context(), uuid, &in)
	shared.EmitEvent(r.Context(), eventRandomData, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write randomData response", "err", writeErr)
	}
}

// --- Crypto operations --------------------------------------------------

func (h *Handler) signData(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	keyUuid, ok := shared.RequirePathValue(w, r, "keyUuid")
	if !ok {
		return
	}
	var in mdl.SignDataRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventSignData, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.SignData(r.Context(), uuid, keyUuid, &in)
	shared.EmitEvent(r.Context(), eventSignData, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write signData response", "err", writeErr)
	}
}

func (h *Handler) verifyData(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	keyUuid, ok := shared.RequirePathValue(w, r, "keyUuid")
	if !ok {
		return
	}
	var in mdl.VerifyDataRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventVerifyData, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.VerifyData(r.Context(), uuid, keyUuid, &in)
	shared.EmitEvent(r.Context(), eventVerifyData, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write verifyData response", "err", writeErr)
	}
}

func (h *Handler) encryptData(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	keyUuid, ok := shared.RequirePathValue(w, r, "keyUuid")
	if !ok {
		return
	}
	var in mdl.CipherDataRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventEncryptData, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.EncryptData(r.Context(), uuid, keyUuid, &in)
	shared.EmitEvent(r.Context(), eventEncryptData, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write encryptData response", "err", writeErr)
	}
}

func (h *Handler) decryptData(w http.ResponseWriter, r *http.Request) {
	uuid, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	keyUuid, ok := shared.RequirePathValue(w, r, "keyUuid")
	if !ok {
		return
	}
	var in mdl.CipherDataRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventDecryptData, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.DecryptData(r.Context(), uuid, keyUuid, &in)
	shared.EmitEvent(r.Context(), eventDecryptData, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write decryptData response", "err", writeErr)
	}
}

// --- Generic kind attributes (per-literal-kind closure) -----------------

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

// --- Per-instance attribute routes (helpers below avoid repetition) -----

// instanceAttrList handles GET .../tokens/{uuid}/<resource>/attributes.
// When the sub-provider is nil it returns 200 with [] per the SDK convention.

// instanceAttrValidate handles POST .../tokens/{uuid}/<resource>/attributes/validate.

// Token profile attributes.
func (h *Handler) listTokenProfileAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string) ([]mdl.BaseAttributeDto, error)
	if h.tokenProfileAttrs != nil {
		fn = h.tokenProfileAttrs.TokenProfileAttributes
	}
	handlerbase.ListInstanceAttributes(&h.Config, eventListTokenProfileAttributes, "uuid", fn)(w, r)
}
func (h *Handler) validateTokenProfileAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string, []mdl.RequestAttribute) ([]string, error)
	if h.tokenProfileAttrs != nil {
		fn = h.tokenProfileAttrs.ValidateTokenProfileAttributes
	}
	handlerbase.ValidateInstanceAttributes(&h.Config, eventValidateTokenProfileAttributes, "uuid", http.StatusNoContent, fn)(w, r)
}

// Token activation attributes.
func (h *Handler) listTokenActivationAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string) ([]mdl.BaseAttributeDto, error)
	if h.tokenActivationAttrs != nil {
		fn = h.tokenActivationAttrs.TokenActivationAttributes
	}
	handlerbase.ListInstanceAttributes(&h.Config, eventListTokenActivationAttributes, "uuid", fn)(w, r)
}
func (h *Handler) validateTokenActivationAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string, []mdl.RequestAttribute) ([]string, error)
	if h.tokenActivationAttrs != nil {
		fn = h.tokenActivationAttrs.ValidateTokenActivationAttributes
	}
	handlerbase.ValidateInstanceAttributes(&h.Config, eventValidateTokenActivationAttrs, "uuid", http.StatusNoContent, fn)(w, r)
}

// Create secret key attributes.
func (h *Handler) listCreateSecretKeyAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string) ([]mdl.BaseAttributeDto, error)
	if h.createSecretKeyAttrs != nil {
		fn = h.createSecretKeyAttrs.CreateSecretKeyAttributes
	}
	handlerbase.ListInstanceAttributes(&h.Config, eventListCreateSecretKeyAttributes, "uuid", fn)(w, r)
}
func (h *Handler) validateCreateSecretKeyAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string, []mdl.RequestAttribute) ([]string, error)
	if h.createSecretKeyAttrs != nil {
		fn = h.createSecretKeyAttrs.ValidateCreateSecretKeyAttributes
	}
	handlerbase.ValidateInstanceAttributes(&h.Config, eventValidateCreateSecretKeyAttrs, "uuid", http.StatusNoContent, fn)(w, r)
}

// Create key pair attributes.
func (h *Handler) listCreateKeyPairAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string) ([]mdl.BaseAttributeDto, error)
	if h.createKeyPairAttrs != nil {
		fn = h.createKeyPairAttrs.CreateKeyPairAttributes
	}
	handlerbase.ListInstanceAttributes(&h.Config, eventListCreateKeyPairAttributes, "uuid", fn)(w, r)
}
func (h *Handler) validateCreateKeyPairAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string, []mdl.RequestAttribute) ([]string, error)
	if h.createKeyPairAttrs != nil {
		fn = h.createKeyPairAttrs.ValidateCreateKeyPairAttributes
	}
	handlerbase.ValidateInstanceAttributes(&h.Config, eventValidateCreateKeyPairAttributes, "uuid", http.StatusNoContent, fn)(w, r)
}

// Random data attributes.
func (h *Handler) listRandomDataAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string) ([]mdl.BaseAttributeDto, error)
	if h.randomDataAttrs != nil {
		fn = h.randomDataAttrs.RandomDataAttributes
	}
	handlerbase.ListInstanceAttributes(&h.Config, eventListRandomDataAttributes, "uuid", fn)(w, r)
}
func (h *Handler) validateRandomDataAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string, []mdl.RequestAttribute) ([]string, error)
	if h.randomDataAttrs != nil {
		fn = h.randomDataAttrs.ValidateRandomDataAttributes
	}
	handlerbase.ValidateInstanceAttributes(&h.Config, eventValidateRandomDataAttributes, "uuid", http.StatusNoContent, fn)(w, r)
}
