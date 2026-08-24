package cryptography

import (
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Connector event names emitted to connector_events_total{event,outcome}.
const (
	eventTokenAttributes        = "list_token_attributes"
	eventTokenProfileAttributes = "list_token_profile_attributes"
	eventCreateKeyAttributes    = "list_create_key_attributes"
	eventEncryptAttributes      = "list_encrypt_attributes"
	eventDecryptAttributes      = "list_decrypt_attributes"
	eventSignAttributes         = "list_sign_attributes"
	eventVerifyAttributes       = "list_verify_attributes"
	eventRandomDataAttributes   = "list_random_data_attributes"

	eventTokenStatus           = "token_status"
	eventTokenProfileKeyUsages = "token_profile_key_usages"
	eventKeyRequestTypes       = "key_request_types"
	eventCreateKey             = "create_key"
	eventDestroyKey            = "destroy_key"
	eventSignData              = "sign_data"
	eventEncryptData           = "encrypt_data"
	eventDecryptData           = "decrypt_data"
	eventVerifyData            = "verify_data"
	eventRandomData            = "random_data"

	eventCreateKeyStatus  = "create_key_status"
	eventCancelCreateKey  = "cancel_create_key"
	eventDestroyKeyStatus = "destroy_key_status"
	eventCancelDestroyKey = "cancel_destroy_key"
	eventSignDataStatus   = "sign_data_status"
	eventCancelSignData   = "cancel_sign_data"
)

// rejectRequest is the shared tail of every request-side validation guard
// added in validate.go: emit the outcome event and render the problem
// response, then the caller returns. Factored out of the repeated
// three-line EmitEvent/RenderError/return body so each guard's call site is
// one line. Not used by the response-shape guards below (see their own
// comment on why they must not emit).
func (h *Handler) rejectRequest(w http.ResponseWriter, r *http.Request, event string, err error) {
	shared.EmitEvent(r.Context(), event, err)
	shared.RenderError(w, r, err)
}

// --- Attribute endpoints -----------------------------------------------------

// Attribute endpoints with no registered sub-provider respond 200 with an
// empty array — the SDK-wide convention: missing optional attribute providers
// must not break callers that enumerate them.

func (h *Handler) listTokenAttributes(w http.ResponseWriter, r *http.Request) {
	var out []mdl.BaseAttributeDto
	var err error
	if h.tokenAttrs != nil {
		out, err = h.tokenAttrs.TokenAttributes(r.Context())
	}
	shared.EmitEvent(r.Context(), eventTokenAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listTokenAttributes response", "err", writeErr)
	}
}

func (h *Handler) listTokenProfileAttributes(w http.ResponseWriter, r *http.Request) {
	var in mdl.TokenScopedRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventTokenProfileAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.tokenProfileAttrs != nil {
		out, err = h.tokenProfileAttrs.TokenProfileAttributes(r.Context(), &in)
	}
	shared.EmitEvent(r.Context(), eventTokenProfileAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listTokenProfileAttributes response", "err", writeErr)
	}
}

func (h *Handler) listCreateKeyAttributes(w http.ResponseWriter, r *http.Request) {
	var in mdl.CreateKeyAttributesRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCreateKeyAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := validateKeyUsages(in.KeyUsages); err != nil {
		h.rejectRequest(w, r, eventCreateKeyAttributes, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.createKeyAttrs != nil {
		out, err = h.createKeyAttrs.CreateKeyAttributes(r.Context(), &in)
	}
	shared.EmitEvent(r.Context(), eventCreateKeyAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listCreateKeyAttributes response", "err", writeErr)
	}
}

func (h *Handler) listEncryptAttributes(w http.ResponseWriter, r *http.Request) {
	var in mdl.KeyScopedRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventEncryptAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := firstError(
		validateKeyUsages(in.KeyUsages),
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
	); err != nil {
		h.rejectRequest(w, r, eventEncryptAttributes, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.encryptAttrs != nil {
		out, err = h.encryptAttrs.EncryptAttributes(r.Context(), &in)
	}
	shared.EmitEvent(r.Context(), eventEncryptAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listEncryptAttributes response", "err", writeErr)
	}
}

func (h *Handler) listDecryptAttributes(w http.ResponseWriter, r *http.Request) {
	var in mdl.KeyScopedRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventDecryptAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := firstError(
		validateKeyUsages(in.KeyUsages),
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
	); err != nil {
		h.rejectRequest(w, r, eventDecryptAttributes, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.decryptAttrs != nil {
		out, err = h.decryptAttrs.DecryptAttributes(r.Context(), &in)
	}
	shared.EmitEvent(r.Context(), eventDecryptAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listDecryptAttributes response", "err", writeErr)
	}
}

func (h *Handler) listSignAttributes(w http.ResponseWriter, r *http.Request) {
	var in mdl.KeyScopedRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventSignAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := firstError(
		validateKeyUsages(in.KeyUsages),
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
	); err != nil {
		h.rejectRequest(w, r, eventSignAttributes, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.signAttrs != nil {
		out, err = h.signAttrs.SignAttributes(r.Context(), &in)
	}
	shared.EmitEvent(r.Context(), eventSignAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listSignAttributes response", "err", writeErr)
	}
}

func (h *Handler) listVerifyAttributes(w http.ResponseWriter, r *http.Request) {
	var in mdl.KeyScopedRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventVerifyAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := firstError(
		validateKeyUsages(in.KeyUsages),
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
	); err != nil {
		h.rejectRequest(w, r, eventVerifyAttributes, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.verifyAttrs != nil {
		out, err = h.verifyAttrs.VerifyAttributes(r.Context(), &in)
	}
	shared.EmitEvent(r.Context(), eventVerifyAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listVerifyAttributes response", "err", writeErr)
	}
}

func (h *Handler) listRandomDataAttributes(w http.ResponseWriter, r *http.Request) {
	var in mdl.TokenProfileScopedRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventRandomDataAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := validateKeyUsages(in.KeyUsages); err != nil {
		h.rejectRequest(w, r, eventRandomDataAttributes, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.randomAttrs != nil {
		out, err = h.randomAttrs.RandomDataAttributes(r.Context(), &in)
	}
	shared.EmitEvent(r.Context(), eventRandomDataAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listRandomDataAttributes response", "err", writeErr)
	}
}

// --- Token instances ---------------------------------------------------------

func (h *Handler) tokenStatus(w http.ResponseWriter, r *http.Request) {
	var in mdl.TokenScopedRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventTokenStatus, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.TokenStatus(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventTokenStatus, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write tokenStatus response", "err", writeErr)
	}
}

func (h *Handler) tokenProfileKeyUsages(w http.ResponseWriter, r *http.Request) {
	var in mdl.TokenScopedRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventTokenProfileKeyUsages, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.TokenProfileKeyUsages(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventTokenProfileKeyUsages, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write tokenProfileKeyUsages response", "err", writeErr)
	}
}

func (h *Handler) keyRequestTypes(w http.ResponseWriter, r *http.Request) {
	var in mdl.TokenProfileScopedRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventKeyRequestTypes, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := validateKeyUsages(in.KeyUsages); err != nil {
		h.rejectRequest(w, r, eventKeyRequestTypes, err)
		return
	}
	out, err := h.provider.KeyRequestTypes(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventKeyRequestTypes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write keyRequestTypes response", "err", writeErr)
	}
}

// --- Key management and signing: caller-selected execution mode -------------
//
// Each of these three routes accepts a request whose executionMode field is
// caller-selected. The provider does not choose the mode; it reports, via
// accepted, whether the operation it was asked for completed inline or was
// taken up for asynchronous execution. accepted == false renders 200 with the
// completed result; accepted == true renders 202 with the same response type
// carrying the async tracking handle.
//
// The handler does not infer the mode from the request, but it does hold the
// provider to it: a synchronously requested operation reported as accepted is
// a provider-contract violation and renders 500, never a 202 the caller never
// asked to poll (see validateModeNotSwitched, which also documents why the
// converse is allowed).

// 409 ErrKeyCreationConflict when keyCreationId is reused non-equivalently.
func (h *Handler) createKey(w http.ResponseWriter, r *http.Request) {
	var in mdl.CreateKeyRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCreateKey, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := firstError(
		validateExecutionMode(in.ExecutionMode),
		validateKeyCreationId(in.KeyCreationId),
		validateKeyUsages(in.KeyUsages),
	); err != nil {
		h.rejectRequest(w, r, eventCreateKey, err)
		return
	}
	out, accepted, err := h.provider.CreateKey(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventCreateKey, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	// The EmitEvent above already reported outcome "ok", so emitting here
	// would double-count this request as both ok and error. The error-level
	// log is the observability signal for a provider bug.
	if err := firstError(
		validateModeNotSwitched(in.ExecutionMode, accepted, "key creation"),
		validateKeyCreationShape(accepted, out),
		validateRequestedKeyRequestType(keyCreationRequestType(out), in.KeyRequestType),
	); err != nil {
		h.LoggerFor(r).Error("createKey response shape", "err", err)
		shared.RenderError(w, r, err)
		return
	}
	status := http.StatusOK
	if accepted {
		status = http.StatusAccepted
	}
	if writeErr := shared.WriteJSON(w, status, out); writeErr != nil {
		h.LoggerFor(r).Error("write createKey response", "err", writeErr)
	}
}

func (h *Handler) destroyKey(w http.ResponseWriter, r *http.Request) {
	var in mdl.DestroyKeyRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventDestroyKey, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := firstError(
		validateExecutionMode(in.ExecutionMode),
		validateKeyUsages(in.KeyUsages),
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
	); err != nil {
		h.rejectRequest(w, r, eventDestroyKey, err)
		return
	}
	out, accepted, err := h.provider.DestroyKey(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventDestroyKey, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	// No EmitEvent: see createKey.
	if err := firstError(
		validateModeNotSwitched(in.ExecutionMode, accepted, "key destruction"),
		validateDestroyShape(accepted, len(out.OperationMeta) > 0),
	); err != nil {
		h.LoggerFor(r).Error("destroyKey response shape", "err", err)
		shared.RenderError(w, r, err)
		return
	}
	status := http.StatusOK
	if accepted {
		status = http.StatusAccepted
	}
	if writeErr := shared.WriteJSON(w, status, out); writeErr != nil {
		h.LoggerFor(r).Error("write destroyKey response", "err", writeErr)
	}
}

func (h *Handler) signData(w http.ResponseWriter, r *http.Request) {
	var in mdl.SignDataRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventSignData, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := firstError(
		validateExecutionMode(in.ExecutionMode),
		validateKeyUsages(in.KeyUsages),
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
		validateNonEmptyBatch(len(in.Data), "data"),
		validateUniqueIdentifiers(signatureDataIdentifiers(in.Data), "data"),
		validateBatchItems(signatureDataIdentifiers(in.Data), signatureDataPayloads(in.Data), "data"),
	); err != nil {
		h.rejectRequest(w, r, eventSignData, err)
		return
	}
	out, accepted, err := h.provider.SignData(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventSignData, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	// No EmitEvent: see createKey.
	if err := firstError(
		validateModeNotSwitched(in.ExecutionMode, accepted, "sign data"),
		validateExecutionShape(accepted, len(out.OperationMeta) > 0, signHasPayload(out), "sign data"),
	); err != nil {
		h.LoggerFor(r).Error("signData response shape", "err", err)
		shared.RenderError(w, r, err)
		return
	}
	// Core correlates identifiers on a synchronous signing response only; an
	// accepted batch carries no signatures to correlate.
	if !accepted {
		if err := validateResponseBatch(
			signatureDataIdentifiers(in.Data),
			signatureDataIdentifiers(out.Signatures),
			signatureDataPayloads(out.Signatures),
			"sign data",
		); err != nil {
			h.LoggerFor(r).Error("signData response shape", "err", err)
			shared.RenderError(w, r, err)
			return
		}
	}
	status := http.StatusOK
	if accepted {
		status = http.StatusAccepted
	}
	if writeErr := shared.WriteJSON(w, status, out); writeErr != nil {
		h.LoggerFor(r).Error("write signData response", "err", writeErr)
	}
}

// --- Always-synchronous cryptographic operations -----------------------------

func (h *Handler) encryptData(w http.ResponseWriter, r *http.Request) {
	var in mdl.CipherDataRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventEncryptData, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := firstError(
		validateKeyUsages(in.KeyUsages),
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
		validateNonEmptyBatch(len(in.CipherData), "cipherData"),
		validateUniqueIdentifiers(cipherDataIdentifiers(in.CipherData), "cipherData"),
		validateBatchItems(cipherDataIdentifiers(in.CipherData), cipherDataPayloads(in.CipherData), "cipherData"),
	); err != nil {
		h.rejectRequest(w, r, eventEncryptData, err)
		return
	}
	out, err := h.provider.EncryptData(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventEncryptData, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	// No EmitEvent: see createKey.
	if err := validateResponseBatch(
		cipherDataIdentifiers(in.CipherData),
		cipherDataIdentifiers(out.EncryptedData),
		cipherDataPayloads(out.EncryptedData),
		"encrypt data",
	); err != nil {
		h.LoggerFor(r).Error("encryptData response shape", "err", err)
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write encryptData response", "err", writeErr)
	}
}

func (h *Handler) decryptData(w http.ResponseWriter, r *http.Request) {
	var in mdl.CipherDataRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventDecryptData, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := firstError(
		validateKeyUsages(in.KeyUsages),
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
		validateNonEmptyBatch(len(in.CipherData), "cipherData"),
		validateUniqueIdentifiers(cipherDataIdentifiers(in.CipherData), "cipherData"),
		validateBatchItems(cipherDataIdentifiers(in.CipherData), cipherDataPayloads(in.CipherData), "cipherData"),
	); err != nil {
		h.rejectRequest(w, r, eventDecryptData, err)
		return
	}
	out, err := h.provider.DecryptData(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventDecryptData, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	// No EmitEvent: see createKey.
	if err := validateResponseBatch(
		cipherDataIdentifiers(in.CipherData),
		cipherDataIdentifiers(out.DecryptedData),
		cipherDataPayloads(out.DecryptedData),
		"decrypt data",
	); err != nil {
		h.LoggerFor(r).Error("decryptData response shape", "err", err)
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write decryptData response", "err", writeErr)
	}
}

func (h *Handler) verifyData(w http.ResponseWriter, r *http.Request) {
	var in mdl.VerifyDataRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventVerifyData, err)
		shared.RenderError(w, r, err)
		return
	}
	dataIDs := signatureDataIdentifiers(in.Data)
	signatureIDs := signatureDataIdentifiers(in.Signatures)
	// Order is load-bearing: validateIdentifiersMatch is a same-size-plus-
	// subset test, which is only a genuine set comparison once both lists
	// are already known to be duplicate-free. Listed after the two
	// uniqueness checks, its verdict is only ever reported when both passed;
	// ahead of them, want=[a,b] got=[a,a] would be reported as matching
	// (same size, every got element found in want).
	if err := firstError(
		validateKeyUsages(in.KeyUsages),
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
		validateNonEmptyBatch(len(in.Data), "data"),
		validateNonEmptyBatch(len(in.Signatures), "signatures"),
		validateUniqueIdentifiers(dataIDs, "data"),
		validateUniqueIdentifiers(signatureIDs, "signatures"),
		validateIdentifiersMatch(dataIDs, signatureIDs, "signatures"),
		validateBatchItems(dataIDs, signatureDataPayloads(in.Data), "data"),
		validateBatchItems(signatureIDs, signatureDataPayloads(in.Signatures), "signatures"),
	); err != nil {
		h.rejectRequest(w, r, eventVerifyData, err)
		return
	}
	out, err := h.provider.VerifyData(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventVerifyData, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	// No EmitEvent: see createKey.
	if err := validateResponseIdentifiers(
		dataIDs,
		verificationIdentifiers(out.Verifications),
		"verify data",
	); err != nil {
		h.LoggerFor(r).Error("verifyData response shape", "err", err)
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write verifyData response", "err", writeErr)
	}
}

func (h *Handler) randomData(w http.ResponseWriter, r *http.Request) {
	var in mdl.RandomDataRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventRandomData, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := firstError(
		validateKeyUsages(in.KeyUsages),
		validateRandomDataLength(in.Length),
	); err != nil {
		h.rejectRequest(w, r, eventRandomData, err)
		return
	}
	out, err := h.provider.RandomData(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventRandomData, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	// No EmitEvent: see createKey.
	if err := validateRandomDataPayload(out.Data, in.Length); err != nil {
		h.LoggerFor(r).Error("randomData response shape", "err", err)
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write randomData response", "err", writeErr)
	}
}

// --- Async key status and cancellation ---------------------------------------
//
// Mounted only when an AsyncKeyProvider is registered (see WithAsyncKeys);
// h.asyncKeys is dereferenced without a nil check because these routes are
// not reachable otherwise.

// 200 with the creation status | 404 ErrOperationNotTracked.
func (h *Handler) createKeyStatus(w http.ResponseWriter, r *http.Request) {
	var in mdl.OperationTrackingRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCreateKeyStatus, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := validateNonEmptyBatch(len(in.OperationMeta), "operationMeta"); err != nil {
		h.rejectRequest(w, r, eventCreateKeyStatus, err)
		return
	}
	out, err := h.asyncKeys.CreateKeyStatus(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventCreateKeyStatus, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	// No EmitEvent: see createKey.
	if err := validateKeyCreationStatusShape(out); err != nil {
		h.LoggerFor(r).Error("createKeyStatus response shape", "err", err)
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write createKeyStatus response", "err", writeErr)
	}
}

// 204 aborted | 404 ErrOperationNotTracked | 422 ErrCancelPastPointOfNoReturn (terminal or past the point of no return).
func (h *Handler) cancelCreateKey(w http.ResponseWriter, r *http.Request) {
	var in mdl.OperationTrackingRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCancelCreateKey, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := validateNonEmptyBatch(len(in.OperationMeta), "operationMeta"); err != nil {
		h.rejectRequest(w, r, eventCancelCreateKey, err)
		return
	}
	if err := h.asyncKeys.CancelCreateKey(r.Context(), &in); err != nil {
		shared.EmitEvent(r.Context(), eventCancelCreateKey, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventCancelCreateKey, nil)
	w.WriteHeader(http.StatusNoContent)
}

// 200 with the destruction status | 404 ErrOperationNotTracked.
func (h *Handler) destroyKeyStatus(w http.ResponseWriter, r *http.Request) {
	var in mdl.OperationTrackingRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventDestroyKeyStatus, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := validateNonEmptyBatch(len(in.OperationMeta), "operationMeta"); err != nil {
		h.rejectRequest(w, r, eventDestroyKeyStatus, err)
		return
	}
	out, err := h.asyncKeys.DestroyKeyStatus(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventDestroyKeyStatus, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	// KeyDestructionStatusResponseV2Dto carries status and reason only, so the
	// reason rule alone applies. No EmitEvent: see createKey.
	if err := validateStatusReason(out.Status, out.Reason); err != nil {
		h.LoggerFor(r).Error("destroyKeyStatus response shape", "err", err)
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write destroyKeyStatus response", "err", writeErr)
	}
}

// 204 aborted | 404 ErrOperationNotTracked | 422 ErrCancelPastPointOfNoReturn (terminal or past the point of no return).
func (h *Handler) cancelDestroyKey(w http.ResponseWriter, r *http.Request) {
	var in mdl.OperationTrackingRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCancelDestroyKey, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := validateNonEmptyBatch(len(in.OperationMeta), "operationMeta"); err != nil {
		h.rejectRequest(w, r, eventCancelDestroyKey, err)
		return
	}
	if err := h.asyncKeys.CancelDestroyKey(r.Context(), &in); err != nil {
		shared.EmitEvent(r.Context(), eventCancelDestroyKey, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventCancelDestroyKey, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Async signing status and cancellation -----------------------------------
//
// Mounted only when an AsyncSignProvider is registered (see WithAsyncSign);
// h.asyncSign is dereferenced without a nil check because these routes are
// not reachable otherwise.

// 200 with the signing batch status | 404 ErrOperationNotTracked.
func (h *Handler) signDataStatus(w http.ResponseWriter, r *http.Request) {
	var in mdl.OperationTrackingRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventSignDataStatus, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := validateNonEmptyBatch(len(in.OperationMeta), "operationMeta"); err != nil {
		h.rejectRequest(w, r, eventSignDataStatus, err)
		return
	}
	out, err := h.asyncSign.SignDataStatus(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventSignDataStatus, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if out == nil {
		shared.RenderError(w, r, ErrNilResponse)
		return
	}
	// The spec sets minItems: 1 on items; an empty array skips the per-item
	// loop below entirely rather than tripping any of its checks, so it must
	// be rejected explicitly before the loop runs.
	if len(out.Items) == 0 {
		err := errResponseShape("items must not be empty")
		h.LoggerFor(r).Error("signDataStatus response shape", "err", err)
		shared.RenderError(w, r, err)
		return
	}
	// No EmitEvent: see createKey.
	if err := validateResponseItemIdentifiers(signatureResultIdentifiers(out.Items), "sign status"); err != nil {
		h.LoggerFor(r).Error("signDataStatus response shape", "err", err)
		shared.RenderError(w, r, err)
		return
	}
	// SignOperationStatusResponseV2Dto has no top-level status: each batch
	// item carries its own, so the shape rule is checked once per item.
	for _, item := range out.Items {
		if err := validateSignatureResultItem(item); err != nil {
			h.LoggerFor(r).Error("signDataStatus response shape", "err", err)
			shared.RenderError(w, r, err)
			return
		}
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write signDataStatus response", "err", writeErr)
	}
}

// 204 aborted | 404 ErrOperationNotTracked | 422 ErrCancelPastPointOfNoReturn (terminal or past the point of no return).
func (h *Handler) cancelSignData(w http.ResponseWriter, r *http.Request) {
	var in mdl.OperationTrackingRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCancelSignData, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := validateNonEmptyBatch(len(in.OperationMeta), "operationMeta"); err != nil {
		h.rejectRequest(w, r, eventCancelSignData, err)
		return
	}
	if err := h.asyncSign.CancelSignData(r.Context(), &in); err != nil {
		shared.EmitEvent(r.Context(), eventCancelSignData, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventCancelSignData, nil)
	w.WriteHeader(http.StatusNoContent)
}
