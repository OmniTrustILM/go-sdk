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

	eventImportableKeyTypes  = "list_importable_key_types"
	eventImportKeyAttributes = "list_import_key_attributes"
	eventImportKey           = "import_key"
	eventImportKeyResult     = "import_key_result"
	eventImportKeyStatus     = "import_key_status"
	eventCancelImportKey     = "cancel_import_key"

	eventExportableKeyTypes  = "list_exportable_key_types"
	eventExportKeyAttributes = "list_export_key_attributes"
	eventExportKey           = "export_key"
)

// errKeyImportNotSupported is the import routes' answer without WithKeyImport,
// the body the contract declares for "endpoint not found or not implemented".
var errKeyImportNotSupported = shared.NotFound("OPERATION_NOT_SUPPORTED", "key import is not implemented by this connector")

// errKeyExportNotSupported is the export routes' answer without WithKeyExport.
var errKeyExportNotSupported = shared.NotFound("OPERATION_NOT_SUPPORTED", "key export is not implemented by this connector")

// rejectRequest emits the outcome event and renders the problem response for a
// failed request guard.
func (h *Handler) rejectRequest(w http.ResponseWriter, r *http.Request, event string, err error) {
	shared.EmitEvent(r.Context(), event, err)
	shared.RenderError(w, r, err)
}

// Every payload handler validates the response before emitting its event, so a
// shape violation is recorded as outcome "error". shared.RenderError logs every
// 5xx with detail and path, so handlers add no log line of their own.

// --- Attribute endpoints -----------------------------------------------------

// Attribute endpoints with no registered sub-provider respond 200 with an empty
// array once the request validates, the SDK-wide convention for optional
// attribute providers.

func (h *Handler) listTokenAttributes(w http.ResponseWriter, r *http.Request) {
	var out []mdl.BaseAttributeDto
	var err error
	if h.tokenAttrs != nil {
		out, err = h.tokenAttrs.TokenAttributes(r.Context())
	}
	if err == nil {
		err = validateEncodable(out)
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
	if err == nil {
		err = validateEncodable(out)
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
	var out []mdl.BaseAttributeDto
	var err error
	if h.createKeyAttrs != nil {
		out, err = h.createKeyAttrs.CreateKeyAttributes(r.Context(), &in)
	}
	if err == nil {
		err = validateEncodable(out)
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
	if err := validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"); err != nil {
		h.rejectRequest(w, r, eventEncryptAttributes, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.encryptAttrs != nil {
		out, err = h.encryptAttrs.EncryptAttributes(r.Context(), &in)
	}
	if err == nil {
		err = validateEncodable(out)
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
	if err := validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"); err != nil {
		h.rejectRequest(w, r, eventDecryptAttributes, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.decryptAttrs != nil {
		out, err = h.decryptAttrs.DecryptAttributes(r.Context(), &in)
	}
	if err == nil {
		err = validateEncodable(out)
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
	if err := validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"); err != nil {
		h.rejectRequest(w, r, eventSignAttributes, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.signAttrs != nil {
		out, err = h.signAttrs.SignAttributes(r.Context(), &in)
	}
	if err == nil {
		err = validateEncodable(out)
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
	if err := validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"); err != nil {
		h.rejectRequest(w, r, eventVerifyAttributes, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.verifyAttrs != nil {
		out, err = h.verifyAttrs.VerifyAttributes(r.Context(), &in)
	}
	if err == nil {
		err = validateEncodable(out)
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
	var out []mdl.BaseAttributeDto
	var err error
	if h.randomAttrs != nil {
		out, err = h.randomAttrs.RandomDataAttributes(r.Context(), &in)
	}
	if err == nil {
		err = validateEncodable(out)
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
	if err == nil {
		err = validateResponse(out, validateTokenStatus)
	}
	shared.EmitEvent(r.Context(), eventTokenStatus, err)
	if err != nil {
		shared.RenderError(w, r, err)
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
	if err == nil {
		err = validateKnownEnums(out, "key usages")
	}
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
	out, err := h.provider.KeyRequestTypes(r.Context(), &in)
	if err == nil {
		err = validateKnownEnums(out, "key request types")
	}
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
// The provider reports via accepted whether the operation completed inline
// (200) or was taken up asynchronously (202). An operation reported in the
// mode the caller did not select renders 500 in both directions (see
// validateModeNotSwitched).

// executionStatus maps the provider's accepted flag to the wire status.
func executionStatus(accepted bool) int {
	if accepted {
		return http.StatusAccepted
	}
	return http.StatusOK
}

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
		validateIdempotencyKey(in.KeyCreationId, "keyCreationId"),
	); err != nil {
		h.rejectRequest(w, r, eventCreateKey, err)
		return
	}
	out, accepted, err := h.provider.CreateKey(r.Context(), &in)
	if err == nil {
		err = validateResponse(out, func(out *mdl.KeyCreationResponse) error {
			return firstError(
				validateModeNotSwitched(in.ExecutionMode, accepted, "key creation"),
				validateKeyCreationShape(accepted, out),
				validateRequestedKeyRequestType(keyCreationRequestType(out), in.KeyRequestType),
			)
		})
	}
	shared.EmitEvent(r.Context(), eventCreateKey, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, executionStatus(accepted), out); writeErr != nil {
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
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
	); err != nil {
		h.rejectRequest(w, r, eventDestroyKey, err)
		return
	}
	out, accepted, err := h.provider.DestroyKey(r.Context(), &in)
	if err == nil {
		err = validateResponse(out, func(out *mdl.KeyOperationResponseV2Dto) error {
			return firstError(
				validateModeNotSwitched(in.ExecutionMode, accepted, "key destruction"),
				validateMetadataElements(out.OperationMeta, "operationMeta"),
				validateDestroyShape(accepted, len(out.OperationMeta) > 0),
			)
		})
	}
	shared.EmitEvent(r.Context(), eventDestroyKey, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, executionStatus(accepted), out); writeErr != nil {
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
	dataIDs := signatureDataIdentifiers(in.Data)
	if err := firstError(
		validateExecutionMode(in.ExecutionMode),
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
		validateNonEmptyBatch(len(in.Data), "data"),
		validateUniqueIdentifiers(dataIDs, "data"),
		validateBatchItems(dataIDs, signatureDataPayloads(in.Data), "data"),
	); err != nil {
		h.rejectRequest(w, r, eventSignData, err)
		return
	}
	out, accepted, err := h.provider.SignData(r.Context(), &in)
	if err == nil {
		err = validateResponse(out, func(out *mdl.SignDataResponseV2Dto) error {
			if err := firstError(
				validateModeNotSwitched(in.ExecutionMode, accepted, "sign data"),
				validateMetadataElements(out.OperationMeta, "operationMeta"),
				validateExecutionShape(accepted, len(out.OperationMeta) > 0, signHasPayload(out), "sign data"),
			); err != nil {
				return err
			}
			// An accepted batch carries no signatures to correlate.
			if accepted {
				return nil
			}
			return validateResponseBatch(dataIDs, signatureDataIdentifiers(out.Signatures), signatureDataPayloads(out.Signatures), "sign data")
		})
	}
	shared.EmitEvent(r.Context(), eventSignData, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, executionStatus(accepted), out); writeErr != nil {
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
	cipherIDs := cipherDataIdentifiers(in.CipherData)
	if err := firstError(
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
		validateNonEmptyBatch(len(in.CipherData), "cipherData"),
		validateUniqueIdentifiers(cipherIDs, "cipherData"),
		validateBatchItems(cipherIDs, cipherDataPayloads(in.CipherData), "cipherData"),
	); err != nil {
		h.rejectRequest(w, r, eventEncryptData, err)
		return
	}
	out, err := h.provider.EncryptData(r.Context(), &in)
	if err == nil {
		err = validateResponse(out, func(out *mdl.EncryptDataResponseV2Dto) error {
			return validateResponseBatch(cipherIDs, cipherDataIdentifiers(out.EncryptedData), cipherDataPayloads(out.EncryptedData), "encrypt data")
		})
	}
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
	var in mdl.CipherDataRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventDecryptData, err)
		shared.RenderError(w, r, err)
		return
	}
	cipherIDs := cipherDataIdentifiers(in.CipherData)
	if err := firstError(
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
		validateNonEmptyBatch(len(in.CipherData), "cipherData"),
		validateUniqueIdentifiers(cipherIDs, "cipherData"),
		validateBatchItems(cipherIDs, cipherDataPayloads(in.CipherData), "cipherData"),
	); err != nil {
		h.rejectRequest(w, r, eventDecryptData, err)
		return
	}
	out, err := h.provider.DecryptData(r.Context(), &in)
	if err == nil {
		err = validateResponse(out, func(out *mdl.DecryptDataResponseV2Dto) error {
			return validateResponseBatch(cipherIDs, cipherDataIdentifiers(out.DecryptedData), cipherDataPayloads(out.DecryptedData), "decrypt data")
		})
	}
	shared.EmitEvent(r.Context(), eventDecryptData, err)
	if err != nil {
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
	if err := firstError(
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
	if err == nil {
		err = validateResponse(out, func(out *mdl.VerifyDataResponseV2Dto) error {
			return validateResponseIdentifiers(dataIDs, verificationIdentifiers(out.Verifications), "verify data")
		})
	}
	shared.EmitEvent(r.Context(), eventVerifyData, err)
	if err != nil {
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
	if err := validateRandomDataLength(in.Length); err != nil {
		h.rejectRequest(w, r, eventRandomData, err)
		return
	}
	out, err := h.provider.RandomData(r.Context(), &in)
	if err == nil {
		err = validateResponse(out, func(out *mdl.RandomDataResponseV2Dto) error {
			return validateRandomDataPayload(out.Data, in.Length)
		})
	}
	shared.EmitEvent(r.Context(), eventRandomData, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write randomData response", "err", writeErr)
	}
}

// --- Async status and cancellation -------------------------------------------
//
// All six routes are always mounted; without their sub-provider (WithAsyncKeys,
// WithAsyncSign) they answer 404 OPERATION_NOT_SUPPORTED, the body the contract
// declares for "endpoint not found or not implemented".

// decodeTracking rejects the request when the sub-provider is absent, then
// decodes the tracking handle and enforces minItems: 1. Reports false after
// rendering.
func (h *Handler) decodeTracking(w http.ResponseWriter, r *http.Request, event string, registered bool, in *mdl.OperationTrackingRequestV2Dto) bool {
	if !registered {
		h.rejectRequest(w, r, event, ErrOperationNotSupported)
		return false
	}
	if err := shared.DecodeJSON(w, r, in, h.MaxBytes, h.Strict); err != nil {
		h.rejectRequest(w, r, event, err)
		return false
	}
	if err := validateNonEmptyBatch(len(in.OperationMeta), "operationMeta"); err != nil {
		h.rejectRequest(w, r, event, err)
		return false
	}
	return true
}

// 200 with the creation status | 404 ErrOperationNotTracked.
func (h *Handler) createKeyStatus(w http.ResponseWriter, r *http.Request) {
	var in mdl.OperationTrackingRequestV2Dto
	if !h.decodeTracking(w, r, eventCreateKeyStatus, h.asyncKeys != nil, &in) {
		return
	}
	out, err := h.asyncKeys.CreateKeyStatus(r.Context(), &in)
	if err == nil {
		err = validateResponse(out, validateKeyCreationStatusShape)
	}
	shared.EmitEvent(r.Context(), eventCreateKeyStatus, err)
	if err != nil {
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
	if !h.decodeTracking(w, r, eventCancelCreateKey, h.asyncKeys != nil, &in) {
		return
	}
	if err := h.asyncKeys.CancelCreateKey(r.Context(), &in); err != nil {
		h.rejectRequest(w, r, eventCancelCreateKey, err)
		return
	}
	shared.EmitEvent(r.Context(), eventCancelCreateKey, nil)
	w.WriteHeader(http.StatusNoContent)
}

// 200 with the destruction status | 404 ErrOperationNotTracked.
func (h *Handler) destroyKeyStatus(w http.ResponseWriter, r *http.Request) {
	var in mdl.OperationTrackingRequestV2Dto
	if !h.decodeTracking(w, r, eventDestroyKeyStatus, h.asyncKeys != nil, &in) {
		return
	}
	out, err := h.asyncKeys.DestroyKeyStatus(r.Context(), &in)
	if err == nil {
		// No result field, so the reason rule alone applies.
		err = validateResponse(out, func(out *mdl.KeyDestructionStatusResponseV2Dto) error {
			return validateStatusReason(out.Status, out.Reason)
		})
	}
	shared.EmitEvent(r.Context(), eventDestroyKeyStatus, err)
	if err != nil {
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
	if !h.decodeTracking(w, r, eventCancelDestroyKey, h.asyncKeys != nil, &in) {
		return
	}
	if err := h.asyncKeys.CancelDestroyKey(r.Context(), &in); err != nil {
		h.rejectRequest(w, r, eventCancelDestroyKey, err)
		return
	}
	shared.EmitEvent(r.Context(), eventCancelDestroyKey, nil)
	w.WriteHeader(http.StatusNoContent)
}

// 200 with the signing batch status | 404 ErrOperationNotTracked.
func (h *Handler) signDataStatus(w http.ResponseWriter, r *http.Request) {
	var in mdl.OperationTrackingRequestV2Dto
	if !h.decodeTracking(w, r, eventSignDataStatus, h.asyncSign != nil, &in) {
		return
	}
	out, err := h.asyncSign.SignDataStatus(r.Context(), &in)
	if err == nil {
		err = validateResponse(out, validateSignStatusShape)
	}
	shared.EmitEvent(r.Context(), eventSignDataStatus, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write signDataStatus response", "err", writeErr)
	}
}

// 204 aborted | 404 ErrOperationNotTracked | 422 ErrCancelPastPointOfNoReturn (terminal or past the point of no return).
func (h *Handler) cancelSignData(w http.ResponseWriter, r *http.Request) {
	var in mdl.OperationTrackingRequestV2Dto
	if !h.decodeTracking(w, r, eventCancelSignData, h.asyncSign != nil, &in) {
		return
	}
	if err := h.asyncSign.CancelSignData(r.Context(), &in); err != nil {
		h.rejectRequest(w, r, eventCancelSignData, err)
		return
	}
	shared.EmitEvent(r.Context(), eventCancelSignData, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Key import ------------------------------------------------------------------
//
// Without WithKeyImport the import, key type and result routes answer 404
// OPERATION_NOT_SUPPORTED before reading the body; the status and cancel routes
// follow the async routes' rule with WithAsyncKeyImport.

func (h *Handler) listImportableKeyTypes(w http.ResponseWriter, r *http.Request) {
	if h.keyImport == nil {
		h.rejectRequest(w, r, eventImportableKeyTypes, errKeyImportNotSupported)
		return
	}
	var in mdl.TokenProfileScopedRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		h.rejectRequest(w, r, eventImportableKeyTypes, err)
		return
	}
	out, err := h.keyImport.ImportableKeyTypes(r.Context(), &in)
	if err == nil {
		err = validateKeyTypeDeclarations(importableDeclarations(out), "importable key types")
	}
	shared.EmitEvent(r.Context(), eventImportableKeyTypes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listImportableKeyTypes response", "err", writeErr)
	}
}

func (h *Handler) listImportKeyAttributes(w http.ResponseWriter, r *http.Request) {
	var in mdl.ImportKeyAttributesRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		h.rejectRequest(w, r, eventImportKeyAttributes, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.importAttrs != nil {
		out, err = h.importAttrs.ImportKeyAttributes(r.Context(), &in)
	}
	if err == nil {
		err = validateEncodable(out)
	}
	shared.EmitEvent(r.Context(), eventImportKeyAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listImportKeyAttributes response", "err", writeErr)
	}
}

// 409 ErrKeyImportConflict when keyImportId is reused non-equivalently.
func (h *Handler) importKey(w http.ResponseWriter, r *http.Request) {
	if h.keyImport == nil {
		h.rejectRequest(w, r, eventImportKey, errKeyImportNotSupported)
		return
	}
	var in mdl.ImportKeyRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		h.rejectRequest(w, r, eventImportKey, err)
		return
	}
	if err := firstError(
		validateExecutionMode(in.ExecutionMode),
		validateIdempotencyKey(in.KeyImportId, "keyImportId"),
		validateKeyReference(in.KeyReference),
		validatePassphrase(in.Passphrase),
		validateRequestMaterial(in.Material),
	); err != nil {
		h.rejectRequest(w, r, eventImportKey, err)
		return
	}
	out, accepted, err := h.keyImport.ImportKey(r.Context(), &in)
	if err == nil {
		err = validateResponse(out, func(out *mdl.KeyCreationResponse) error {
			return firstError(
				validateModeNotSwitched(in.ExecutionMode, accepted, "key import"),
				validateKeyResultShape(accepted, out, "key import"),
				validateRequestedKeyRequestType(keyCreationRequestType(out), in.KeyRequestType),
			)
		})
	}
	shared.EmitEvent(r.Context(), eventImportKey, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, executionStatus(accepted), out); writeErr != nil {
		h.LoggerFor(r).Error("write importKey response", "err", writeErr)
	}
}

// 200 with the recorded state | 404 ErrOperationNotTracked for an import never accepted.
func (h *Handler) importKeyResult(w http.ResponseWriter, r *http.Request) {
	if h.keyImport == nil {
		h.rejectRequest(w, r, eventImportKeyResult, errKeyImportNotSupported)
		return
	}
	var in mdl.ImportKeyResultRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		h.rejectRequest(w, r, eventImportKeyResult, err)
		return
	}
	if err := validateIdempotencyKey(in.KeyImportId, "keyImportId"); err != nil {
		h.rejectRequest(w, r, eventImportKeyResult, err)
		return
	}
	out, err := h.keyImport.ImportKeyResult(r.Context(), &in)
	if err == nil {
		err = validateResponse(out, validateKeyImportStatusShape)
	}
	shared.EmitEvent(r.Context(), eventImportKeyResult, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write importKeyResult response", "err", writeErr)
	}
}

// 200 with the import status | 404 ErrOperationNotTracked.
func (h *Handler) importKeyStatus(w http.ResponseWriter, r *http.Request) {
	var in mdl.OperationTrackingRequestV2Dto
	if !h.decodeTracking(w, r, eventImportKeyStatus, h.asyncImport != nil, &in) {
		return
	}
	out, err := h.asyncImport.ImportKeyStatus(r.Context(), &in)
	if err == nil {
		err = validateResponse(out, validateKeyImportStatusShape)
	}
	shared.EmitEvent(r.Context(), eventImportKeyStatus, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write importKeyStatus response", "err", writeErr)
	}
}

// 204 aborted | 404 ErrOperationNotTracked | 422 ErrCancelPastPointOfNoReturn (terminal or past the point of no return).
func (h *Handler) cancelImportKey(w http.ResponseWriter, r *http.Request) {
	var in mdl.OperationTrackingRequestV2Dto
	if !h.decodeTracking(w, r, eventCancelImportKey, h.asyncImport != nil, &in) {
		return
	}
	if err := h.asyncImport.CancelImportKey(r.Context(), &in); err != nil {
		h.rejectRequest(w, r, eventCancelImportKey, err)
		return
	}
	shared.EmitEvent(r.Context(), eventCancelImportKey, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Key export ------------------------------------------------------------------
//
// Without WithKeyExport the export and key type routes answer 404
// OPERATION_NOT_SUPPORTED before reading the body.

func (h *Handler) listExportableKeyTypes(w http.ResponseWriter, r *http.Request) {
	if h.keyExport == nil {
		h.rejectRequest(w, r, eventExportableKeyTypes, errKeyExportNotSupported)
		return
	}
	var in mdl.TokenProfileScopedRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		h.rejectRequest(w, r, eventExportableKeyTypes, err)
		return
	}
	out, err := h.keyExport.ExportableKeyTypes(r.Context(), &in)
	if err == nil {
		err = validateKeyTypeDeclarations(exportableDeclarations(out), "exportable key types")
	}
	shared.EmitEvent(r.Context(), eventExportableKeyTypes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listExportableKeyTypes response", "err", writeErr)
	}
}

func (h *Handler) listExportKeyAttributes(w http.ResponseWriter, r *http.Request) {
	var in mdl.KeyScopedRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		h.rejectRequest(w, r, eventExportKeyAttributes, err)
		return
	}
	if err := validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"); err != nil {
		h.rejectRequest(w, r, eventExportKeyAttributes, err)
		return
	}
	var out []mdl.BaseAttributeDto
	var err error
	if h.exportAttrs != nil {
		out, err = h.exportAttrs.ExportKeyAttributes(r.Context(), &in)
	}
	if err == nil {
		err = validateEncodable(out)
	}
	shared.EmitEvent(r.Context(), eventExportKeyAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listExportKeyAttributes response", "err", writeErr)
	}
}

// Always synchronous: no protected material is ever held in tracking state.
func (h *Handler) exportKey(w http.ResponseWriter, r *http.Request) {
	if h.keyExport == nil {
		h.rejectRequest(w, r, eventExportKey, errKeyExportNotSupported)
		return
	}
	var in mdl.ExportKeyRequestV2Dto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		h.rejectRequest(w, r, eventExportKey, err)
		return
	}
	if err := firstError(
		validateNonEmptyBatch(len(in.KeyMeta), "keyMeta"),
		validateOptionalKeyReference(in.KeyReference),
		validatePassphrase(in.Passphrase),
	); err != nil {
		h.rejectRequest(w, r, eventExportKey, err)
		return
	}
	out, err := h.keyExport.ExportKey(r.Context(), &in)
	if err == nil {
		err = validateResponse(out, func(out *mdl.ExportKeyResponseV2Dto) error {
			return validateExportShape(&in, out)
		})
	}
	shared.EmitEvent(r.Context(), eventExportKey, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write exportKey response", "err", writeErr)
	}
}
