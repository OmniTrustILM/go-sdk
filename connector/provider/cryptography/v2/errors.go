package cryptography

import (
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors for the Cryptography Provider v2 surface, rendered as RFC 9457
// problem+json with an errorCode from the contract's ErrorCode enum.
//
// WithCause attaches context that is logged and never serialized; WithProperty
// renders into the client-visible problem document. Neither may carry key
// material or secrets, and WithProperty must not echo a key identifier the
// caller did not supply: a 404 naming the alias it failed to find is a
// key-enumeration oracle.
//
//	return cryptography.ErrKeyNotFound.WithCause(fmt.Errorf("slot %d: %w", slot, err))
var (
	// ErrKeyCreationConflict -> 409. keyCreationId reused with a request that
	// is not equivalent to the original.
	ErrKeyCreationConflict = shared.Conflict("RESOURCE_ALREADY_EXISTS", "keyCreationId already used for a different request")

	// ErrOperationNotTracked -> 404. A status or cancel call named a tracking
	// handle the connector does not know. The cryptography contract specifies
	// OPERATION_NOT_TRACKED, where authority/v3 uses OPERATION_NOT_FOUND.
	ErrOperationNotTracked = shared.NotFound("OPERATION_NOT_TRACKED", "async operation is not tracked")

	// ErrCancelPastPointOfNoReturn -> 422. Cancel refused because the
	// operation is already terminal or past the point of no return.
	ErrCancelPastPointOfNoReturn = shared.Invalid("OPERATION_PAST_POINT_OF_NO_RETURN", "operation is terminal or past the point of no return")

	// ErrTokenNotFound -> 404.
	ErrTokenNotFound = shared.NotFound("RESOURCE_NOT_FOUND", "token not found")

	// ErrKeyNotFound -> 404.
	ErrKeyNotFound = shared.NotFound("RESOURCE_NOT_FOUND", "key not found")

	// ErrInvalidRequest -> 400. BAD_REQUEST is the contract's code for an
	// unreadable body; the v1-family packages' INVALID_REQUEST is not in this
	// contract's enum.
	ErrInvalidRequest = shared.BadRequest("BAD_REQUEST", "invalid request")

	// ErrOperationNotSupported -> 404. Rendered by the status and cancel
	// routes when their sub-provider was not registered.
	ErrOperationNotSupported = shared.NotFound("OPERATION_NOT_SUPPORTED", "asynchronous execution is not implemented by this connector")

	// ErrSignatureAlgorithmUnsupported -> 422. The selected signature algorithm
	// is unknown, or the key lacks it.
	ErrSignatureAlgorithmUnsupported = shared.Invalid("PARAMETER_UNSUPPORTED", "signature algorithm is not supported by the key")

	// ErrNilResponse -> 500. A nil result with no error would serialize as a
	// 200 with a null body.
	ErrNilResponse = shared.Internal("INTERNAL_SERVER_ERROR", "provider returned no response")

	// ErrKeyDecryptionFailed -> 422. The key material does not open with the
	// supplied passphrase; OpenKeyMaterial returns it.
	ErrKeyDecryptionFailed = shared.Invalid("KEY_DECRYPTION_FAILED", "key material could not be decrypted with the supplied passphrase")

	// ErrKeyImportConflict -> 409. keyImportId reused with a request that is
	// not equivalent to the original.
	ErrKeyImportConflict = shared.Conflict("RESOURCE_ALREADY_EXISTS", "keyImportId already used for a different request")

	// ErrKeyTypeNotImportable -> 422. The key type or algorithm cannot be
	// imported into this token.
	ErrKeyTypeNotImportable = shared.Invalid("KEY_TYPE_NOT_IMPORTABLE", "key type or algorithm cannot be imported into this token")

	// ErrKeyMaterialMismatch -> 422. The key is not of the declared key type
	// or algorithm.
	ErrKeyMaterialMismatch = shared.Invalid("KEY_MATERIAL_MISMATCH", "key is not of the declared key type or algorithm")

	// ErrExportableNotSupported -> 422. The token cannot hold a key that stays
	// exportable.
	ErrExportableNotSupported = shared.Invalid("EXPORTABLE_NOT_SUPPORTED", "token cannot hold a key that stays exportable")

	// ErrKeyNotExportable -> 422. The key was not created or imported as
	// exportable.
	ErrKeyNotExportable = shared.Invalid("KEY_NOT_EXPORTABLE", "key was not created or imported as exportable")

	// ErrKeyTypeNotExportable -> 422. The key type or algorithm cannot be
	// exported from this token.
	ErrKeyTypeNotExportable = shared.Invalid("KEY_TYPE_NOT_EXPORTABLE", "key type or algorithm cannot be exported from this token")
)
