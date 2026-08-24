package cryptography

import (
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors for the Cryptography Provider v2 surface. Rendered as
// RFC 9457 problem+json with the errorCode extension (the v2-family wire
// shape). Wrap with shared.Error.WithCause / WithProperty to attach context —
// both return copies, so these package-level values stay immutable:
//
//	return cryptography.ErrKeyNotFound.WithProperty("keyAlias", alias)
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

	// ErrInvalidRequest -> 400.
	ErrInvalidRequest = shared.BadRequest("INVALID_REQUEST", "invalid request")

	// ErrNilResponse -> 500. Guards handlers whose provider method must always
	// return a value: a nil result with no error is a provider contract
	// violation, and serializing it would emit a 200 with a null body.
	ErrNilResponse = shared.Internal("INTERNAL_SERVER_ERROR", "provider returned no response")
)
