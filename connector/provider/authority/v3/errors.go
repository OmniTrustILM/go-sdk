package authority

import (
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors for the Authority Provider v3 surface. Rendered as RFC 9457
// problem+json with the errorCode extension (the v2-family wire shape).
//
// Wrap with shared.Error.WithCause / WithProperty to attach context:
//
//	return authority.ErrCertificateNotFound.WithProperty("serial", serial)
var (
	// ErrCertificateNotFound -> 404 (identify / renew / revoke of a
	// certificate unknown to the upstream CA)
	ErrCertificateNotFound = shared.NotFound("CERTIFICATE_NOT_FOUND", "certificate not found")

	// ErrOperationNotFound -> 404 (status / cancel with an unknown meta
	// tracking handle)
	ErrOperationNotFound = shared.NotFound("OPERATION_NOT_FOUND", "async operation not found")

	// ErrCancelRefused -> 422 (cancel arrived past the point of no return)
	ErrCancelRefused = shared.Invalid("CANCEL_REFUSED", "operation is past the point of no return")

	// ErrInvalidRequest -> 400
	ErrInvalidRequest = shared.BadRequest("INVALID_REQUEST", "invalid request")

	// ErrConnectionFailed -> 503 (upstream CA unreachable)
	ErrConnectionFailed = shared.Unavailable("CONNECTION_FAILED", "could not connect to authority backend")

	// ErrDefinitionNotFound -> 404 (getDefinition with an unknown attribute UUID).
	// Uses the spec ErrorCode enum value ATTRIBUTE_DEFINITION_NOT_FOUND
	// (ProblemDetailExtended.errorCode is $ref ErrorCode).
	ErrDefinitionNotFound = shared.NotFound("ATTRIBUTE_DEFINITION_NOT_FOUND", "attribute definition not found")

	// ErrNilResponse -> 500. Guards handlers whose provider method must always
	// return a value: a nil result with no error is a provider contract
	// violation, and serializing it would emit a 200 with a null body.
	ErrNilResponse = shared.Internal("INTERNAL_SERVER_ERROR", "provider returned no response")
)
