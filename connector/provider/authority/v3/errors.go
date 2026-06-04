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
)
