package authority

import (
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors for the Authority Provider v2 surface. v1-spec error codes
// are SDK-internal and surface only in logs (the wire shape is just a
// message string for 4xx/5xx).
//
// Wrap with shared.Error.WithCause / WithProperty to attach context:
//
//	return authority.ErrAuthorityNotFound.WithCause(err).WithProperty("uuid", id)
var (
	// ErrAuthorityNotFound -> 404 V1ErrorMessageDto
	ErrAuthorityNotFound = shared.NotFound("AUTHORITY_NOT_FOUND", "authority instance not found")

	// ErrAuthorityConflict -> 409 V1ErrorMessageDto (createAuthorityInstance)
	ErrAuthorityConflict = shared.Conflict("AUTHORITY_ALREADY_EXISTS", "authority instance already exists")

	// ErrInvalidRequest -> 400 V1ErrorMessageDto
	ErrInvalidRequest = shared.BadRequest("INVALID_REQUEST", "invalid request")

	// ErrConnectionFailed -> 503 V1ErrorMessageDto (getConnection / backend unreachable)
	ErrConnectionFailed = shared.Unavailable("CONNECTION_FAILED", "could not connect to authority backend")

	// ErrCertificateNotFound -> 404 V1ErrorMessageDto (identify / renew of an unknown cert)
	ErrCertificateNotFound = shared.NotFound("CERTIFICATE_NOT_FOUND", "certificate not found")
)
