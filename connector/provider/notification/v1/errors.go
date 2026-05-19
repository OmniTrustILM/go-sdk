package notification

import (
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors for the Notification Provider surface. v1-spec error codes
// are SDK-internal and surface only in logs.
//
// Wrap with shared.Error.WithCause / WithProperty to attach context.
var (
	ErrInstanceNotFound = shared.NotFound("INSTANCE_NOT_FOUND", "notification instance not found")
	ErrInstanceConflict = shared.Conflict("INSTANCE_ALREADY_EXISTS", "notification instance already exists")
	ErrInvalidRequest   = shared.BadRequest("INVALID_REQUEST", "invalid request")
	ErrSendFailed       = shared.Unavailable("SEND_FAILED", "could not deliver notification")
)
