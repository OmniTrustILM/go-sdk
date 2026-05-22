package credential

import (
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors for the Credential Provider surface. v1-spec error codes
// are SDK-internal and surface only in logs.
//
// Wrap with shared.Error.WithCause / WithProperty to attach context.
var (
	ErrKindNotFound   = shared.NotFound("KIND_NOT_FOUND", "credential kind not supported")
	ErrInvalidRequest = shared.BadRequest("INVALID_REQUEST", "invalid request")
)
