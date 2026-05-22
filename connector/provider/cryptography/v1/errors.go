package cryptography

import (
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors for the Cryptography Provider surface. v1-spec error codes
// are SDK-internal and surface only in logs.
//
// Wrap with shared.Error.WithCause / WithProperty to attach context.
var (
	ErrTokenNotFound  = shared.NotFound("TOKEN_NOT_FOUND", "token instance not found")
	ErrKeyNotFound    = shared.NotFound("KEY_NOT_FOUND", "key not found")
	ErrTokenConflict  = shared.Conflict("TOKEN_ALREADY_EXISTS", "token instance already exists")
	ErrInvalidRequest = shared.BadRequest("INVALID_REQUEST", "invalid request")
	ErrTokenInactive  = shared.Unavailable("TOKEN_INACTIVE", "token instance is not active")
)
