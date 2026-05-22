package authority

import (
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors for the Authority Provider Legacy surface. v1-spec error
// codes are SDK-internal and surface only in logs (the wire shape is just a
// message string for 4xx/5xx).
//
// Wrap with shared.Error.WithCause / WithProperty to attach context:
//
//	return authority.ErrAuthorityNotFound.WithCause(err).WithProperty("uuid", id)
var (
	ErrAuthorityNotFound = shared.NotFound("AUTHORITY_NOT_FOUND", "authority instance not found")
	ErrAuthorityConflict = shared.Conflict("AUTHORITY_ALREADY_EXISTS", "authority instance already exists")
	ErrEndEntityNotFound = shared.NotFound("END_ENTITY_NOT_FOUND", "end entity not found")
	ErrProfileNotFound   = shared.NotFound("PROFILE_NOT_FOUND", "end-entity profile not found")
	ErrInvalidRequest    = shared.BadRequest("INVALID_REQUEST", "invalid request")
	ErrConnectionFailed  = shared.Unavailable("CONNECTION_FAILED", "could not connect to authority backend")
)
