package entity

import (
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors for the Entity Provider surface. v1-spec error codes are
// SDK-internal and surface only in logs.
//
// Wrap with shared.Error.WithCause / WithProperty to attach context.
var (
	ErrEntityNotFound      = shared.NotFound("ENTITY_NOT_FOUND", "entity instance not found")
	ErrEntityConflict      = shared.Conflict("ENTITY_ALREADY_EXISTS", "entity instance already exists")
	ErrLocationNotFound    = shared.NotFound("LOCATION_NOT_FOUND", "location not found")
	ErrCertificateNotFound = shared.NotFound("CERTIFICATE_NOT_FOUND", "certificate not found at location")
	ErrInvalidRequest      = shared.BadRequest("INVALID_REQUEST", "invalid request")
)
