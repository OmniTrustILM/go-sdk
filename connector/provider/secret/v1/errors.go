package secret

import (
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors returned by Provider implementations. ErrorCode values
// match the ErrorCode enum from connector/model/secret/v1 so that the
// rendered ProblemDetailExtended payload aligns with the spec.
//
// Wrap with shared.Error.WithCause / WithProperty to attach context:
//
//	return secret.ErrSecretNotFound.WithCause(err).WithProperty("name", req.Name)
//
// Custom errors not covered here can be built directly via shared.NotFound,
// shared.Invalid, etc.
var (
	// ErrSecretNotFound -> 404 RESOURCE_NOT_FOUND
	ErrSecretNotFound = shared.NotFound("RESOURCE_NOT_FOUND", "secret not found")

	// ErrSecretConflict -> 409 RESOURCE_ALREADY_EXISTS (createSecret only)
	ErrSecretConflict = shared.Conflict("RESOURCE_ALREADY_EXISTS", "secret already exists")

	// ErrInvalidSecretType -> 422 VALIDATION_FAILED (path param validation)
	ErrInvalidSecretType = shared.Invalid("VALIDATION_FAILED", "invalid secret type")

	// ErrInvalidAttributes -> 422 ATTRIBUTES_ERROR (vault/profile/rotate attrs failed validation)
	ErrInvalidAttributes = shared.Invalid("ATTRIBUTES_ERROR", "attributes failed validation")

	// ErrVaultUnreachable -> 503 SERVICE_UNAVAILABLE (vault backend down or unreachable)
	ErrVaultUnreachable = shared.Unavailable("SERVICE_UNAVAILABLE", "vault backend unavailable")

	// ErrAttributesNotRegistered -> 404 RESOURCE_NOT_FOUND (attribute endpoint with no registered provider)
	ErrAttributesNotRegistered = shared.NotFound("RESOURCE_NOT_FOUND", "attribute provider not registered")
)
