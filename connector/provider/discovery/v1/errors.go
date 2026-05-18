package discovery

import (
	"net/http"

	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors returned by Provider / AttributeProvider implementations.
// The Discovery v1 spec does not define ErrorCode enum values; the codes
// here are SDK-internal and surface only in logs.
//
// Wrap with shared.Error.WithCause / WithProperty to attach context:
//
//	return discovery.ErrDiscoveryNotFound.WithCause(err).WithProperty("uuid", id)
var (
	// ErrDiscoveryNotFound -> 404 V1ErrorMessageDto
	ErrDiscoveryNotFound = shared.NotFound("DISCOVERY_NOT_FOUND", "discovery not found")

	// ErrInvalidRequest -> 400 V1ErrorMessageDto
	ErrInvalidRequest = shared.BadRequest("INVALID_REQUEST", "invalid request")
)

// WriteError is kept for backwards compatibility with code already wiring
// shared.WithErrorRenderer(discovery.WriteError). It delegates to the v1-
// family renderer hoisted into shared so the actual output shape is owned
// in one place.
//
// New code should prefer shared.WriteV1Error directly.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	shared.WriteV1Error(w, r, err)
}

// WriteValidationErrors delegates to the shared v1-family helper for the
// same reason as WriteError.
func WriteValidationErrors(w http.ResponseWriter, r *http.Request, messages []string) {
	shared.WriteV1ValidationErrors(w, r, messages)
}
