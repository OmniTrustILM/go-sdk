package attributes

import "github.com/OmniTrustILM/go-sdk/connector/shared"

var (
	// ErrDefinitionNotFound -> 404. Returned by GET /v2/attributes/{uuid} for an
	// unknown UUID and by POST /v2/attributes/callback when the referenced
	// attribute has no registered callback. Uses the interfaces ErrorCode enum
	// value ATTRIBUTE_DEFINITION_NOT_FOUND (CONNECTOR-general, non-retryable):
	// Core refreshes its definition registry from the connector and retries
	// transparently rather than surfacing the failure to the API caller.
	ErrDefinitionNotFound = shared.NotFound("ATTRIBUTE_DEFINITION_NOT_FOUND", "attribute definition not found")

	// ErrNilResponse -> 500. A registered callback returned (nil, nil), a
	// provider contract violation: serializing it would emit a 200 with a null
	// body instead of the required content/attributes arm.
	ErrNilResponse = shared.Internal("INTERNAL_SERVER_ERROR", "callback returned no response")

	// ErrInvalidCallbackResponse -> 500. A callback returned a response that did
	// not set exactly one of content/attributes. The ContentResponse and
	// AttributesResponse helpers guarantee the arm contract; this guard catches
	// hand-built responses that violate it before an ambiguous body reaches Core.
	ErrInvalidCallbackResponse = shared.Internal("INTERNAL_SERVER_ERROR", "callback response must set exactly one of content or attributes")
)
