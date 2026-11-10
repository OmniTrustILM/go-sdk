package discovery

import "github.com/OmniTrustILM/go-sdk/connector/shared"

var (
	ErrInvalidRequest      = shared.Invalid("VALIDATION_FAILED", "invalid discovery request")
	ErrDiscoveryNotFound   = shared.NotFound("RESOURCE_NOT_FOUND", "discovery run or undrained results unavailable")
	ErrCheckpointLost      = &shared.Error{Status: 410, ErrorCode: "CHECKPOINT_LOST", Title: "Gone", Detail: "discovery checkpoint unavailable"}
	ErrPastPointOfNoReturn = shared.Invalid("OPERATION_PAST_POINT_OF_NO_RETURN", "discovery cannot be stopped or cancelled")
	ErrDefinitionNotFound  = shared.NotFound("ATTRIBUTE_DEFINITION_NOT_FOUND", "attribute definition not found")
	ErrNilResponse         = shared.Internal("INTERNAL_SERVER_ERROR", "provider returned no response")
)
