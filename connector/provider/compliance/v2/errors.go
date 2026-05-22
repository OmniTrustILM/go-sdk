package compliance

import (
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors for the Compliance Provider v2 surface. v1-spec error codes
// are SDK-internal and surface only in logs.
//
// Wrap with shared.Error.WithCause / WithProperty to attach context:
//
//	return compliance.ErrRuleNotFound.WithCause(err).WithProperty("uuid", id)
var (
	ErrRuleNotFound   = shared.NotFound("RULE_NOT_FOUND", "compliance rule not found")
	ErrGroupNotFound  = shared.NotFound("GROUP_NOT_FOUND", "compliance group not found")
	ErrKindNotFound   = shared.NotFound("KIND_NOT_FOUND", "compliance kind not supported")
	ErrInvalidRequest = shared.BadRequest("INVALID_REQUEST", "invalid request")
)
