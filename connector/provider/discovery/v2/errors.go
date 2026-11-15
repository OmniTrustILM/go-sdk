package discovery

import "github.com/OmniTrustILM/go-sdk/connector/shared"

var (
	// ErrInvalidRequest is a request the connector cannot serve as sent: an
	// unsupported resource or attribute, or a checkpoint it cannot read.
	ErrInvalidRequest = shared.Invalid("VALIDATION_FAILED", "invalid discovery request")
	// ErrDiscoveryNotFound is a run the connector cannot serve from the
	// request: a runId it cannot rebuild, buffered items it no longer holds,
	// or, in checkpointed delivery, a checkpoint that disagrees with
	// afterSequence. It ends the run at once.
	ErrDiscoveryNotFound = shared.NotFound("OPERATION_NOT_TRACKED", "discovery run not tracked")
	// ErrCheckpointLost answers a resume whose checkpoint is no longer
	// available. Only resume declares it.
	ErrCheckpointLost      = &shared.Error{Status: 410, ErrorCode: "CHECKPOINT_LOST", Title: "Gone", Detail: "discovery checkpoint unavailable"}
	ErrPastPointOfNoReturn = shared.Invalid("OPERATION_PAST_POINT_OF_NO_RETURN", "discovery cannot be stopped or cancelled")
	// ErrResourceNotSupported answers a resource type the connector does not
	// discover.
	ErrResourceNotSupported = shared.NotFound("RESOURCE_NOT_FOUND", "resource type not supported")
	// ErrCheckpointedNotOffered answers a drain of a checkpointed run that
	// does not offer checkpointed delivery, so that a Core which does can take
	// the retry.
	ErrCheckpointedNotOffered = shared.Unavailable("SERVICE_UNAVAILABLE", "the drain does not offer checkpointed delivery")
	// ErrBusy answers a drain the connector is too busy to take. In
	// checkpointed delivery Core calls again shortly without counting a
	// failure, for a bounded time; in buffered delivery it counts as an
	// unanswered drain.
	ErrBusy               = shared.Unavailable("SERVICE_UNAVAILABLE", "connector too busy to take the call")
	ErrDefinitionNotFound = shared.NotFound("ATTRIBUTE_DEFINITION_NOT_FOUND", "attribute definition not found")
	ErrNilResponse        = shared.Internal("INTERNAL_SERVER_ERROR", "provider returned no response")
)
