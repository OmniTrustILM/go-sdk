// Package discovery implements the Discovery Provider v2 connector interface:
// the run lifecycle (initiate, status, results, stop, resume and cancel), the
// supported resources and their attribute schemas and, optionally, the
// connector-global Attributes v2 API.
//
// Every lifecycle call replays the run's scope and its opaque checkpoint, so a
// provider can serve a run from the request alone. A run travels in one of two
// delivery modes, agreed on initiate and again on resume (see
// ChooseDeliveryMode):
//
//   - buffered: the connector holds the items it has not handed over between
//     calls, and the checkpoint changes only on initiate, stop and resume.
//   - checkpointed: the connector holds nothing between calls. Each results
//     call does a bounded amount of work from the replayed checkpoint and
//     returns the run's new checkpoint with its page, so any instance of the
//     connector can serve the next call.
package discovery

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
)

// Provider is the surface every v2 discovery connector implements.
//
// Before any method runs, the handler rejects with 422 a runId that is not a
// UUID, an empty or repeating resources list, a checkpoint larger than
// MaxCheckpointBytes and drain bounds outside the contract. Everything else is
// the provider's to check on every call: the resources and attributes it
// supports, and the checkpoint it minted.
//
// Initiate must be idempotent per runId. Initiate and Resume answer the
// delivery mode the run uses from then on, one of the modes the request
// offers; a nil DeliveryMode means buffered. A connector that supports none of
// the offered modes answers 422 (ChooseDeliveryMode returns that error).
//
// In buffered delivery, Results never returns a page across a lost sequence
// range: answer ErrDiscoveryNotFound, because Core takes the highest sequence
// returned as its cursor.
//
// In checkpointed delivery:
//   - Results numbers its items densely from afterSequence + 1, returns the
//     checkpoint after those items on every page (an empty one included),
//     never splits one unit of work across pages and answers within 20
//     seconds. A drain that does not offer checkpointed comes from a Core that
//     would not store the page's checkpoint: answer ErrCheckpointedNotOffered.
//     When the connector is too busy, answer ErrBusy.
//   - Status reports the run from the replayed checkpoint.
//   - Stop and Resume answer without a checkpoint: Core keeps the one it holds.
//   - A checkpoint the provider cannot read is ErrInvalidRequest, and one that
//     disagrees with afterSequence is ErrDiscoveryNotFound. Any 422 on Results
//     ends the run, so keep it for conditions a retry cannot clear.
//
// Write checkpoints as schema v3 metadata attributes. Schema v2 attribute
// content carries no type of its own, so a v2 string checkpoint does not
// decode when Core replays it.
type Provider interface {
	Initiate(context.Context, *mdl.DiscoveryInitiateRequestDto) (*mdl.DiscoveryInitiateResponseDto, error)
	Status(context.Context, *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryStatusResponseDto, error)
	Results(context.Context, *mdl.DiscoveryDrainRequestDto) (*mdl.DiscoveryResultsResponseDto, error)
	Stop(context.Context, *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryStopResponseDto, error)
	Resume(context.Context, *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryInitiateResponseDto, error)
	Cancel(context.Context, *mdl.DiscoveryRunRequestDto) error
	SupportedResources(context.Context) ([]mdl.DiscoverySupportedResourceDto, error)
	RunAttributes(context.Context) ([]mdl.BaseAttributeDto, error)
	ResourceAttributes(context.Context, mdl.Resource) ([]mdl.BaseAttributeDto, error)
}

// AttributeDefinitionsProvider optionally mounts the connector-global Attributes v2 API.
// Wire it only when another provider (such as authority/v3) does not already mount that API.
type AttributeDefinitionsProvider interface {
	ListDefinitions(context.Context) (*mdl.AttributeDefinitionsDto, error)
	GetDefinition(context.Context, string) (*mdl.BaseAttributeDto, error)
	Callback(context.Context, *mdl.AttributeCallbackRequestDto) (*mdl.AttributeCallbackResponseDto, error)
}
