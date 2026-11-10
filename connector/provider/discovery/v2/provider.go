// Package discovery adapts the replayable Discovery Provider v2 API to the shared connector server.
package discovery

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
)

// Provider implements discovery business logic. Requests replay connection attributes and checkpoints;
// implementations must validate supported resources and attributes on every lifecycle call.
// Initiate must be idempotent; Results must never return a page across a lost sequence range.
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
