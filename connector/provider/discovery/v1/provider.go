// Package discovery provides the HTTP server adapter for the Discovery
// Provider v1 API. Connector authors implement the Provider interface (and
// optionally the AttributeProvider interface) and register the resulting
// Handler with shared.Connector.
//
// Discovery is a v1 spec: it uses /v1 listSupportedFunctions for info and
// /v1/health for health checks. The Handler implements shared.V1Reporter so
// it surfaces under /v1 info. Error responses follow the v1 ErrorMessageDto
// shape — wire WithErrorRenderer(discovery.WriteError) on the Connector to
// keep panic responses consistent with the rest of the spec.
package discovery

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v1"
)

// Provider is the core business contract every Discovery Provider connector
// must implement. Methods correspond 1:1 to the discovery operations in
// discovery.json.
//
// Returned errors should be *shared.Error (use the sentinel values in
// errors.go or build with shared.NotFound/Invalid/...). Plain errors are
// rendered as 500 INTERNAL_ERROR via WriteError.
type Provider interface {
	// DiscoverCertificate starts a new discovery job. Implementations may
	// run the discovery synchronously or kick off an async task and return
	// a status of "inProgress" — the response shape is identical either
	// way.
	DiscoverCertificate(ctx context.Context, req *mdl.DiscoveryRequestDto) (*mdl.DiscoveryProviderDto, error)

	// GetDiscovery fetches the current state and paginated certificate data
	// for an existing discovery, identified by the {uuid} path parameter.
	GetDiscovery(ctx context.Context, uuid string, req *mdl.DiscoveryDataRequestDto) (*mdl.DiscoveryProviderDto, error)

	// DeleteDiscovery removes a discovery and any associated state.
	// Returns ErrDiscoveryNotFound when the uuid is unknown.
	DeleteDiscovery(ctx context.Context, uuid string) error
}
