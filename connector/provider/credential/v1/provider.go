// Package credential provides the HTTP server adapter for the Credential
// Provider API. Credential providers carry no per-instance state — their
// entire surface is the kind-scoped attribute endpoints used by other
// connectors to collect credential material (username/password, API key,
// keystore, etc.).
//
// The Provider interface here is therefore identical in shape to other
// providers' KindAttributeProvider: list attributes for a kind, validate
// a submitted attribute payload. There are no sub-interfaces.
//
// Credential is a v1-family spec: it uses /v1 listSupportedFunctions for
// info and /v1/health for health checks. Wire
// shared.WithErrorRenderer(shared.WriteV1Error) on the Connector.
package credential

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/credential/v1"
)

// Provider is the core business contract every Credential Provider connector
// must implement. The spec exposes only the kind-scoped attribute endpoints,
// so Provider mirrors that surface directly.
//
// Returned errors should be *shared.Error. ValidateAttributes returns
// validation messages (non-empty -> 422 body) separately from operational
// errors:
//
//	(nil, nil)            -> 200 (no validation errors)
//	(["e1","e2"], nil)    -> 422 with the array as body
//	(_, *shared.Error)    -> mapped to the configured error renderer
type Provider interface {
	Attributes(ctx context.Context, kind string) ([]mdl.BaseAttributeDto, error)
	ValidateAttributes(ctx context.Context, kind string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}
