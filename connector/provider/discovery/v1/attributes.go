package discovery

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v1"
)

// AttributeProvider is the optional interface backing the kind-scoped
// attribute endpoints:
//
//	GET  /v1/discoveryProvider/{kind}/attributes
//	POST /v1/discoveryProvider/{kind}/attributes/validate
//
// Connector authors implement it once and pass it via WithAttributes. When
// no AttributeProvider is registered, the list endpoint returns 200 with an
// empty array and the validate endpoint returns 200 (i.e. nothing to
// validate). The empty-list-on-absent-provider convention is shared across
// the SDK.
//
// Attributes is called from list endpoint; ValidateAttributes from the
// validate endpoint. ValidateAttributes returns:
//
//	(nil, nil)            -> 200 (no validation errors)
//	(["e1","e2"], nil)    -> 422 with the array as body
//	(_, *shared.Error)    -> mapped to the configured error renderer
type AttributeProvider interface {
	Attributes(ctx context.Context, kind string) ([]mdl.BaseAttributeDto, error)
	ValidateAttributes(ctx context.Context, kind string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}
