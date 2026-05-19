package authority

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v1"
)

// Attribute provider interfaces are split per endpoint family so a connector
// can implement only the surfaces it actually exposes. Each unregistered
// attribute endpoint responds 200 with an empty array (list) or bare 200
// (validate) — the SDK-wide convention.

// KindAttributeProvider serves the generic kind-scoped attribute endpoints
// shared across all v1-family providers:
//
//	GET  /v1/authorityProvider/{kind}/attributes
//	POST /v1/authorityProvider/{kind}/attributes/validate
//
// Used to drive authority instance creation UIs that depend on the chosen kind.
type KindAttributeProvider interface {
	Attributes(ctx context.Context, kind string) ([]mdl.BaseAttributeDto, error)
	ValidateAttributes(ctx context.Context, kind string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}

// RAProfileAttributeProvider serves the RA Profile attribute endpoints scoped
// to a specific authority instance:
//
//	GET  /v1/authorityProvider/authorities/{uuid}/raProfile/attributes
//	POST /v1/authorityProvider/authorities/{uuid}/raProfile/attributes/validate
type RAProfileAttributeProvider interface {
	RAProfileAttributes(ctx context.Context, authorityUuid string) ([]mdl.BaseAttributeDto, error)
	ValidateRAProfileAttributes(ctx context.Context, authorityUuid string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}
