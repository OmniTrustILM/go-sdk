package compliance

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/compliance/v1"
)

// KindAttributeProvider serves the generic kind-scoped attribute endpoints
// shared across v1-family providers:
//
//	GET  /v1/complianceProvider/{kind}/attributes
//	POST /v1/complianceProvider/{kind}/attributes/validate
//
// When no KindAttributeProvider is registered, the list endpoint returns
// 200 with an empty array and validate returns bare 200 — the SDK-wide
// convention.
type KindAttributeProvider interface {
	Attributes(ctx context.Context, kind string) ([]mdl.BaseAttributeDto, error)
	ValidateAttributes(ctx context.Context, kind string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}
