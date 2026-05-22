package notification

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/notification/v1"
)

// Attribute provider interfaces are split per endpoint family so a connector
// can implement only the surfaces it actually exposes. Each unregistered
// endpoint responds 200 with an empty array (list) or bare 200 (validate) —
// the SDK-wide convention.

// KindAttributeProvider serves the generic kind-scoped attribute endpoints
// driving notification-instance creation UIs:
//
//	GET  /v1/notificationProvider/{kind}/attributes
//	POST /v1/notificationProvider/{kind}/attributes/validate
type KindAttributeProvider interface {
	Attributes(ctx context.Context, kind string) ([]mdl.BaseAttributeDto, error)
	ValidateAttributes(ctx context.Context, kind string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}

// MappingAttributeProvider serves the kind-scoped recipient-mapping attribute
// endpoint:
//
//	GET /v1/notificationProvider/{kind}/attributes/mapping
//
// Note the response is a list of mdl.DataAttribute (a oneOf V2/V3 wrapper)
// instead of BaseAttributeDto — the mapping definition only allows data
// attributes per spec.
type MappingAttributeProvider interface {
	MappingAttributes(ctx context.Context, kind string) ([]mdl.DataAttribute, error)
}
