package entity

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
)

// Attribute provider interfaces are split per endpoint family so a connector
// can implement only the surfaces it actually exposes. Each unregistered
// endpoint responds 200 with an empty array (list) or bare 200 (validate) —
// the SDK-wide convention.

// KindAttributeProvider serves the generic kind-scoped attribute endpoints
// driving entity-instance creation UIs:
//
//	GET  /v1/entityProvider/{kind}/attributes
//	POST /v1/entityProvider/{kind}/attributes/validate
type KindAttributeProvider interface {
	Attributes(ctx context.Context, kind string) ([]mdl.BaseAttributeDto, error)
	ValidateAttributes(ctx context.Context, kind string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}

// LocationAttributeProvider serves the per-entity location-attribute endpoints:
//
//	GET  /v1/entityProvider/entities/{entityUuid}/location/attributes
//	POST /v1/entityProvider/entities/{entityUuid}/location/attributes/validate
type LocationAttributeProvider interface {
	LocationAttributes(ctx context.Context, entityUuid string) ([]mdl.BaseAttributeDto, error)
	ValidateLocationAttributes(ctx context.Context, entityUuid string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}

// PushCertificateAttributeProvider serves the per-entity push-certificate
// attribute endpoints:
//
//	GET  /v1/entityProvider/entities/{entityUuid}/locations/push/attributes
//	POST /v1/entityProvider/entities/{entityUuid}/locations/push/attributes/validate
type PushCertificateAttributeProvider interface {
	PushCertificateAttributes(ctx context.Context, entityUuid string) ([]mdl.BaseAttributeDto, error)
	ValidatePushCertificateAttributes(ctx context.Context, entityUuid string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}

// GenerateCsrAttributeProvider serves the per-entity generate-CSR attribute
// endpoints:
//
//	GET  /v1/entityProvider/entities/{entityUuid}/locations/csr/attributes
//	POST /v1/entityProvider/entities/{entityUuid}/locations/csr/attributes/validate
type GenerateCsrAttributeProvider interface {
	GenerateCsrAttributes(ctx context.Context, entityUuid string) ([]mdl.BaseAttributeDto, error)
	ValidateGenerateCsrAttributes(ctx context.Context, entityUuid string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}
