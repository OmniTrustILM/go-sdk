package authority

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v2"
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
// Used to drive instance creation UIs that depend on the chosen kind.
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

// IssueCertificateAttributeProvider serves the issue-certificate attribute
// endpoints scoped to a specific authority instance:
//
//	GET  /v2/authorityProvider/authorities/{uuid}/certificates/issue/attributes
//	POST /v2/authorityProvider/authorities/{uuid}/certificates/issue/attributes/validate
type IssueCertificateAttributeProvider interface {
	IssueCertificateAttributes(ctx context.Context, authorityUuid string) ([]mdl.BaseAttributeDto, error)
	ValidateIssueCertificateAttributes(ctx context.Context, authorityUuid string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}

// RevokeCertificateAttributeProvider serves the revoke-certificate attribute
// endpoints scoped to a specific authority instance:
//
//	GET  /v2/authorityProvider/authorities/{uuid}/certificates/revoke/attributes
//	POST /v2/authorityProvider/authorities/{uuid}/certificates/revoke/attributes/validate
type RevokeCertificateAttributeProvider interface {
	RevokeCertificateAttributes(ctx context.Context, authorityUuid string) ([]mdl.BaseAttributeDto, error)
	ValidateRevokeCertificateAttributes(ctx context.Context, authorityUuid string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}
