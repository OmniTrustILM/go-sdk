package authority

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
)

// Attribute provider interfaces are split per endpoint family so a connector
// can implement only the surfaces it actually exposes. Each unregistered
// attribute endpoint responds 200 with an empty array — the SDK-wide
// convention for optional attribute providers.

// AuthorityAttributeProvider serves the top-level authority attribute schema
// used by the create-authority UI:
//
//	GET /v3/authorityProvider/authorities/attributes
//
// Attributes marked required here must be present as authorityAttributes on
// every other v3 operation; the connector validates them per request because
// v3 is stateless.
type AuthorityAttributeProvider interface {
	AuthorityAttributes(ctx context.Context) ([]mdl.BaseAttributeDto, error)
}

// RAProfileAttributeProvider serves the RA-profile attribute schema given an
// authority context:
//
//	POST /v3/authorityProvider/authorities/raProfile/attributes
type RAProfileAttributeProvider interface {
	RAProfileAttributes(ctx context.Context, authorityAttrs []mdl.RequestAttribute) ([]mdl.BaseAttributeDto, error)
}

// IssueAttributeProvider serves the issue-operation attribute schema (shared
// by issue and renew):
//
//	POST /v3/authorityProvider/certificates/issue/attributes
type IssueAttributeProvider interface {
	IssueAttributes(ctx context.Context, req *mdl.CertificateAttributeListRequestDtoV3) ([]mdl.BaseAttributeDto, error)
}

// RevokeAttributeProvider serves the revoke-operation attribute schema:
//
//	POST /v3/authorityProvider/certificates/revoke/attributes
type RevokeAttributeProvider interface {
	RevokeAttributes(ctx context.Context, req *mdl.CertificateAttributeListRequestDtoV3) ([]mdl.BaseAttributeDto, error)
}

// RegisterAttributeProvider serves the register-operation attribute schema:
//
//	POST /v3/authorityProvider/certificates/register/attributes
type RegisterAttributeProvider interface {
	RegisterAttributes(ctx context.Context, req *mdl.CertificateAttributeListRequestDtoV3) ([]mdl.BaseAttributeDto, error)
}

// AttributeDefinitionsProvider serves the connector-level Attributes API
// (spec tag "Connector Attributes v2") introduced in authority-v3:
//
//	GET  /v2/attributes            -> list every attribute definition
//	GET  /v2/attributes/{uuid}     -> one definition by UUID
//	POST /v2/attributes/callback   -> resolve a dynamic-attribute callback
//
// These endpoints are connector-global rather than authority-scoped; they
// are exposed here because authority-v3 is currently their only implementor.
// Wire one via WithAttributeDefinitions; when unwired, ListDefinitions
// returns an empty definition set, GetDefinition responds 404, and Callback
// responds 404.
type AttributeDefinitionsProvider interface {
	// ListDefinitions returns the connector version and every attribute
	// definition the connector publishes. GET /v2/attributes -> 200.
	ListDefinitions(ctx context.Context) (*mdl.AttributeDefinitionsDto, error)

	// GetDefinition returns a single attribute definition by UUID, or
	// ErrDefinitionNotFound (404) when unknown. GET /v2/attributes/{uuid}.
	GetDefinition(ctx context.Context, uuid string) (*mdl.BaseAttributeDto, error)

	// Callback resolves a dynamic-attribute callback. POST
	// /v2/attributes/callback -> 200 with the resolved content/attributes.
	Callback(ctx context.Context, req *mdl.AttributeCallbackRequestDto) (*mdl.AttributeCallbackResponseDto, error)
}
