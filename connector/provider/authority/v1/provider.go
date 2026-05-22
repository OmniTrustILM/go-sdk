// Package authority provides the HTTP server adapter for the Authority
// Provider Legacy (v1) API. Connector authors implement the Provider
// interface (and optionally the KindAttributeProvider /
// RAProfileAttributeProvider sub-interfaces) and register the resulting
// Handler with shared.Connector.
//
// Authority v1 is a v1-family info/health spec: it uses /v1 listSupportedFunctions
// for info and /v1/health for health checks. The function group code reported
// in /v1 info is "legacyAuthorityProvider" (per FUNCTIONGROUPCODE_LEGACY_AUTHORITY_PROVIDER),
// while the route paths use the literal "authorityProvider" path token — a
// quirk of the legacy spec. This means two connectors cannot host both
// authority/v1 and authority/v2 on the same mux (their paths collide), but
// either version can coexist with discovery / entity / cryptography / etc.
//
// Error responses follow the v1 wire shape (ErrorMessageDto /
// AuthenticationServiceExceptionDto / []string for 422); wire
// shared.WithErrorRenderer(shared.WriteV1Error) on the Connector.
package authority

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v1"
)

// Provider is the core business contract every Authority Provider Legacy
// connector must implement. Methods correspond 1:1 to the authority,
// end-entity, and certificate operations in authority-v1.json.
//
// Returned errors should be *shared.Error (use the sentinel values in
// errors.go or build with shared.NotFound/Invalid/...). Plain errors are
// rendered as 500 INTERNAL_ERROR via WriteV1Error.
type Provider interface {
	// --- Authority Management --------------------------------------------

	ListAuthorityInstances(ctx context.Context) ([]mdl.AuthorityProviderInstanceDto, error)
	CreateAuthorityInstance(ctx context.Context, req *mdl.AuthorityProviderInstanceRequestDto) (*mdl.AuthorityProviderInstanceDto, error)
	GetAuthorityInstance(ctx context.Context, uuid string) (*mdl.AuthorityProviderInstanceDto, error)
	UpdateAuthorityInstance(ctx context.Context, uuid string, req *mdl.AuthorityProviderInstanceRequestDto) (*mdl.AuthorityProviderInstanceDto, error)
	RemoveAuthorityInstance(ctx context.Context, uuid string) error
	GetConnection(ctx context.Context, uuid string) error
	GetCaCertificates(ctx context.Context, uuid string, req *mdl.CaCertificatesRequestDto) (*mdl.CaCertificatesResponseDto, error)
	GetCrl(ctx context.Context, uuid string, req *mdl.CertificateRevocationListRequestDto) (*mdl.CertificateRevocationListResponseDto, error)

	// --- End Entity Management -------------------------------------------

	ListEndEntities(ctx context.Context, authorityUuid, endEntityProfileName string) ([]mdl.EndEntityDto, error)
	CreateEndEntity(ctx context.Context, authorityUuid, endEntityProfileName string, req *mdl.AddEndEntityRequestDto) error
	GetEndEntity(ctx context.Context, authorityUuid, endEntityProfileName, endEntityName string) (*mdl.EndEntityDto, error)
	UpdateEndEntity(ctx context.Context, authorityUuid, endEntityProfileName, endEntityName string, req *mdl.EditEndEntityRequestDto) error
	RemoveEndEntity(ctx context.Context, authorityUuid, endEntityProfileName, endEntityName string) error
	ResetPassword(ctx context.Context, authorityUuid, endEntityProfileName, endEntityName string) error

	// --- Certificate Management (under end-entity profile) ---------------

	IssueCertificate(ctx context.Context, authorityUuid, endEntityProfileName string, req *mdl.CertificateSignRequestDto) (*mdl.CertificateSignResponseDto, error)
	RevokeCertificate(ctx context.Context, authorityUuid, endEntityProfileName string, req *mdl.CertRevocationDto) error

	// --- Profile lookups -------------------------------------------------

	ListEntityProfiles(ctx context.Context, authorityUuid string) ([]mdl.NameAndIdDto, error)
	ListCertificateProfiles(ctx context.Context, authorityUuid string, endEntityProfileId int32) ([]mdl.NameAndIdDto, error)
	ListCAsInProfile(ctx context.Context, authorityUuid string, endEntityProfileId int32) ([]mdl.NameAndIdDto, error)
}
