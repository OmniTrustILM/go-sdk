// Package authority provides the HTTP server adapter for the Authority
// Provider v2 API. Connector authors implement the Provider interface (and
// any subset of the optional attribute provider interfaces) and register the
// resulting Handler with shared.Connector.
//
// Authority v2 is a v1-family info/health spec: it uses /v1 listSupportedFunctions
// for info and /v1/health for health checks, while certificate management
// operations live under /v2/authorityProvider/authorities/{uuid}/certificates/...
// The Handler implements shared.V1Reporter so the function group surfaces under
// /v1 info. Error responses follow the v1 wire shape (ErrorMessageDto /
// AuthenticationServiceExceptionDto / []string for 422); wire
// shared.WithErrorRenderer(shared.WriteV1Error) on the Connector.
package authority

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v2"
)

// Provider is the core business contract every Authority Provider v2 connector
// must implement. Methods correspond 1:1 to the authority and certificate
// operations in authority-v2.json.
//
// Returned errors should be *shared.Error (use the sentinel values in
// errors.go or build with shared.NotFound/Invalid/...). Plain errors are
// rendered as 500 INTERNAL_ERROR via WriteV1Error.
type Provider interface {
	// --- Authority Management ---------------------------------------------

	// ListAuthorityInstances returns every authority instance the connector
	// currently manages.
	ListAuthorityInstances(ctx context.Context) ([]mdl.AuthorityProviderInstanceDto, error)

	// CreateAuthorityInstance provisions a new authority instance from the
	// supplied attributes. Implementations should return a stable Uuid that
	// the caller can use in subsequent /authorities/{uuid} operations.
	CreateAuthorityInstance(ctx context.Context, req *mdl.AuthorityProviderInstanceRequestDto) (*mdl.AuthorityProviderInstanceDto, error)

	// GetAuthorityInstance fetches one authority instance by uuid. Returns
	// ErrAuthorityNotFound when the uuid is unknown.
	GetAuthorityInstance(ctx context.Context, uuid string) (*mdl.AuthorityProviderInstanceDto, error)

	// UpdateAuthorityInstance replaces the attributes of an existing instance.
	UpdateAuthorityInstance(ctx context.Context, uuid string, req *mdl.AuthorityProviderInstanceRequestDto) (*mdl.AuthorityProviderInstanceDto, error)

	// RemoveAuthorityInstance deletes the authority instance.
	RemoveAuthorityInstance(ctx context.Context, uuid string) error

	// GetConnection probes connectivity to the underlying CA backend behind
	// the authority instance. Returns nil on success; non-nil on failure
	// (typically shared.Unavailable).
	GetConnection(ctx context.Context, uuid string) error

	// GetCaCertificates returns the CA chain published by the authority
	// instance for the requested RA Profile.
	GetCaCertificates(ctx context.Context, uuid string, req *mdl.CaCertificatesRequestDto) (*mdl.CaCertificatesResponseDto, error)

	// GetCrl returns the (delta) CRL published by the authority instance.
	GetCrl(ctx context.Context, uuid string, req *mdl.CertificateRevocationListRequestDto) (*mdl.CertificateRevocationListResponseDto, error)

	// --- Certificate Management (v2) -------------------------------------

	// IssueCertificate signs a CSR and returns the resulting certificate.
	IssueCertificate(ctx context.Context, authorityUuid string, req *mdl.CertificateSignRequestDto) (*mdl.CertificateDataResponseDto, error)

	// RenewCertificate signs a renewal CSR for an existing certificate.
	RenewCertificate(ctx context.Context, authorityUuid string, req *mdl.CertificateRenewRequestDto) (*mdl.CertificateDataResponseDto, error)

	// RevokeCertificate revokes the supplied certificate against the
	// authority instance.
	RevokeCertificate(ctx context.Context, authorityUuid string, req *mdl.CertRevocationDto) error

	// IdentifyCertificate looks up metadata for a certificate that is known
	// to the authority instance.
	IdentifyCertificate(ctx context.Context, authorityUuid string, req *mdl.CertificateIdentificationRequestDto) (*mdl.CertificateIdentificationResponseDto, error)
}
