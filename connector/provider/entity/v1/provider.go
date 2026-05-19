// Package entity provides the HTTP server adapter for the Entity Provider
// API. Connector authors implement the Provider interface (and any subset
// of the optional attribute provider sub-interfaces) and register the
// resulting Handler with shared.Connector.
//
// Entity is a v1-family info/health spec: it uses /v1 listSupportedFunctions
// for info and /v1/health for health checks. Wire
// shared.WithErrorRenderer(shared.WriteV1Error) on the Connector.
package entity

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
)

// Provider is the core business contract every Entity Provider connector
// must implement. Methods correspond 1:1 to the operations in entity.json.
//
// Returned errors should be *shared.Error. Plain errors render as 500
// INTERNAL_ERROR via WriteV1Error.
type Provider interface {
	// --- Entity instance management -------------------------------------

	ListEntityInstances(ctx context.Context) ([]mdl.EntityInstanceDto, error)
	CreateEntityInstance(ctx context.Context, req *mdl.EntityInstanceRequestDto) (*mdl.EntityInstanceDto, error)
	GetEntityInstance(ctx context.Context, entityUuid string) (*mdl.EntityInstanceDto, error)
	UpdateEntityInstance(ctx context.Context, entityUuid string, req *mdl.EntityInstanceRequestDto) (*mdl.EntityInstanceDto, error)
	RemoveEntityInstance(ctx context.Context, entityUuid string) error

	// --- Location operations --------------------------------------------

	// GetLocationDetail fetches the certificate inventory + metadata for a
	// specific location identified by req.LocationAttributes.
	GetLocationDetail(ctx context.Context, entityUuid string, req *mdl.LocationDetailRequestDto) (*mdl.LocationDetailResponseDto, error)

	// PushCertificateToLocation uploads a certificate to a location.
	PushCertificateToLocation(ctx context.Context, entityUuid string, req *mdl.PushCertificateRequestDto) (*mdl.PushCertificateResponseDto, error)

	// RemoveCertificateFromLocation removes a previously pushed certificate.
	RemoveCertificateFromLocation(ctx context.Context, entityUuid string, req *mdl.RemoveCertificateRequestDto) (*mdl.RemoveCertificateResponseDto, error)

	// GenerateCsrLocation produces a CSR scoped to the location.
	GenerateCsrLocation(ctx context.Context, entityUuid string, req *mdl.GenerateCsrRequestDto) (*mdl.GenerateCsrResponseDto, error)
}
