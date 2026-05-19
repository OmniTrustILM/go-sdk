// Package compliance provides the HTTP server adapter for the Compliance
// Provider v1 API. Connector authors implement the Provider interface (and
// optionally the KindAttributeProvider sub-interface) and register the
// resulting Handler with shared.Connector.
//
// Compliance v1 is a v1-family info/health spec: it uses /v1 listSupportedFunctions
// for info and /v1/health for health checks. Unlike legacy authority or
// compliance v2, the function group code "complianceProvider" matches the
// path token in the URL — no mismatch.
//
// Error responses follow the v1 wire shape (ErrorMessageDto /
// AuthenticationServiceExceptionDto / []string for 422); wire
// shared.WithErrorRenderer(shared.WriteV1Error) on the Connector.
package compliance

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/compliance/v1"
)

// Provider is the core business contract every Compliance Provider v1
// connector must implement. Methods correspond 1:1 to the operations in
// compliance-v1.json.
//
// Returned errors should be *shared.Error. Plain errors are rendered as 500
// INTERNAL_ERROR via WriteV1Error.
type Provider interface {
	// GetRules returns every compliance rule supported by the given kind.
	GetRules(ctx context.Context, kind string) ([]mdl.ComplianceRulesResponseDto, error)

	// GetGroups returns every compliance group supported by the given kind.
	GetGroups(ctx context.Context, kind string) ([]mdl.ComplianceGroupsResponseDto, error)

	// GetGroupRules returns every rule that belongs to the given group.
	GetGroupRules(ctx context.Context, kind, groupUuid string) ([]mdl.ComplianceRulesResponseDto, error)

	// CheckCompliance evaluates the supplied certificate against the
	// requested rules and returns the per-rule status.
	CheckCompliance(ctx context.Context, kind string, req *mdl.ComplianceRequestDto) (*mdl.ComplianceResponseDto, error)
}
