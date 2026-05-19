// Package compliance provides the HTTP server adapter for the Compliance
// Provider v2 API. Connector authors implement the Provider interface (and
// optionally the KindAttributeProvider sub-interface) and register the
// resulting Handler with shared.Connector.
//
// Compliance v2 is a v1-family info/health spec: it uses /v1 listSupportedFunctions
// for info and /v1/health for health checks, while compliance management
// operations live under /v2/complianceProvider/{kind}/... The function group
// code reported in /v1 info is "complianceProviderV2" (per
// FUNCTIONGROUPCODE_COMPLIANCE_PROVIDER_V2), but the v2 route paths use the
// literal "complianceProvider" path token — a quirk of the spec that mirrors
// the legacy authority case. Two compliance versions cannot share a single
// mux (paths collide); either can coexist with non-compliance providers.
//
// Error responses follow the v1 wire shape (ErrorMessageDto /
// AuthenticationServiceExceptionDto / []string for 422); wire
// shared.WithErrorRenderer(shared.WriteV1Error) on the Connector.
package compliance

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/compliance/v2"
)

// Provider is the core business contract every Compliance Provider v2
// connector must implement. Methods correspond 1:1 to the operations in
// compliance-v2.json.
//
// Returned errors should be *shared.Error. Plain errors are rendered as 500
// INTERNAL_ERROR via WriteV1Error.
type Provider interface {
	// GetRules returns every compliance rule supported by the given kind.
	GetRules(ctx context.Context, kind string) ([]mdl.ComplianceRuleResponseDto, error)

	// GetRule returns a single rule by uuid.
	GetRule(ctx context.Context, kind, ruleUuid string) (*mdl.ComplianceRuleResponseDto, error)

	// GetRulesBatch returns rules and groups identified by the uuids in req.
	// WithGroupRules toggles whether group rules are inlined into the
	// response.
	GetRulesBatch(ctx context.Context, kind string, req *mdl.ComplianceRulesBatchRequestDto) (*mdl.ComplianceRulesBatchResponseDto, error)

	// GetGroups returns every compliance group supported by the given kind.
	GetGroups(ctx context.Context, kind string) ([]mdl.ComplianceGroupResponseDto, error)

	// GetGroup returns a single group by uuid.
	GetGroup(ctx context.Context, kind, groupUuid string) (*mdl.ComplianceGroupResponseDto, error)

	// GetGroupRules returns every rule that belongs to the given group.
	GetGroupRules(ctx context.Context, kind, groupUuid string) ([]mdl.ComplianceRuleResponseDto, error)

	// CheckCompliance evaluates the supplied resource payload against the
	// requested rules and groups, returning per-rule status.
	CheckCompliance(ctx context.Context, kind string, req *mdl.ComplianceRequestDtoV2) (*mdl.ComplianceResponseDtoV2, error)
}
