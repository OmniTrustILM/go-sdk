package compliance

import (
	"errors"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/compliance/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the route prefix for compliance v2 management routes.
// Note the path token differs from FunctionGroupCode below.
const DefaultBasePath = "/v2/complianceProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of
// the "compliance" connector interface.
const InterfaceVersion = shared.VersionV2

// FunctionGroupCode is the canonical code emitted in /v1 info for this
// provider, pulled from the generated FunctionGroupCode enum. Differs from
// the path token "complianceProvider" — same situation as legacy authority.
const FunctionGroupCode = string(mdl.FUNCTIONGROUPCODE_COMPLIANCE_PROVIDER_V2)

// Handler adapts a Provider implementation (and optional KindAttributeProvider)
// to an HTTP surface mountable on a shared.Connector. Implements both
// shared.Registrable (Mount + Interface) and shared.V1Reporter (FunctionGroup)
// so it appears in /v1 listSupportedFunctions.
type Handler struct {
	handlerbase.Config

	provider  Provider
	kindAttrs KindAttributeProvider
	kinds     []string
}

// NewHandler builds a Handler for the given Provider.
func NewHandler(p Provider, opts ...Option) (*Handler, error) {
	if p == nil {
		return nil, errors.New("compliance v2: provider must not be nil")
	}
	h := &Handler{
		Config:   handlerbase.NewConfig(DefaultBasePath),
		provider: p,
	}
	if err := handlerbase.ApplyOptions(h, opts, "compliance v2"); err != nil {
		return nil, err
	}
	return h, nil
}

// Interface satisfies shared.Registrable.
func (h *Handler) Interface() shared.InterfaceInfo {
	return h.InterfaceInfo(shared.InterfaceCodeCompliance, InterfaceVersion)
}

// FunctionGroup implements shared.V1Reporter. Endpoints listed mirror the
// routes mounted by Mount, including the kind-scoped attribute endpoints
// under the v1 attribute path namespace.
//
// /v1 and /v1/health are intentionally omitted — add via shared.WithExtraEndpoints
// if the deployment convention requires it.
func (h *Handler) FunctionGroup() shared.V1FunctionGroup {
	base := h.BasePath

	endpoints := []shared.V1Endpoint{
		// v1 generic kind attributes.
		{Name: "listAttributeDefinitions", Method: http.MethodGet, Context: "/v1/" + FunctionGroupCode + "/{kind}/attributes"},
		{Name: "validateAttributes", Method: http.MethodPost, Context: "/v1/" + FunctionGroupCode + "/{kind}/attributes/validate"},

		// v2 compliance management.
		{Name: "getRules", Method: http.MethodGet, Context: base + "/{kind}/rules"},
		{Name: "getRulesBatch", Method: http.MethodPost, Context: base + "/{kind}/rules"},
		{Name: "getRule", Method: http.MethodGet, Context: base + "/{kind}/rules/{ruleUuid}"},
		{Name: "getGroups", Method: http.MethodGet, Context: base + "/{kind}/groups"},
		{Name: "getGroup", Method: http.MethodGet, Context: base + "/{kind}/groups/{groupUuid}"},
		{Name: "getGroupRules", Method: http.MethodGet, Context: base + "/{kind}/groups/{groupUuid}/rules"},
		{Name: "checkCompliance", Method: http.MethodPost, Context: base + "/{kind}/compliance"},
	}

	return shared.V1FunctionGroup{
		FunctionGroupCode: FunctionGroupCode,
		Kinds:             shared.EnsureSlice(h.Kinds),
		EndPoints:         endpoints,
	}
}

// Mount attaches every Compliance Provider v2 route onto r.
//
// v2 compliance routes use {kind} as a wildcard at the same segment position
// across all endpoints, so the stdlib ServeMux distinguishes them by what
// follows — no collision. The v1 attribute endpoints are mounted under the
// literal FunctionGroupCode segment per the SDK convention; multiple
// v1-family providers can coexist on the same Connector this way.
func (h *Handler) Mount(r shared.Router) {
	base := h.BasePath

	// v1 generic kind attributes — literal FunctionGroupCode (no wildcard
	// substitution) to avoid colliding with other v1-family providers.
	r.Handle(http.MethodGet, "/v1/"+FunctionGroupCode+"/{kind}/attributes", h.listKindAttributes)
	r.Handle(http.MethodPost, "/v1/"+FunctionGroupCode+"/{kind}/attributes/validate", h.validateKindAttributes)

	// v2 compliance management.
	r.Handle(http.MethodGet, base+"/{kind}/rules", h.getRules)
	r.Handle(http.MethodPost, base+"/{kind}/rules", h.getRulesBatch)
	r.Handle(http.MethodGet, base+"/{kind}/rules/{ruleUuid}", h.getRule)
	r.Handle(http.MethodGet, base+"/{kind}/groups", h.getGroups)
	r.Handle(http.MethodGet, base+"/{kind}/groups/{groupUuid}", h.getGroup)
	r.Handle(http.MethodGet, base+"/{kind}/groups/{groupUuid}/rules", h.getGroupRules)
	r.Handle(http.MethodPost, base+"/{kind}/compliance", h.checkCompliance)
}
