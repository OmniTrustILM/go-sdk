package compliance

import (
	"errors"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/compliance/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the route prefix every endpoint mounts under.
const DefaultBasePath = "/v1/complianceProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of
// the "compliance" connector interface.
const InterfaceVersion = shared.VersionV1

// FunctionGroupCode is the canonical code emitted in /v1 info, pulled from
// the generated FunctionGroupCode enum. Matches the path token (no legacy
// mismatch).
const FunctionGroupCode = string(mdl.FUNCTIONGROUPCODE_COMPLIANCE_PROVIDER)

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
		return nil, errors.New("compliance v1: provider must not be nil")
	}
	h := &Handler{
		Config:   handlerbase.NewConfig(DefaultBasePath),
		provider: p,
	}
	if err := handlerbase.ApplyOptions(h, opts, "compliance v1"); err != nil {
		return nil, err
	}
	return h, nil
}

// Interface satisfies shared.Registrable.
func (h *Handler) Interface() shared.InterfaceInfo {
	return h.InterfaceInfo(shared.InterfaceCodeCompliance, InterfaceVersion)
}

// FunctionGroup implements shared.V1Reporter. Endpoints listed mirror the
// routes mounted by Mount.
//
// /v1 and /v1/health are intentionally omitted — add via shared.WithExtraEndpoints
// if the deployment convention requires it.
func (h *Handler) FunctionGroup() shared.V1FunctionGroup {
	base := h.BasePath

	endpoints := []shared.V1Endpoint{
		// Generic kind attributes.
		{Name: "listAttributeDefinitions", Method: http.MethodGet, Context: base + "/{kind}/attributes"},
		{Name: "validateAttributes", Method: http.MethodPost, Context: base + "/{kind}/attributes/validate"},

		// Compliance management.
		{Name: "getRules", Method: http.MethodGet, Context: base + "/{kind}/rules"},
		{Name: "getGroups", Method: http.MethodGet, Context: base + "/{kind}/groups"},
		{Name: "getGroupRules", Method: http.MethodGet, Context: base + "/{kind}/groups/{uuid}"},
		{Name: "checkCompliance", Method: http.MethodPost, Context: base + "/{kind}/compliance"},
	}

	return shared.V1FunctionGroup{
		FunctionGroupCode: FunctionGroupCode,
		Kinds:             shared.EnsureSlice(h.Kinds),
		EndPoints:         endpoints,
	}
}

// Mount attaches every Compliance Provider v1 route onto r. All routes share
// the {kind} wildcard at segment 3 but differ in literal tails — stdlib
// ServeMux dispatches them without conflict.
func (h *Handler) Mount(r shared.Router) {
	base := h.BasePath

	r.Handle(http.MethodGet, base+"/{kind}/attributes", h.listKindAttributes)
	r.Handle(http.MethodPost, base+"/{kind}/attributes/validate", h.validateKindAttributes)

	r.Handle(http.MethodGet, base+"/{kind}/rules", h.getRules)
	r.Handle(http.MethodGet, base+"/{kind}/groups", h.getGroups)
	r.Handle(http.MethodGet, base+"/{kind}/groups/{uuid}", h.getGroupRules)
	r.Handle(http.MethodPost, base+"/{kind}/compliance", h.checkCompliance)
}
