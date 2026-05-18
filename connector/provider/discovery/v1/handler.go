package discovery

import (
	"errors"
	"fmt"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the route prefix discovery-specific endpoints mount under.
const DefaultBasePath = "/v1/discoveryProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of
// the "discovery" connector interface, using the SDK-wide "vN" convention.
const InterfaceVersion = shared.VersionV1

// FunctionGroupCode is the canonical code emitted in /v1 info for discovery,
// pulled from the generated FunctionGroupCode enum.
const FunctionGroupCode = string(mdl.FUNCTIONGROUPCODE_DISCOVERY_PROVIDER)

// Handler adapts a Provider implementation (and optional AttributeProvider)
// to an HTTP surface mountable on a shared.Connector. Implements both
// shared.Registrable (via Mount + Interface) and shared.V1Reporter (via
// FunctionGroup) so it appears in /v1 listSupportedFunctions.
//
// Construct with NewHandler; mount via shared.Register(handler) on the
// Connector. Goroutine-safe once constructed.
type Handler struct {
	handlerbase.Config

	provider Provider
	attrs    AttributeProvider
	kinds    []string
}

// NewHandler builds a Handler for the given Provider.
func NewHandler(p Provider, opts ...Option) (*Handler, error) {
	if p == nil {
		return nil, errors.New("discovery: provider must not be nil")
	}
	h := &Handler{
		Config:   handlerbase.NewConfig(DefaultBasePath),
		provider: p,
	}
	for _, opt := range opts {
		if err := opt(h); err != nil {
			return nil, fmt.Errorf("discovery: apply option: %w", err)
		}
	}
	return h, nil
}

// Interface reports the discovery interface for /v2/info. Discovery is a v1
// spec but the /v2/info wire shape still expects an entry per implemented
// interface — the Version field captures the spec generation.
func (h *Handler) Interface() shared.InterfaceInfo {
	return shared.InterfaceInfo{
		Code:    shared.InterfaceCodeDiscovery,
		Version: InterfaceVersion,
	}
}

// FunctionGroup implements shared.V1Reporter. Endpoints listed mirror the
// routes mounted by Mount, including the kind-scoped attribute endpoints.
// Shared endpoints (/v1, /v1/health) are intentionally omitted — add them
// via shared.WithExtraEndpoints if the deployment requires it.
func (h *Handler) FunctionGroup() shared.V1FunctionGroup {
	endpoints := []shared.V1Endpoint{
		{Name: "listAttributeDefinitions", Method: http.MethodGet, Context: "/v1/" + FunctionGroupCode + "/{kind}/attributes"},
		{Name: "validateAttributes", Method: http.MethodPost, Context: "/v1/" + FunctionGroupCode + "/{kind}/attributes/validate"},
		{Name: "discoverCertificate", Method: http.MethodPost, Context: h.BasePath + "/discover"},
		{Name: "getDiscovery", Method: http.MethodPost, Context: h.BasePath + "/discover/{uuid}"},
		{Name: "deleteDiscovery", Method: http.MethodDelete, Context: h.BasePath + "/discover/{uuid}"},
	}
	kinds := h.kinds
	if kinds == nil {
		kinds = []string{}
	}
	return shared.V1FunctionGroup{
		FunctionGroupCode: FunctionGroupCode,
		Kinds:             kinds,
		EndPoints:         endpoints,
	}
}

// Mount attaches every Discovery Provider v1 route onto r.
//
// Attribute endpoints are spec-shared across all v1 providers via the
// /v1/{functionalGroup}/{kind}/attributes(/validate) template, but we mount
// them with the literal FunctionGroupCode substituted so multiple v1
// providers (e.g. discovery + authority) can coexist in the same Connector
// without colliding on the {functionalGroup} wildcard. stdlib http.ServeMux
// would otherwise panic on the duplicate pattern at startup.
func (h *Handler) Mount(r shared.Router) {
	base := h.BasePath
	r.Handle(http.MethodPost, base+"/discover", h.discoverCertificate)
	r.Handle(http.MethodPost, base+"/discover/{uuid}", h.getDiscovery)
	r.Handle(http.MethodDelete, base+"/discover/{uuid}", h.deleteDiscovery)

	r.Handle(http.MethodGet, "/v1/"+FunctionGroupCode+"/{kind}/attributes", h.listAttributes)
	r.Handle(http.MethodPost, "/v1/"+FunctionGroupCode+"/{kind}/attributes/validate", h.validateAttributes)
}
