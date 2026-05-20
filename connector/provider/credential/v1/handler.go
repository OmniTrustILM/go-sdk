package credential

import (
	"errors"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/credential/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the route prefix every endpoint mounts under.
const DefaultBasePath = "/v1/credentialProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of the
// "credential" connector interface (no such code exists in shared; the
// connector interface enum does not list credential — providers usually
// declare themselves only in /v1 info).
const InterfaceVersion = shared.VersionV1

// FunctionGroupCode is the canonical code emitted in /v1 info, pulled from
// the generated FunctionGroupCode enum. Matches the path token.
const FunctionGroupCode = string(mdl.FUNCTIONGROUPCODE_CREDENTIAL_PROVIDER)

// Handler adapts a Provider implementation to an HTTP surface mountable on
// a shared.Connector. Implements both shared.Registrable (Mount + Interface)
// and shared.V1Reporter (FunctionGroup).
type Handler struct {
	handlerbase.Config

	provider Provider
	kinds    []string
}

// NewHandler builds a Handler for the given Provider.
func NewHandler(p Provider, opts ...Option) (*Handler, error) {
	if p == nil {
		return nil, errors.New("credential: provider must not be nil")
	}
	h := &Handler{
		Config:   handlerbase.NewConfig(DefaultBasePath),
		provider: p,
	}
	if err := handlerbase.ApplyOptions(h, opts, "credential"); err != nil {
		return nil, err
	}
	return h, nil
}

// Interface satisfies shared.Registrable. Credential has no dedicated entry
// in shared.InterfaceCode* — the spec is exclusively v1-info-driven. We
// report under "credential" so a /v2/info-only deployment can still surface
// the provider when one is configured.
func (h *Handler) Interface() shared.InterfaceInfo {
	return shared.InterfaceInfo{
		Code:    "credential",
		Version: InterfaceVersion,
	}
}

// FunctionGroup implements shared.V1Reporter. Endpoints mirror the routes
// mounted by Mount.
func (h *Handler) FunctionGroup() shared.V1FunctionGroup {
	base := h.BasePath
	endpoints := []shared.V1Endpoint{
		{Name: "listAttributeDefinitions", Method: http.MethodGet, Context: base + "/{kind}/attributes"},
		{Name: "validateAttributes", Method: http.MethodPost, Context: base + "/{kind}/attributes/validate"},
	}
	return shared.V1FunctionGroup{
		FunctionGroupCode: FunctionGroupCode,
		Kinds:             shared.EnsureSlice(h.Kinds),
		EndPoints:         endpoints,
	}
}

// Mount attaches every Credential Provider route onto r. Two endpoints
// only — list and validate attribute definitions for a given kind.
func (h *Handler) Mount(r shared.Router) {
	base := h.BasePath
	r.Handle(http.MethodGet, base+"/{kind}/attributes", h.listAttributes)
	r.Handle(http.MethodPost, base+"/{kind}/attributes/validate", h.validateAttributes)
}
