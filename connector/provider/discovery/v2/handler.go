package discovery

import (
	"errors"
	"net/http"

	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the prefix for every Discovery Provider v2 route.
const DefaultBasePath = "/v2/discoveryProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of
// the "discovery" connector interface.
const InterfaceVersion = shared.VersionV2

// Handler mounts Discovery v2 routes. Shared info, health and metrics come from shared.Connector.
type Handler struct {
	handlerbase.Config
	provider Provider
}

// NewHandler builds a Handler for the given Provider.
func NewHandler(p Provider, opts ...Option) (*Handler, error) {
	if p == nil {
		return nil, errors.New("discovery v2: provider must not be nil")
	}
	h := &Handler{Config: handlerbase.NewConfig(DefaultBasePath), provider: p}
	if err := handlerbase.ApplyOptions(h, opts, "discovery v2"); err != nil {
		return nil, err
	}
	return h, nil
}

// Interface satisfies shared.Registrable. Reports the "discovery" interface
// at version v2.
func (h *Handler) Interface() shared.InterfaceInfo {
	return h.InterfaceInfo(shared.InterfaceCodeDiscovery, InterfaceVersion)
}

// Mount attaches every Discovery Provider v2 route onto r.
func (h *Handler) Mount(r shared.Router) {
	r.Handle(http.MethodPost, h.BasePath+"/discoveries/initiate", h.initiate)
	r.Handle(http.MethodPost, h.BasePath+"/discoveries/status", h.status)
	r.Handle(http.MethodPost, h.BasePath+"/discoveries/results", h.results)
	r.Handle(http.MethodPost, h.BasePath+"/discoveries/stop", h.stop)
	r.Handle(http.MethodPost, h.BasePath+"/discoveries/resume", h.resume)
	r.Handle(http.MethodPost, h.BasePath+"/discoveries/cancel", h.cancel)

	r.Handle(http.MethodGet, h.BasePath+"/resources", h.resources)
	r.Handle(http.MethodGet, h.BasePath+"/attributes", h.runAttributes)
	r.Handle(http.MethodGet, h.BasePath+"/{resource}/attributes", h.resourceAttributes)
}
