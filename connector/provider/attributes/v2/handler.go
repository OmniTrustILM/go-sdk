package attributes

import (
	"errors"
	"net/http"
	"strings"

	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// Handler serves the Attributes v2 API on the connector-global /v2/attributes
// prefix. It is a shared.Registrable; register it with shared.Register
// alongside a connector's functional-interface handler.
type Handler struct {
	handlerbase.Config
	reg *registry
}

// NewHandler builds an Attributes v2 handler from a static definition registry.
// connectorVersion is echoed in the GET /v2/attributes response so Core can
// detect a stale registry. The registry is self-validated (see Validate) and
// NewHandler fails fast — returning an error — on any inconsistency, so a
// misconfigured connector never starts serving.
func NewHandler(connectorVersion string, defs []Definition, opts ...Option) (*Handler, error) {
	if strings.TrimSpace(connectorVersion) == "" {
		return nil, errors.New("attributes: connectorVersion must not be blank (the registry response requires a build version for staleness detection)")
	}
	reg, err := buildRegistry(connectorVersion, defs)
	if err != nil {
		return nil, err
	}
	h := &Handler{
		Config: handlerbase.NewConfig(""), // routes are absolute, no base path
		reg:    reg,
	}
	if err := handlerbase.ApplyOptions(h, opts, "attributes"); err != nil {
		return nil, err
	}
	return h, nil
}

// Interface opts out of the /v2/info interfaces list by reporting an empty
// Code. The Attributes v2 surface is part of the common connector baseline
// (alongside info/health/metrics), not a distinct functional provider
// interface — and the interfaces ConnectorInterface enum has no "attributes"
// code, so advertising one would diverge from the wire contract. The routes
// are still mounted; they are simply not announced as a separate interface.
func (h *Handler) Interface() shared.InterfaceInfo {
	return shared.InterfaceInfo{}
}

// Mount registers the three routes at the connector-global /v2/attributes
// prefix (not under any functional-interface base path).
func (h *Handler) Mount(r shared.Router) {
	r.Handle(http.MethodGet, "/v2/attributes", h.listDefinitions)
	r.Handle(http.MethodGet, "/v2/attributes/{uuid}", h.getDefinition)
	r.Handle(http.MethodPost, "/v2/attributes/callback", h.attributeCallback)
}
