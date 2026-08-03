package authority

import (
	"errors"
	"net/http"

	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the prefix for every Authority Provider v3 route.
const DefaultBasePath = "/v3/authorityProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of
// the "authority" connector interface.
const InterfaceVersion = shared.VersionV3

// Handler adapts a Provider implementation (and optional attribute providers)
// to an HTTP surface mountable on a shared.Connector. Implements
// shared.Registrable (Mount + Interface). Unlike the v1-family providers it
// does NOT implement shared.V1Reporter — authority v3 is a v2-family spec
// with no /v1 listSupportedFunctions section.
type Handler struct {
	handlerbase.Config

	provider Provider

	authorityAttrs AuthorityAttributeProvider
	raProfileAttrs RAProfileAttributeProvider
	issueAttrs     IssueAttributeProvider
	revokeAttrs    RevokeAttributeProvider
	registerAttrs  RegisterAttributeProvider
	attributeDefs  AttributeDefinitionsProvider
}

// NewHandler builds a Handler for the given Provider.
func NewHandler(p Provider, opts ...Option) (*Handler, error) {
	if p == nil {
		return nil, errors.New("authority: provider must not be nil")
	}
	h := &Handler{
		Config:   handlerbase.NewConfig(DefaultBasePath),
		provider: p,
	}
	if err := handlerbase.ApplyOptions(h, opts, "authority"); err != nil {
		return nil, err
	}
	return h, nil
}

// Interface satisfies shared.Registrable. Reports the "authority" interface
// at version v3.
func (h *Handler) Interface() shared.InterfaceInfo {
	return h.InterfaceInfo(shared.InterfaceCodeAuthority, InterfaceVersion)
}

// Mount attaches every Authority Provider v3 route onto r. All paths are
// literal (v3 is stateless — no {uuid} or {kind} wildcards), so this
// provider composes with any other provider package on one mux without
// route conflicts.
func (h *Handler) Mount(r shared.Router) {
	base := h.BasePath

	// Certificate management: issue family.
	r.Handle(http.MethodPost, base+"/certificates/issue", h.issue)
	r.Handle(http.MethodPost, base+"/certificates/issue/status", h.issueStatus)
	r.Handle(http.MethodPost, base+"/certificates/issue/cancel", h.cancelIssue)
	r.Handle(http.MethodPost, base+"/certificates/issue/attributes", h.listIssueAttributes)
	r.Handle(http.MethodPost, base+"/certificates/renew", h.renew)

	// Certificate management: register family.
	r.Handle(http.MethodPost, base+"/certificates/register", h.register)
	r.Handle(http.MethodPost, base+"/certificates/register/status", h.registerStatus)
	r.Handle(http.MethodPost, base+"/certificates/register/cancel", h.cancelRegister)
	r.Handle(http.MethodPost, base+"/certificates/register/attributes", h.listRegisterAttributes)

	// Certificate management: revoke family.
	r.Handle(http.MethodPost, base+"/certificates/revoke", h.revoke)
	r.Handle(http.MethodPost, base+"/certificates/revoke/status", h.revokeStatus)
	r.Handle(http.MethodPost, base+"/certificates/revoke/cancel", h.cancelRevoke)
	r.Handle(http.MethodPost, base+"/certificates/revoke/attributes", h.listRevokeAttributes)

	// Certificate management: identify.
	r.Handle(http.MethodPost, base+"/certificates/identify", h.identify)

	// Authority management.
	r.Handle(http.MethodPost, base+"/authorities", h.checkAuthorityConnection)
	r.Handle(http.MethodPost, base+"/authorities/raProfile/attributes", h.listRAProfileAttributes)
	r.Handle(http.MethodPost, base+"/authorities/crl", h.getCrl)
	r.Handle(http.MethodPost, base+"/authorities/caCertificates", h.getCaCertificates)
	r.Handle(http.MethodGet, base+"/authorities/attributes", h.listAuthorityAttributes)

	// Connector-level Attributes API (spec tag "Connector Attributes v2").
	// Mounted at the connector-global /v2/attributes prefix, not under the
	// authority base path.
	r.Handle(http.MethodGet, "/v2/attributes", h.listDefinitions)
	r.Handle(http.MethodGet, "/v2/attributes/{uuid}", h.getDefinition)
	r.Handle(http.MethodPost, "/v2/attributes/callback", h.attributeCallback)
}
