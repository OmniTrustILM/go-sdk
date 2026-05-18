package authority

import (
	"errors"
	"fmt"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the prefix used for the /v1 authority management routes.
// Certificate management routes mount under DefaultBasePathV2 (different
// version prefix, same provider).
const (
	DefaultBasePath   = "/v1/authorityProvider"
	DefaultBasePathV2 = "/v2/authorityProvider"
)

// InterfaceVersion is reported via /v2/info as the implemented version of
// the "authority" connector interface. Authority v2 advertises itself as v2.
const InterfaceVersion = shared.VersionV2

// FunctionGroupCode is the canonical code emitted in /v1 info for the
// authority function group, pulled from the generated FunctionGroupCode
// enum.
const FunctionGroupCode = string(mdl.FUNCTIONGROUPCODE_AUTHORITY_PROVIDER)

// Handler adapts a Provider implementation (and optional attribute providers)
// to an HTTP surface mountable on a shared.Connector. Implements both
// shared.Registrable (Mount + Interface) and shared.V1Reporter (FunctionGroup)
// so it appears in /v1 listSupportedFunctions next to other v1-family
// providers.
type Handler struct {
	handlerbase.Config

	provider Provider

	kindAttrs      KindAttributeProvider
	raProfileAttrs RAProfileAttributeProvider
	issueAttrs     IssueCertificateAttributeProvider
	revokeAttrs    RevokeCertificateAttributeProvider

	kinds      []string
	basePathV2 string
}

// NewHandler builds a Handler for the given Provider.
func NewHandler(p Provider, opts ...Option) (*Handler, error) {
	if p == nil {
		return nil, errors.New("authority: provider must not be nil")
	}
	h := &Handler{
		Config:     handlerbase.NewConfig(DefaultBasePath),
		provider:   p,
		basePathV2: DefaultBasePathV2,
	}
	for _, opt := range opts {
		if err := opt(h); err != nil {
			return nil, fmt.Errorf("authority: apply option: %w", err)
		}
	}
	return h, nil
}

// Interface satisfies shared.Registrable. Reports the "authority" interface
// at version v2.
func (h *Handler) Interface() shared.InterfaceInfo {
	return shared.InterfaceInfo{
		Code:    shared.InterfaceCodeAuthority,
		Version: InterfaceVersion,
	}
}

// FunctionGroup implements shared.V1Reporter. Endpoints listed mirror the
// routes mounted by Mount. The kind-scoped attribute endpoints render with
// the literal FunctionGroupCode substituted into the path so multi-provider
// connectors do not collide on the {functionalGroup} wildcard.
//
// /v1 and /v1/health are intentionally omitted — add via shared.WithExtraEndpoints
// if the deployment convention requires it.
func (h *Handler) FunctionGroup() shared.V1FunctionGroup {
	base := h.BasePath
	baseV2 := h.basePathV2

	endpoints := []shared.V1Endpoint{
		// Generic kind attributes.
		{Name: "listAttributeDefinitions", Method: http.MethodGet, Context: "/v1/" + FunctionGroupCode + "/{kind}/attributes"},
		{Name: "validateAttributes", Method: http.MethodPost, Context: "/v1/" + FunctionGroupCode + "/{kind}/attributes/validate"},

		// Authority management.
		{Name: "listAuthorityInstances", Method: http.MethodGet, Context: base + "/authorities"},
		{Name: "createAuthorityInstance", Method: http.MethodPost, Context: base + "/authorities"},
		{Name: "getAuthorityInstance", Method: http.MethodGet, Context: base + "/authorities/{uuid}"},
		{Name: "updateAuthorityInstance", Method: http.MethodPost, Context: base + "/authorities/{uuid}"},
		{Name: "removeAuthorityInstance", Method: http.MethodDelete, Context: base + "/authorities/{uuid}"},
		{Name: "getConnection", Method: http.MethodGet, Context: base + "/authorities/{uuid}/connect"},
		{Name: "getCaCertificates", Method: http.MethodPost, Context: base + "/authorities/{uuid}/caCertificates"},
		{Name: "getCrl", Method: http.MethodPost, Context: base + "/authorities/{uuid}/crl"},

		// RA Profile attributes.
		{Name: "listRAProfileAttributes", Method: http.MethodGet, Context: base + "/authorities/{uuid}/raProfile/attributes"},
		{Name: "validateRAProfileAttributes", Method: http.MethodPost, Context: base + "/authorities/{uuid}/raProfile/attributes/validate"},

		// Certificate management (v2).
		{Name: "issueCertificate", Method: http.MethodPost, Context: baseV2 + "/authorities/{uuid}/certificates/issue"},
		{Name: "renewCertificate", Method: http.MethodPost, Context: baseV2 + "/authorities/{uuid}/certificates/renew"},
		{Name: "revokeCertificate", Method: http.MethodPost, Context: baseV2 + "/authorities/{uuid}/certificates/revoke"},
		{Name: "identifyCertificate", Method: http.MethodPost, Context: baseV2 + "/authorities/{uuid}/certificates/identify"},
		{Name: "listIssueCertificateAttributes", Method: http.MethodGet, Context: baseV2 + "/authorities/{uuid}/certificates/issue/attributes"},
		{Name: "validateIssueCertificateAttributes", Method: http.MethodPost, Context: baseV2 + "/authorities/{uuid}/certificates/issue/attributes/validate"},
		{Name: "listRevokeCertificateAttributes", Method: http.MethodGet, Context: baseV2 + "/authorities/{uuid}/certificates/revoke/attributes"},
		{Name: "validateRevokeCertificateAttributes", Method: http.MethodPost, Context: baseV2 + "/authorities/{uuid}/certificates/revoke/attributes/validate"},
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

// Mount attaches every Authority Provider v2 route onto r. The generic
// kind-scoped attribute endpoints are mounted once per declared kind with
// the kind name as a literal path segment. This avoids the stdlib ServeMux
// conflict that would otherwise occur between
//
//	GET /v1/authorityProvider/{kind}/attributes
//	GET /v1/authorityProvider/authorities/{uuid}
//
// — both have four segments with one literal and one wildcard at swapped
// positions, and neither is more specific than the other (per Go 1.22
// ServeMux precedence rules), so they collide on a path like
// "/v1/authorityProvider/authorities/attributes" and the registration panics.
//
// Use WithKinds to declare the supported kinds. With no kinds declared, no
// kind-attribute endpoint is mounted.
func (h *Handler) Mount(r shared.Router) {
	base := h.BasePath
	baseV2 := h.basePathV2

	// Generic kind attributes, mounted per literal kind to avoid the
	// authorities-vs-{kind} wildcard conflict described above.
	for _, k := range h.kinds {
		kind := k // capture for closure
		listPath := "/v1/" + FunctionGroupCode + "/" + kind + "/attributes"
		validatePath := listPath + "/validate"
		r.Handle(http.MethodGet, listPath, func(w http.ResponseWriter, r *http.Request) {
			h.listKindAttributesFor(w, r, kind)
		})
		r.Handle(http.MethodPost, validatePath, func(w http.ResponseWriter, r *http.Request) {
			h.validateKindAttributesFor(w, r, kind)
		})
	}

	// Authority management.
	r.Handle(http.MethodGet, base+"/authorities", h.listAuthorityInstances)
	r.Handle(http.MethodPost, base+"/authorities", h.createAuthorityInstance)
	r.Handle(http.MethodGet, base+"/authorities/{uuid}", h.getAuthorityInstance)
	r.Handle(http.MethodPost, base+"/authorities/{uuid}", h.updateAuthorityInstance)
	r.Handle(http.MethodDelete, base+"/authorities/{uuid}", h.removeAuthorityInstance)
	r.Handle(http.MethodGet, base+"/authorities/{uuid}/connect", h.getConnection)
	r.Handle(http.MethodPost, base+"/authorities/{uuid}/caCertificates", h.getCaCertificates)
	r.Handle(http.MethodPost, base+"/authorities/{uuid}/crl", h.getCrl)

	// RA Profile attributes.
	r.Handle(http.MethodGet, base+"/authorities/{uuid}/raProfile/attributes", h.listRAProfileAttributes)
	r.Handle(http.MethodPost, base+"/authorities/{uuid}/raProfile/attributes/validate", h.validateRAProfileAttributes)

	// Certificate management.
	r.Handle(http.MethodPost, baseV2+"/authorities/{uuid}/certificates/issue", h.issueCertificate)
	r.Handle(http.MethodPost, baseV2+"/authorities/{uuid}/certificates/renew", h.renewCertificate)
	r.Handle(http.MethodPost, baseV2+"/authorities/{uuid}/certificates/revoke", h.revokeCertificate)
	r.Handle(http.MethodPost, baseV2+"/authorities/{uuid}/certificates/identify", h.identifyCertificate)
	r.Handle(http.MethodGet, baseV2+"/authorities/{uuid}/certificates/issue/attributes", h.listIssueCertificateAttributes)
	r.Handle(http.MethodPost, baseV2+"/authorities/{uuid}/certificates/issue/attributes/validate", h.validateIssueCertificateAttributes)
	r.Handle(http.MethodGet, baseV2+"/authorities/{uuid}/certificates/revoke/attributes", h.listRevokeCertificateAttributes)
	r.Handle(http.MethodPost, baseV2+"/authorities/{uuid}/certificates/revoke/attributes/validate", h.validateRevokeCertificateAttributes)
}
