package authority

import (
	"errors"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the route prefix every endpoint mounts under. Legacy
// authority shares the path token with authority/v2 even though its function
// group code differs.
const DefaultBasePath = "/v1/authorityProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of the
// "authority" connector interface.
const InterfaceVersion = shared.VersionV1

// FunctionGroupCode is the canonical code emitted in /v1 info, pulled from
// the generated FunctionGroupCode enum. Note the legacyAuthorityProvider
// value differs from the path token "authorityProvider".
const FunctionGroupCode = string(mdl.FUNCTIONGROUPCODE_LEGACY_AUTHORITY_PROVIDER)

// Handler adapts a Provider implementation (and optional attribute providers)
// to an HTTP surface mountable on a shared.Connector. Implements both
// shared.Registrable (Mount + Interface) and shared.V1Reporter (FunctionGroup)
// so it appears in /v1 listSupportedFunctions.
type Handler struct {
	handlerbase.Config

	provider Provider

	kindAttrs      KindAttributeProvider
	raProfileAttrs RAProfileAttributeProvider
}

// NewHandler builds a Handler for the given Provider.
func NewHandler(p Provider, opts ...Option) (*Handler, error) {
	if p == nil {
		return nil, errors.New("authority v1: provider must not be nil")
	}
	h := &Handler{
		Config:   handlerbase.NewConfig(DefaultBasePath),
		provider: p,
	}
	if err := handlerbase.ApplyOptions(h, opts, "authority v1"); err != nil {
		return nil, err
	}
	return h, nil
}

// Interface satisfies shared.Registrable. Reports "authority" interface code
// at version v1 (legacy).
func (h *Handler) Interface() shared.InterfaceInfo {
	return shared.InterfaceInfo{
		Code:    shared.InterfaceCodeAuthority,
		Version: InterfaceVersion,
	}
}

// FunctionGroup implements shared.V1Reporter. Endpoints listed mirror the
// routes mounted by Mount. The kind-scoped attribute endpoints render with
// the literal path token "authorityProvider" in the context strings.
//
// /v1 and /v1/health are intentionally omitted — add via shared.WithExtraEndpoints
// if the deployment convention requires it.
func (h *Handler) FunctionGroup() shared.V1FunctionGroup {
	base := h.BasePath

	endpoints := []shared.V1Endpoint{
		// Generic kind attributes.
		{Name: "listAttributeDefinitions", Method: http.MethodGet, Context: base + "/{kind}/attributes"},
		{Name: "validateAttributes", Method: http.MethodPost, Context: base + "/{kind}/attributes/validate"},

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

		// End entity profile lookups.
		{Name: "listEntityProfiles", Method: http.MethodGet, Context: base + "/authorities/{uuid}/endEntityProfiles"},
		{Name: "listCertificateProfiles", Method: http.MethodGet, Context: base + "/authorities/{uuid}/endEntityProfiles/{endEntityProfileId}/certificateprofiles"},
		{Name: "listCAsInProfile", Method: http.MethodGet, Context: base + "/authorities/{uuid}/endEntityProfiles/{endEntityProfileId}/cas"},

		// End entity management.
		{Name: "listEndEntities", Method: http.MethodGet, Context: base + "/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/endEntities"},
		{Name: "createEndEntity", Method: http.MethodPost, Context: base + "/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/endEntities"},
		{Name: "getEndEntity", Method: http.MethodGet, Context: base + "/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/endEntities/{endEntityName}"},
		{Name: "updateEndEntity", Method: http.MethodPost, Context: base + "/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/endEntities/{endEntityName}"},
		{Name: "removeEndEntity", Method: http.MethodDelete, Context: base + "/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/endEntities/{endEntityName}"},
		{Name: "resetPassword", Method: http.MethodPut, Context: base + "/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/endEntities/{endEntityName}/resetPassword"},

		// Certificate management (under end-entity profile).
		{Name: "issueCertificate", Method: http.MethodPost, Context: base + "/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/certificates/issue"},
		{Name: "revokeCertificate", Method: http.MethodPost, Context: base + "/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/certificates/revoke"},
	}

	return shared.V1FunctionGroup{
		FunctionGroupCode: FunctionGroupCode,
		Kinds:             shared.EnsureSlice(h.Kinds),
		EndPoints:         endpoints,
	}
}

// Mount attaches every Authority Provider Legacy route onto r. Generic
// kind-scoped attribute endpoints are mounted once per declared kind with
// the kind name as a literal path segment — same ServeMux conflict reason
// as authority/v2 (see that package's Mount doc for details).
func (h *Handler) Mount(r shared.Router) {
	base := h.BasePath

	// Per-kind generic attribute endpoints.
	handlerbase.MountPerKindAttributes(r, base, h.Kinds, h.listKindAttributesFor, h.validateKindAttributesFor)

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

	// End-entity profile lookups.
	r.Handle(http.MethodGet, base+"/authorities/{uuid}/endEntityProfiles", h.listEntityProfiles)
	r.Handle(http.MethodGet, base+"/authorities/{uuid}/endEntityProfiles/{endEntityProfileId}/certificateprofiles", h.listCertificateProfiles)
	r.Handle(http.MethodGet, base+"/authorities/{uuid}/endEntityProfiles/{endEntityProfileId}/cas", h.listCAsInProfile)

	// End entity management. {endEntityProfileName} appears at the same path
	// position as {endEntityProfileId} in the routes above. Mux specificity
	// resolves them by what follows: literal "certificateprofiles" / "cas"
	// vs literal "endEntities".
	r.Handle(http.MethodGet, base+"/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/endEntities", h.listEndEntities)
	r.Handle(http.MethodPost, base+"/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/endEntities", h.createEndEntity)
	r.Handle(http.MethodGet, base+"/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/endEntities/{endEntityName}", h.getEndEntity)
	r.Handle(http.MethodPost, base+"/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/endEntities/{endEntityName}", h.updateEndEntity)
	r.Handle(http.MethodDelete, base+"/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/endEntities/{endEntityName}", h.removeEndEntity)
	r.Handle(http.MethodPut, base+"/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/endEntities/{endEntityName}/resetPassword", h.resetPassword)

	// Certificate management (under end-entity profile).
	r.Handle(http.MethodPost, base+"/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/certificates/issue", h.issueCertificate)
	r.Handle(http.MethodPost, base+"/authorities/{uuid}/endEntityProfiles/{endEntityProfileName}/certificates/revoke", h.revokeCertificate)
}
