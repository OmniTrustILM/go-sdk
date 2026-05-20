package entity

import (
	"errors"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the route prefix every endpoint mounts under.
const DefaultBasePath = "/v1/entityProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of
// the "entity" connector interface.
const InterfaceVersion = shared.VersionV1

// FunctionGroupCode is the canonical code emitted in /v1 info, pulled from
// the generated FunctionGroupCode enum. Matches the path token.
const FunctionGroupCode = string(mdl.FUNCTIONGROUPCODE_ENTITY_PROVIDER)

// Handler adapts a Provider implementation (and optional attribute providers)
// to an HTTP surface mountable on a shared.Connector. Implements both
// shared.Registrable (Mount + Interface) and shared.V1Reporter (FunctionGroup).
type Handler struct {
	handlerbase.Config

	provider Provider

	kindAttrs     KindAttributeProvider
	locationAttrs LocationAttributeProvider
	pushAttrs     PushCertificateAttributeProvider
	csrAttrs      GenerateCsrAttributeProvider

	kinds []string
}

// NewHandler builds a Handler for the given Provider.
func NewHandler(p Provider, opts ...Option) (*Handler, error) {
	if p == nil {
		return nil, errors.New("entity: provider must not be nil")
	}
	h := &Handler{
		Config:   handlerbase.NewConfig(DefaultBasePath),
		provider: p,
	}
	if err := handlerbase.ApplyOptions(h, opts, "entity"); err != nil {
		return nil, err
	}
	return h, nil
}

// Interface satisfies shared.Registrable.
func (h *Handler) Interface() shared.InterfaceInfo {
	return shared.InterfaceInfo{
		Code:    shared.InterfaceCodeEntity,
		Version: InterfaceVersion,
	}
}

// FunctionGroup implements shared.V1Reporter. Endpoints mirror the routes
// mounted by Mount.
func (h *Handler) FunctionGroup() shared.V1FunctionGroup {
	base := h.BasePath

	endpoints := []shared.V1Endpoint{
		// Generic kind attributes (template form with {kind} wildcard).
		{Name: "listAttributeDefinitions", Method: http.MethodGet, Context: base + "/{kind}/attributes"},
		{Name: "validateAttributes", Method: http.MethodPost, Context: base + "/{kind}/attributes/validate"},

		// Entity management.
		{Name: "listEntityInstances", Method: http.MethodGet, Context: base + "/entities"},
		{Name: "createEntityInstance", Method: http.MethodPost, Context: base + "/entities"},
		{Name: "getEntityInstance", Method: http.MethodGet, Context: base + "/entities/{entityUuid}"},
		{Name: "updateEntityInstance", Method: http.MethodPut, Context: base + "/entities/{entityUuid}"},
		{Name: "removeEntityInstance", Method: http.MethodDelete, Context: base + "/entities/{entityUuid}"},

		// Per-entity location attributes.
		{Name: "listLocationAttributes", Method: http.MethodGet, Context: base + "/entities/{entityUuid}/location/attributes"},
		{Name: "validateLocationAttributes", Method: http.MethodPost, Context: base + "/entities/{entityUuid}/location/attributes/validate"},

		// Location operations.
		{Name: "getLocationDetail", Method: http.MethodPost, Context: base + "/entities/{entityUuid}/locations"},
		{Name: "pushCertificateToLocation", Method: http.MethodPost, Context: base + "/entities/{entityUuid}/locations/push"},
		{Name: "removeCertificateFromLocation", Method: http.MethodPost, Context: base + "/entities/{entityUuid}/locations/remove"},
		{Name: "generateCsrLocation", Method: http.MethodPost, Context: base + "/entities/{entityUuid}/locations/csr"},

		// Per-entity push/csr attributes.
		{Name: "listPushCertificateAttributes", Method: http.MethodGet, Context: base + "/entities/{entityUuid}/locations/push/attributes"},
		{Name: "validatePushCertificateAttributes", Method: http.MethodPost, Context: base + "/entities/{entityUuid}/locations/push/attributes/validate"},
		{Name: "listGenerateCsrAttributes", Method: http.MethodGet, Context: base + "/entities/{entityUuid}/locations/csr/attributes"},
		{Name: "validateGenerateCsrAttributes", Method: http.MethodPost, Context: base + "/entities/{entityUuid}/locations/csr/attributes/validate"},
	}

	return shared.V1FunctionGroup{
		FunctionGroupCode: FunctionGroupCode,
		Kinds:             shared.EnsureSlice(h.kinds),
		EndPoints:         endpoints,
	}
}

// Mount attaches every Entity Provider route onto r.
//
// The generic kind-attribute endpoints are mounted once per declared kind
// with the kind name as a literal segment to avoid the stdlib ServeMux
// conflict between
//
//	GET /v1/entityProvider/{kind}/attributes
//	GET /v1/entityProvider/entities/{entityUuid}
//
// (same trick as authority/v2 and cryptography). The location sub-paths
// (/locations, /locations/push, /locations/remove, /locations/csr) coexist
// because each has a distinct literal tail.
func (h *Handler) Mount(r shared.Router) {
	base := h.BasePath

	// Per-literal-kind generic attributes.
	handlerbase.MountPerKindAttributes(r, base, h.kinds, h.listKindAttributesFor, h.validateKindAttributesFor)

	// Entity management.
	r.Handle(http.MethodGet, base+"/entities", h.listEntityInstances)
	r.Handle(http.MethodPost, base+"/entities", h.createEntityInstance)
	r.Handle(http.MethodGet, base+"/entities/{entityUuid}", h.getEntityInstance)
	r.Handle(http.MethodPut, base+"/entities/{entityUuid}", h.updateEntityInstance)
	r.Handle(http.MethodDelete, base+"/entities/{entityUuid}", h.removeEntityInstance)

	// Per-entity location attributes (single "/location" — note singular).
	r.Handle(http.MethodGet, base+"/entities/{entityUuid}/location/attributes", h.listLocationAttributes)
	r.Handle(http.MethodPost, base+"/entities/{entityUuid}/location/attributes/validate", h.validateLocationAttributes)

	// Location operations under /locations (plural).
	r.Handle(http.MethodPost, base+"/entities/{entityUuid}/locations", h.getLocationDetail)
	r.Handle(http.MethodPost, base+"/entities/{entityUuid}/locations/push", h.pushCertificateToLocation)
	r.Handle(http.MethodPost, base+"/entities/{entityUuid}/locations/remove", h.removeCertificateFromLocation)
	r.Handle(http.MethodPost, base+"/entities/{entityUuid}/locations/csr", h.generateCsrLocation)

	// Per-entity push/csr attributes.
	r.Handle(http.MethodGet, base+"/entities/{entityUuid}/locations/push/attributes", h.listPushCertificateAttributes)
	r.Handle(http.MethodPost, base+"/entities/{entityUuid}/locations/push/attributes/validate", h.validatePushCertificateAttributes)
	r.Handle(http.MethodGet, base+"/entities/{entityUuid}/locations/csr/attributes", h.listGenerateCsrAttributes)
	r.Handle(http.MethodPost, base+"/entities/{entityUuid}/locations/csr/attributes/validate", h.validateGenerateCsrAttributes)
}
