package notification

import (
	"errors"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/notification/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the route prefix every endpoint mounts under.
const DefaultBasePath = "/v1/notificationProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of
// the "notification" connector interface.
const InterfaceVersion = shared.VersionV1

// FunctionGroupCode is the canonical code emitted in /v1 info, pulled from
// the generated FunctionGroupCode enum. Matches the path token.
const FunctionGroupCode = string(mdl.FUNCTIONGROUPCODE_NOTIFICATION_PROVIDER)

// Handler adapts a Provider implementation (and optional attribute providers)
// to an HTTP surface mountable on a shared.Connector. Implements both
// shared.Registrable (Mount + Interface) and shared.V1Reporter (FunctionGroup).
type Handler struct {
	handlerbase.Config

	provider     Provider
	kindAttrs    KindAttributeProvider
	mappingAttrs MappingAttributeProvider

}

// NewHandler builds a Handler for the given Provider.
func NewHandler(p Provider, opts ...Option) (*Handler, error) {
	if p == nil {
		return nil, errors.New("notification: provider must not be nil")
	}
	h := &Handler{
		Config:   handlerbase.NewConfig(DefaultBasePath),
		provider: p,
	}
	if err := handlerbase.ApplyOptions(h, opts, "notification"); err != nil {
		return nil, err
	}
	return h, nil
}

// Interface satisfies shared.Registrable.
func (h *Handler) Interface() shared.InterfaceInfo {
	return shared.InterfaceInfo{
		Code:    shared.InterfaceCodeNotification,
		Version: InterfaceVersion,
	}
}

// FunctionGroup implements shared.V1Reporter. Endpoints mirror the routes
// mounted by Mount.
func (h *Handler) FunctionGroup() shared.V1FunctionGroup {
	base := h.BasePath

	endpoints := []shared.V1Endpoint{
		// Generic kind attributes.
		{Name: "listAttributeDefinitions", Method: http.MethodGet, Context: base + "/{kind}/attributes"},
		{Name: "validateAttributes", Method: http.MethodPost, Context: base + "/{kind}/attributes/validate"},
		{Name: "listMappingAttributes", Method: http.MethodGet, Context: base + "/{kind}/attributes/mapping"},

		// Notification instance management.
		{Name: "listNotificationInstances", Method: http.MethodGet, Context: base + "/notifications"},
		{Name: "createNotificationInstance", Method: http.MethodPost, Context: base + "/notifications"},
		{Name: "getNotificationInstance", Method: http.MethodGet, Context: base + "/notifications/{uuid}"},
		{Name: "updateNotificationInstance", Method: http.MethodPut, Context: base + "/notifications/{uuid}"},
		{Name: "removeNotificationInstance", Method: http.MethodDelete, Context: base + "/notifications/{uuid}"},
		{Name: "sendNotification", Method: http.MethodPost, Context: base + "/notifications/{uuid}/notify"},
	}

	return shared.V1FunctionGroup{
		FunctionGroupCode: FunctionGroupCode,
		Kinds:             shared.EnsureSlice(h.Kinds),
		EndPoints:         endpoints,
	}
}

// Mount attaches every Notification Provider route onto r.
//
// GET /v1/notificationProvider/{kind}/attributes (4 segs) conflicts with
// GET /v1/notificationProvider/notifications/{uuid} (4 segs) on the stdlib
// ServeMux — same swapped-literal/wildcard issue solved everywhere else by
// substituting the literal kind name. The 5-segment validate and mapping
// paths do not have a sibling literal at segment 5 so they mount with the
// {kind} wildcard directly.
func (h *Handler) Mount(r shared.Router) {
	base := h.BasePath

	handlerbase.MountPerKindAttributes(r, base, h.Kinds, h.listKindAttributesFor, nil)

	// Wildcard mounts (no 5-seg conflicts).
	r.Handle(http.MethodPost, base+"/{kind}/attributes/validate", h.validateKindAttributes)
	r.Handle(http.MethodGet, base+"/{kind}/attributes/mapping", h.listMappingAttributes)

	// Notification instance management.
	r.Handle(http.MethodGet, base+"/notifications", h.listNotificationInstances)
	r.Handle(http.MethodPost, base+"/notifications", h.createNotificationInstance)
	r.Handle(http.MethodGet, base+"/notifications/{uuid}", h.getNotificationInstance)
	r.Handle(http.MethodPut, base+"/notifications/{uuid}", h.updateNotificationInstance)
	r.Handle(http.MethodDelete, base+"/notifications/{uuid}", h.removeNotificationInstance)
	r.Handle(http.MethodPost, base+"/notifications/{uuid}/notify", h.sendNotification)
}
