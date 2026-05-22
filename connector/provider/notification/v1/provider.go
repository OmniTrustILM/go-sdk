// Package notification provides the HTTP server adapter for the Notification
// Provider API. Connector authors implement the Provider interface (and any
// subset of the optional attribute provider sub-interfaces) and register
// the resulting Handler with shared.Connector.
//
// Notification is a v1-family info/health spec: it uses /v1
// listSupportedFunctions for info and /v1/health for health checks. Wire
// shared.WithErrorRenderer(shared.WriteV1Error) on the Connector.
package notification

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/notification/v1"
)

// Provider is the core business contract every Notification Provider
// connector must implement. Methods correspond 1:1 to the operations in
// notification.json.
//
// Returned errors should be *shared.Error. Plain errors render as 500
// INTERNAL_ERROR via WriteV1Error.
type Provider interface {
	ListNotificationInstances(ctx context.Context) ([]mdl.NotificationProviderInstanceDto, error)
	CreateNotificationInstance(ctx context.Context, req *mdl.NotificationProviderInstanceRequestDto) (*mdl.NotificationProviderInstanceDto, error)
	GetNotificationInstance(ctx context.Context, uuid string) (*mdl.NotificationProviderInstanceDto, error)
	UpdateNotificationInstance(ctx context.Context, uuid string, req *mdl.NotificationProviderInstanceRequestDto) (*mdl.NotificationProviderInstanceDto, error)
	RemoveNotificationInstance(ctx context.Context, uuid string) error

	// SendNotification delivers the notification described by req via the
	// given instance. Returns nil on success; the spec defines 204 No
	// Content for the success response so the handler writes 204 on nil.
	SendNotification(ctx context.Context, uuid string, req *mdl.NotificationProviderNotifyRequestDto) error
}
