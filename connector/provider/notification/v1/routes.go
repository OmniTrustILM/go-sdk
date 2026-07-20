package notification

import (
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/notification/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const (
	eventListNotificationInstances  = "list_notification_instances"
	eventCreateNotificationInstance = "create_notification_instance"
	eventGetNotificationInstance    = "get_notification_instance"
	eventUpdateNotificationInstance = "update_notification_instance"
	eventRemoveNotificationInstance = "remove_notification_instance"
	eventSendNotification           = "send_notification"
	eventListKindAttributes         = "list_kind_attributes"
	eventValidateKindAttributes     = "validate_kind_attributes"
	eventListMappingAttributes      = "list_mapping_attributes"
)

// --- Notification instance management ------------------------------------

func (h *Handler) listNotificationInstances(w http.ResponseWriter, r *http.Request) {
	out, err := h.provider.ListNotificationInstances(r.Context())
	shared.EmitEvent(r.Context(), eventListNotificationInstances, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listNotificationInstances response", "err", writeErr)
	}
}

func (h *Handler) createNotificationInstance(w http.ResponseWriter, r *http.Request) {
	var in mdl.NotificationProviderInstanceRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventCreateNotificationInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.CreateNotificationInstance(r.Context(), &in)
	shared.EmitEvent(r.Context(), eventCreateNotificationInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write createNotificationInstance response", "err", writeErr)
	}
}

func (h *Handler) getNotificationInstance(w http.ResponseWriter, r *http.Request) {
	id, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	out, err := h.provider.GetNotificationInstance(r.Context(), id)
	shared.EmitEvent(r.Context(), eventGetNotificationInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getNotificationInstance response", "err", writeErr)
	}
}

func (h *Handler) updateNotificationInstance(w http.ResponseWriter, r *http.Request) {
	id, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	var in mdl.NotificationProviderInstanceRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventUpdateNotificationInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.UpdateNotificationInstance(r.Context(), id, &in)
	shared.EmitEvent(r.Context(), eventUpdateNotificationInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write updateNotificationInstance response", "err", writeErr)
	}
}

func (h *Handler) removeNotificationInstance(w http.ResponseWriter, r *http.Request) {
	id, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	if err := h.provider.RemoveNotificationInstance(r.Context(), id); err != nil {
		shared.EmitEvent(r.Context(), eventRemoveNotificationInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventRemoveNotificationInstance, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) sendNotification(w http.ResponseWriter, r *http.Request) {
	id, ok := shared.RequirePathValue(w, r, "uuid")
	if !ok {
		return
	}
	var in mdl.NotificationProviderNotifyRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventSendNotification, err)
		shared.RenderError(w, r, err)
		return
	}
	if err := h.provider.SendNotification(r.Context(), id, &in); err != nil {
		shared.EmitEvent(r.Context(), eventSendNotification, err)
		shared.RenderError(w, r, err)
		return
	}
	shared.EmitEvent(r.Context(), eventSendNotification, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Per-literal-kind attribute routes -----------------------------------

func (h *Handler) listKindAttributesFor(w http.ResponseWriter, r *http.Request, kind string) {
	var out []mdl.BaseAttributeDto
	var err error
	if h.kindAttrs != nil {
		out, err = h.kindAttrs.Attributes(r.Context(), kind)
	}
	shared.EmitEvent(r.Context(), eventListKindAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listKindAttributes response", "err", writeErr)
	}
}

// --- Wildcard-kind attribute routes (5-seg paths, no mux conflict) ------

// POST /v1/notificationProvider/{kind}/attributes/validate
func (h *Handler) validateKindAttributes(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		shared.EmitEvent(r.Context(), eventValidateKindAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if h.kindAttrs == nil {
		shared.EmitEvent(r.Context(), eventValidateKindAttributes, nil)
		w.WriteHeader(http.StatusOK)
		return
	}
	vErrs, err := h.kindAttrs.ValidateAttributes(r.Context(), kind, attrs)
	shared.EmitEvent(r.Context(), eventValidateKindAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if len(vErrs) > 0 {
		shared.WriteV1ValidationErrors(w, r, vErrs)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// GET /v1/notificationProvider/{kind}/attributes/mapping
func (h *Handler) listMappingAttributes(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	var out []mdl.DataAttribute
	var err error
	if h.mappingAttrs != nil {
		out, err = h.mappingAttrs.MappingAttributes(r.Context(), kind)
	}
	shared.EmitEvent(r.Context(), eventListMappingAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, shared.EnsureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listMappingAttributes response", "err", writeErr)
	}
}
