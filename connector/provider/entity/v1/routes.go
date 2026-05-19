package entity

import (
	"context"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const (
	eventListEntityInstances          = "list_entity_instances"
	eventCreateEntityInstance         = "create_entity_instance"
	eventGetEntityInstance            = "get_entity_instance"
	eventUpdateEntityInstance         = "update_entity_instance"
	eventRemoveEntityInstance         = "remove_entity_instance"
	eventGetLocationDetail            = "get_location_detail"
	eventPushCertificateToLocation    = "push_certificate_to_location"
	eventRemoveCertificateFromLoc     = "remove_certificate_from_location"
	eventGenerateCsrLocation          = "generate_csr_location"
	eventListKindAttributes           = "list_kind_attributes"
	eventValidateKindAttributes       = "validate_kind_attributes"
	eventListLocationAttributes       = "list_location_attributes"
	eventValidateLocationAttributes   = "validate_location_attributes"
	eventListPushCertAttributes       = "list_push_certificate_attributes"
	eventValidatePushCertAttributes   = "validate_push_certificate_attributes"
	eventListGenerateCsrAttributes    = "list_generate_csr_attributes"
	eventValidateGenerateCsrAttrs     = "validate_generate_csr_attributes"
)

func emit(ctx context.Context, event string, err error) {
	mc := shared.MetricsFromContext(ctx)
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	mc.IncConnectorEvent(event, outcome)
}

func ensureSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (h *Handler) requireEntityUUID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("entityUuid")
	if id == "" {
		shared.RenderError(w, r, ErrInvalidRequest.WithProperty("reason", "entityUuid is required"))
		return "", false
	}
	return id, true
}

// --- Entity instance management routes -----------------------------------

func (h *Handler) listEntityInstances(w http.ResponseWriter, r *http.Request) {
	out, err := h.provider.ListEntityInstances(r.Context())
	emit(r.Context(), eventListEntityInstances, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listEntityInstances response", "err", writeErr)
	}
}

func (h *Handler) createEntityInstance(w http.ResponseWriter, r *http.Request) {
	var in mdl.EntityInstanceRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventCreateEntityInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.CreateEntityInstance(r.Context(), &in)
	emit(r.Context(), eventCreateEntityInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write createEntityInstance response", "err", writeErr)
	}
}

func (h *Handler) getEntityInstance(w http.ResponseWriter, r *http.Request) {
	id, ok := h.requireEntityUUID(w, r)
	if !ok {
		return
	}
	out, err := h.provider.GetEntityInstance(r.Context(), id)
	emit(r.Context(), eventGetEntityInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getEntityInstance response", "err", writeErr)
	}
}

func (h *Handler) updateEntityInstance(w http.ResponseWriter, r *http.Request) {
	id, ok := h.requireEntityUUID(w, r)
	if !ok {
		return
	}
	var in mdl.EntityInstanceRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventUpdateEntityInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.UpdateEntityInstance(r.Context(), id, &in)
	emit(r.Context(), eventUpdateEntityInstance, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write updateEntityInstance response", "err", writeErr)
	}
}

func (h *Handler) removeEntityInstance(w http.ResponseWriter, r *http.Request) {
	id, ok := h.requireEntityUUID(w, r)
	if !ok {
		return
	}
	if err := h.provider.RemoveEntityInstance(r.Context(), id); err != nil {
		emit(r.Context(), eventRemoveEntityInstance, err)
		shared.RenderError(w, r, err)
		return
	}
	emit(r.Context(), eventRemoveEntityInstance, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Location operation routes -------------------------------------------

func (h *Handler) getLocationDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := h.requireEntityUUID(w, r)
	if !ok {
		return
	}
	var in mdl.LocationDetailRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventGetLocationDetail, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.GetLocationDetail(r.Context(), id, &in)
	emit(r.Context(), eventGetLocationDetail, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write getLocationDetail response", "err", writeErr)
	}
}

func (h *Handler) pushCertificateToLocation(w http.ResponseWriter, r *http.Request) {
	id, ok := h.requireEntityUUID(w, r)
	if !ok {
		return
	}
	var in mdl.PushCertificateRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventPushCertificateToLocation, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.PushCertificateToLocation(r.Context(), id, &in)
	emit(r.Context(), eventPushCertificateToLocation, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write pushCertificateToLocation response", "err", writeErr)
	}
}

func (h *Handler) removeCertificateFromLocation(w http.ResponseWriter, r *http.Request) {
	id, ok := h.requireEntityUUID(w, r)
	if !ok {
		return
	}
	var in mdl.RemoveCertificateRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventRemoveCertificateFromLoc, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.RemoveCertificateFromLocation(r.Context(), id, &in)
	emit(r.Context(), eventRemoveCertificateFromLoc, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write removeCertificateFromLocation response", "err", writeErr)
	}
}

func (h *Handler) generateCsrLocation(w http.ResponseWriter, r *http.Request) {
	id, ok := h.requireEntityUUID(w, r)
	if !ok {
		return
	}
	var in mdl.GenerateCsrRequestDto
	if err := shared.DecodeJSON(w, r, &in, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventGenerateCsrLocation, err)
		shared.RenderError(w, r, err)
		return
	}
	out, err := h.provider.GenerateCsrLocation(r.Context(), id, &in)
	emit(r.Context(), eventGenerateCsrLocation, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, out); writeErr != nil {
		h.LoggerFor(r).Error("write generateCsrLocation response", "err", writeErr)
	}
}

// --- Per-literal-kind attribute routes -----------------------------------

func (h *Handler) listKindAttributesFor(w http.ResponseWriter, r *http.Request, kind string) {
	var out []mdl.BaseAttributeDto
	var err error
	if h.kindAttrs != nil {
		out, err = h.kindAttrs.Attributes(r.Context(), kind)
	}
	emit(r.Context(), eventListKindAttributes, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
		h.LoggerFor(r).Error("write listKindAttributes response", "err", writeErr)
	}
}

func (h *Handler) validateKindAttributesFor(w http.ResponseWriter, r *http.Request, kind string) {
	var attrs []mdl.RequestAttribute
	if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
		emit(r.Context(), eventValidateKindAttributes, err)
		shared.RenderError(w, r, err)
		return
	}
	if h.kindAttrs == nil {
		emit(r.Context(), eventValidateKindAttributes, nil)
		w.WriteHeader(http.StatusOK)
		return
	}
	vErrs, err := h.kindAttrs.ValidateAttributes(r.Context(), kind, attrs)
	emit(r.Context(), eventValidateKindAttributes, err)
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

// --- Per-entity attribute helpers ----------------------------------------

func entityAttrList(
	h *Handler,
	event string,
	fn func(ctx context.Context, entityUuid string) ([]mdl.BaseAttributeDto, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := h.requireEntityUUID(w, r)
		if !ok {
			return
		}
		var out []mdl.BaseAttributeDto
		var err error
		if fn != nil {
			out, err = fn(r.Context(), id)
		}
		emit(r.Context(), event, err)
		if err != nil {
			shared.RenderError(w, r, err)
			return
		}
		if writeErr := shared.WriteJSON(w, http.StatusOK, ensureSlice(out)); writeErr != nil {
			h.LoggerFor(r).Error("write attribute list response", "err", writeErr, "event", event)
		}
	}
}

func entityAttrValidate(
	h *Handler,
	event string,
	fn func(ctx context.Context, entityUuid string, attrs []mdl.RequestAttribute) ([]string, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := h.requireEntityUUID(w, r)
		if !ok {
			return
		}
		var attrs []mdl.RequestAttribute
		if err := shared.DecodeJSON(w, r, &attrs, h.MaxBytes, h.Strict); err != nil {
			emit(r.Context(), event, err)
			shared.RenderError(w, r, err)
			return
		}
		if fn == nil {
			emit(r.Context(), event, nil)
			w.WriteHeader(http.StatusOK)
			return
		}
		vErrs, err := fn(r.Context(), id, attrs)
		emit(r.Context(), event, err)
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
}

// Location attributes (singular path).
func (h *Handler) listLocationAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string) ([]mdl.BaseAttributeDto, error)
	if h.locationAttrs != nil {
		fn = h.locationAttrs.LocationAttributes
	}
	entityAttrList(h, eventListLocationAttributes, fn)(w, r)
}
func (h *Handler) validateLocationAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string, []mdl.RequestAttribute) ([]string, error)
	if h.locationAttrs != nil {
		fn = h.locationAttrs.ValidateLocationAttributes
	}
	entityAttrValidate(h, eventValidateLocationAttributes, fn)(w, r)
}

// Push certificate attributes.
func (h *Handler) listPushCertificateAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string) ([]mdl.BaseAttributeDto, error)
	if h.pushAttrs != nil {
		fn = h.pushAttrs.PushCertificateAttributes
	}
	entityAttrList(h, eventListPushCertAttributes, fn)(w, r)
}
func (h *Handler) validatePushCertificateAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string, []mdl.RequestAttribute) ([]string, error)
	if h.pushAttrs != nil {
		fn = h.pushAttrs.ValidatePushCertificateAttributes
	}
	entityAttrValidate(h, eventValidatePushCertAttributes, fn)(w, r)
}

// Generate CSR attributes.
func (h *Handler) listGenerateCsrAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string) ([]mdl.BaseAttributeDto, error)
	if h.csrAttrs != nil {
		fn = h.csrAttrs.GenerateCsrAttributes
	}
	entityAttrList(h, eventListGenerateCsrAttributes, fn)(w, r)
}
func (h *Handler) validateGenerateCsrAttributes(w http.ResponseWriter, r *http.Request) {
	var fn func(context.Context, string, []mdl.RequestAttribute) ([]string, error)
	if h.csrAttrs != nil {
		fn = h.csrAttrs.ValidateGenerateCsrAttributes
	}
	entityAttrValidate(h, eventValidateGenerateCsrAttrs, fn)(w, r)
}
