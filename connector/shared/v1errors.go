package shared

import (
	"encoding/json"
	"errors"
	"net/http"
)

// V1 spec error shapes. Hoisted into shared so every v1-family provider
// (discovery, authority v1/v2, compliance v1/v2, etc.) renders identical
// error JSON without each package re-importing its own generated copy.

// V1ErrorMessageDto is the wire shape for v1-spec 400/404/500 responses:
//
//	{ "message": "..." }
//
// Mirrors ErrorMessageDto in every v1 model package; intentionally
// independent so shared does not depend on any one provider's model.
type V1ErrorMessageDto struct {
	Message string `json:"message"`
}

// V1AuthenticationServiceExceptionDto is the wire shape for v1-spec 403
// responses. Mirrors AuthenticationServiceExceptionDto from every v1 model
// package.
type V1AuthenticationServiceExceptionDto struct {
	StatusCode int32  `json:"statusCode"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

// WriteV1Error renders err using the v1-spec error shapes:
//
//	400, 404, 500  -> V1ErrorMessageDto             {"message": "..."}
//	403            -> V1AuthenticationServiceExceptionDto  {statusCode, code, message}
//	422            -> []string                       (single-element array)
//
// Plug into the Connector with shared.WithErrorRenderer(shared.WriteV1Error)
// for v1-family providers. Provider handlers reach this via shared.RenderError,
// which respects the configured renderer.
//
// Non-*Error inputs are wrapped to a 500 internal error first.
func WriteV1Error(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}

	var derr *Error
	if !errors.As(err, &derr) {
		derr = Internal("INTERNAL_ERROR", "internal server error").WithCause(err)
	}

	log := LoggerFromContext(r.Context())
	if derr.Status >= http.StatusInternalServerError {
		log.Error("request failed",
			"status", derr.Status,
			"error_code", derr.ErrorCode,
			"detail", derr.Detail,
			"err", derr.Cause,
		)
	} else {
		log.Info("request rejected",
			"status", derr.Status,
			"error_code", derr.ErrorCode,
			"detail", derr.Detail,
		)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(derr.Status)

	msg := derr.Detail
	if msg == "" {
		msg = derr.Title
	}

	var payload any
	switch derr.Status {
	case http.StatusForbidden:
		payload = V1AuthenticationServiceExceptionDto{
			StatusCode: int32(derr.Status),
			Code:       derr.ErrorCode,
			Message:    msg,
		}
	case http.StatusUnprocessableEntity:
		// 422 from non-validation paths (e.g. failed decode) is rendered as a
		// single-element string array so the wire shape stays consistent.
		payload = []string{msg}
	default:
		payload = V1ErrorMessageDto{Message: msg}
	}

	if encErr := json.NewEncoder(w).Encode(payload); encErr != nil {
		log.Error("write v1 error failed", "err", encErr)
	}
}

// WriteV1ValidationErrors emits a 422 response with a JSON array of
// validation-error messages, matching the v1-spec validateAttributes
// response shape.
func WriteV1ValidationErrors(w http.ResponseWriter, r *http.Request, messages []string) {
	if messages == nil {
		messages = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	if err := json.NewEncoder(w).Encode(messages); err != nil {
		LoggerFromContext(r.Context()).Error("write v1 validation errors failed", "err", err)
	}
}
