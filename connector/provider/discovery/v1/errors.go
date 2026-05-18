package discovery

import (
	"encoding/json"
	"errors"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Sentinel errors returned by Provider / AttributeProvider implementations.
// The Discovery v1 spec does not define ErrorCode enum values; the codes
// here are SDK-internal and surface only in logs.
//
// Wrap with shared.Error.WithCause / WithProperty to attach context:
//
//	return discovery.ErrDiscoveryNotFound.WithCause(err).WithProperty("uuid", id)
var (
	// ErrDiscoveryNotFound -> 404 (ErrorMessageDto with message "discovery not found")
	ErrDiscoveryNotFound = shared.NotFound("DISCOVERY_NOT_FOUND", "discovery not found")

	// ErrInvalidRequest -> 400 (ErrorMessageDto)
	ErrInvalidRequest = shared.BadRequest("INVALID_REQUEST", "invalid request")
)

// WriteError renders err using the Discovery v1 error shapes:
//
//	400, 404, 500   -> ErrorMessageDto  {"message": "..."}
//	403             -> AuthenticationServiceExceptionDto {statusCode, code, message}
//	422             -> []string         (validation errors)
//
// Plug into the Connector with shared.WithErrorRenderer(discovery.WriteError)
// so panic responses also follow the spec. Provider handlers reach this via
// shared.RenderError, which respects the configured renderer.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}

	var derr *shared.Error
	if !errors.As(err, &derr) {
		derr = shared.Internal("INTERNAL_ERROR", "internal server error").WithCause(err)
	}

	log := shared.LoggerFromContext(r.Context())
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

	var payload any
	switch derr.Status {
	case http.StatusForbidden:
		payload = mdl.AuthenticationServiceExceptionDto{
			StatusCode: int32(derr.Status),
			Code:       derr.ErrorCode,
			Message:    detailOrTitle(derr),
		}
	case http.StatusUnprocessableEntity:
		// 422 from non-validation paths (e.g. failed decode) is rendered as a
		// single-element string array so the wire shape stays consistent.
		payload = []string{detailOrTitle(derr)}
	default:
		payload = mdl.ErrorMessageDto{Message: detailOrTitle(derr)}
	}

	if encErr := json.NewEncoder(w).Encode(payload); encErr != nil {
		log.Error("write discovery error failed", "err", encErr)
	}
}

// WriteValidationErrors emits a 422 response with a JSON array of validation
// error messages per the discovery spec.
func WriteValidationErrors(w http.ResponseWriter, r *http.Request, messages []string) {
	if messages == nil {
		messages = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	if err := json.NewEncoder(w).Encode(messages); err != nil {
		shared.LoggerFromContext(r.Context()).Error("write validation errors failed", "err", err)
	}
}

func detailOrTitle(e *shared.Error) string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Title
}
