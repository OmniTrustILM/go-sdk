package shared

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ProblemContentType is the IANA media type for RFC 9457 problem responses.
const ProblemContentType = "application/problem+json"

// ProblemDetail mirrors the ProblemDetailExtended schema shared across every
// connector spec. Hoisted into the shared package so all providers serialize
// errors with one type rather than each generated copy.
type ProblemDetail struct {
	Type       string         `json:"type"`
	Title      *string        `json:"title,omitempty"`
	Status     int            `json:"status"`
	Detail     *string        `json:"detail,omitempty"`
	Instance   *string        `json:"instance,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
	ErrorCode  string         `json:"errorCode"`
	Timestamp  time.Time      `json:"timestamp"`
}

// Error is the connector domain error. Carries everything needed to render a
// ProblemDetailExtended response. Provider packages return *Error from their
// handlers; non-*Error values bubble through WriteProblem and are logged at
// error level then mapped to a generic 500.
type Error struct {
	Status     int
	ErrorCode  string
	Title      string
	Detail     string
	TypeURI    string
	Instance   string
	Properties map[string]any
	Cause      error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil shared.Error>"
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.ErrorCode, e.Detail, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.ErrorCode, e.Detail)
}

func (e *Error) Unwrap() error { return e.Cause }

// WithCause returns a copy of e with cause attached. The cause is logged but
// not serialized into the response body.
func (e *Error) WithCause(cause error) *Error {
	ne := *e
	ne.Cause = cause
	return &ne
}

// WithProperty returns a copy of e with the given extension property attached.
// Renders into the "properties" object of the problem JSON.
func (e *Error) WithProperty(key string, value any) *Error {
	ne := *e
	if ne.Properties == nil {
		ne.Properties = map[string]any{key: value}
	} else {
		clone := make(map[string]any, len(ne.Properties)+1)
		for k, v := range ne.Properties {
			clone[k] = v
		}
		clone[key] = value
		ne.Properties = clone
	}
	return &ne
}

// WithInstance overrides the instance URI (default is the request path).
func (e *Error) WithInstance(instance string) *Error {
	ne := *e
	ne.Instance = instance
	return &ne
}

// WithTypeURI overrides the RFC 9457 type URI (default "about:blank").
func (e *Error) WithTypeURI(uri string) *Error {
	ne := *e
	ne.TypeURI = uri
	return &ne
}

func newError(status int, code, msg string, args ...any) *Error {
	detail := msg
	if len(args) > 0 {
		detail = fmt.Sprintf(msg, args...)
	}
	return &Error{
		Status:    status,
		ErrorCode: code,
		Title:     http.StatusText(status),
		Detail:    detail,
		TypeURI:   "about:blank",
	}
}

// HTTP-status constructors. The error code is application-defined and should
// match the ErrorCode enum from the relevant generated model package.
func BadRequest(code, msg string, a ...any) *Error {
	return newError(http.StatusBadRequest, code, msg, a...)
}
func Unauthorized(code, msg string, a ...any) *Error {
	return newError(http.StatusUnauthorized, code, msg, a...)
}
func Forbidden(code, msg string, a ...any) *Error {
	return newError(http.StatusForbidden, code, msg, a...)
}
func NotFound(code, msg string, a ...any) *Error {
	return newError(http.StatusNotFound, code, msg, a...)
}
func Conflict(code, msg string, a ...any) *Error {
	return newError(http.StatusConflict, code, msg, a...)
}
func Invalid(code, msg string, a ...any) *Error {
	return newError(http.StatusUnprocessableEntity, code, msg, a...)
}
func Internal(code, msg string, a ...any) *Error {
	return newError(http.StatusInternalServerError, code, msg, a...)
}
func Unavailable(code, msg string, a ...any) *Error {
	return newError(http.StatusServiceUnavailable, code, msg, a...)
}

// WriteProblem serializes err as application/problem+json. Non-*Error values
// (including those wrapped via fmt.Errorf with %w) are unwrapped via
// errors.As; if no *Error is found, the error is logged and a generic 500
// INTERNAL_ERROR response is written.
func WriteProblem(w http.ResponseWriter, r *http.Request, err error) {
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

	pd := ProblemDetail{
		Type:       derr.TypeURI,
		Status:     derr.Status,
		ErrorCode:  derr.ErrorCode,
		Properties: derr.Properties,
		Timestamp:  time.Now().UTC(),
	}
	if derr.Title != "" {
		t := derr.Title
		pd.Title = &t
	}
	if derr.Detail != "" {
		d := derr.Detail
		pd.Detail = &d
	}
	instance := derr.Instance
	if instance == "" {
		instance = r.URL.Path
	}
	pd.Instance = &instance

	w.Header().Set("Content-Type", ProblemContentType)
	w.WriteHeader(derr.Status)
	if encErr := json.NewEncoder(w).Encode(pd); encErr != nil {
		log.Error("write problem failed", "err", encErr)
	}
}
