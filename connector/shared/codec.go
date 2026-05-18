package shared

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// missingRequiredPropertyPrefix is the literal prefix emitted by the
// generated DTOs' UnmarshalJSON when a required property is absent
// ("no value given for required property NAME").
//
// Matching on the string is fragile: a generator update could rename the
// message and silently demote 422 back to 400. The structural alternatives
// (typed error from the generated DTOs, sentinel via errors.Is) are not
// available — openapi-generator emits a raw fmt.Errorf, so we keep the
// prefix match and additionally treat encoding/json's typed errors as 422
// where the shape is unambiguous. Revisit when the generator exposes a
// typed sentinel.
const missingRequiredPropertyPrefix = "no value given for required property "

// DecodeJSON reads at most maxBytes from r.Body and unmarshals into dst.
// strict=true rejects unknown fields. All decode failures are returned as
// *Error (BadRequest) with the underlying decoder error attached as Cause —
// safe to pass straight to WriteProblem.
//
// w is forwarded to http.MaxBytesReader so the underlying TCP connection is
// closed after an oversized-body response. Without it, a client could reuse
// the keep-alive connection to repeatedly stream oversized bodies.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64, strict bool) error {
	if r.Body == nil {
		return BadRequest("INVALID_BODY", "request body required")
	}
	body := http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(body)
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return BadRequest("BODY_TOO_LARGE", "request body exceeds limit").WithCause(err)
		}
		if errors.Is(err, io.EOF) {
			return BadRequest("EMPTY_BODY", "request body required").WithCause(err)
		}
		// Field has the wrong JSON type — structural; safe to map to 422.
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			return Invalid("VALIDATION_FAILED", "request body has invalid field type").
				WithCause(err).
				WithProperty("field", typeErr.Field).
				WithProperty("expected_type", typeErr.Type.String())
		}
		// Required property missing per generated UnmarshalJSON. Prefix
		// match — see missingRequiredPropertyPrefix doc for the caveats.
		if msg := err.Error(); strings.HasPrefix(msg, missingRequiredPropertyPrefix) {
			field := strings.TrimPrefix(msg, missingRequiredPropertyPrefix)
			return Invalid("VALIDATION_FAILED", "required field is missing").
				WithCause(err).
				WithProperty("field", field)
		}
		return BadRequest("INVALID_JSON", "request body is not valid JSON").WithCause(err)
	}
	if dec.More() {
		return BadRequest("INVALID_JSON", "trailing data after JSON value")
	}
	return nil
}

// WriteJSON serializes v as application/json with the given status. A nil v
// yields an empty body (still with the status and content-type). Encoder
// errors are returned to the caller; logging is the caller's responsibility.
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return nil
	}
	return json.NewEncoder(w).Encode(v)
}
