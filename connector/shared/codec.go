package shared

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// DecodeJSON reads at most maxBytes from r.Body and unmarshals into dst.
// strict=true rejects unknown fields. All decode failures are returned as
// *Error (BadRequest) with the underlying decoder error attached as Cause —
// safe to pass straight to WriteProblem.
func DecodeJSON(r *http.Request, dst any, maxBytes int64, strict bool) error {
	if r.Body == nil {
		return BadRequest("INVALID_BODY", "request body required")
	}
	body := http.MaxBytesReader(nil, r.Body, maxBytes)
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
