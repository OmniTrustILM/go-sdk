package itest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Request describes one HTTP call to the running example. Body, when
// non-nil, is JSON-encoded and sent with Content-Type application/json.
// Headers are applied after that default, so they can override it.
type Request struct {
	Method  string
	Path    string // joined onto BaseURL; leading slash optional
	Body    any
	Headers map[string]string
}

// Response is a fully-read HTTP response: the body is drained and closed, so
// callers can inspect Status, Header, and Body without lifecycle worries.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// JSON unmarshals the response body into dst, failing the test on error.
func (r Response) JSON(t *testing.T, dst any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, dst); err != nil {
		t.Fatalf("itest: response body is not JSON: %v\nbody: %s", err, r.Body)
	}
}

// Do performs req against the harness and returns the drained Response.
// Transport errors fail the test (they are never the behavior under test).
func (h *Harness) Do(t *testing.T, req Request) Response {
	t.Helper()

	var bodyReader io.Reader
	if req.Body != nil {
		raw, err := json.Marshal(req.Body)
		if err != nil {
			t.Fatalf("itest: marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	url := h.BaseURL + "/" + strings.TrimLeft(req.Path, "/")

	httpReq, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("itest: build request %s %s: %v", method, req.Path, err)
	}
	if req.Body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := h.client.Do(httpReq)
	if err != nil {
		t.Fatalf("itest: %s %s: %v", method, req.Path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("itest: read response %s %s: %v", method, req.Path, err)
	}
	return Response{Status: resp.StatusCode, Header: resp.Header, Body: raw}
}

// GetJSON is the common case: issue method+path (with optional JSON body),
// unmarshal the response into dst when non-nil, and return the status code.
//
//	var info map[string]any
//	status := h.GetJSON(t, http.MethodGet, "/v2/info", nil, &info)
func (h *Harness) GetJSON(t *testing.T, method, path string, body, dst any) int {
	t.Helper()
	resp := h.Do(t, Request{Method: method, Path: path, Body: body})
	if dst != nil && len(resp.Body) > 0 {
		resp.JSON(t, dst)
	}
	return resp.Status
}
