package shared

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRoutingErrorsRenderThroughErrorRenderer checks that requests the mux
// cannot route reach the connector's ErrorRenderer, keeping the status code
// and, on 405, the Allow header.
func TestRoutingErrorsRenderThroughErrorRenderer(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantCode   string
		wantAllow  string
	}{
		{name: "unknown path", method: http.MethodGet, path: "/v2/nothing",
			wantStatus: http.StatusNotFound, wantCode: "RESOURCE_NOT_FOUND"},
		{name: "wrong method", method: http.MethodPost, path: "/v2/info",
			wantStatus: http.StatusMethodNotAllowed, wantCode: "BAD_REQUEST", wantAllow: "GET, HEAD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rendered error
			renderer := func(w http.ResponseWriter, r *http.Request, err error) {
				rendered = err
				WriteProblem(w, r, err)
			}
			var buf bytes.Buffer
			c := newTestConnector(t, &buf, WithErrorRenderer(renderer))

			rec := httptest.NewRecorder()
			c.Handler().ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))

			if rendered == nil {
				t.Fatal("configured ErrorRenderer was not called")
			}
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if ct := rec.Header().Get("Content-Type"); ct != ProblemContentType {
				t.Errorf("Content-Type = %q, want %q", ct, ProblemContentType)
			}
			if allow := rec.Header().Get("Allow"); allow != tt.wantAllow {
				t.Errorf("Allow = %q, want %q", allow, tt.wantAllow)
			}
			var pd ProblemDetail
			if err := json.Unmarshal(rec.Body.Bytes(), &pd); err != nil {
				t.Fatalf("body is not a single problem document: %v\n%s", err, rec.Body.String())
			}
			if pd.Status != tt.wantStatus || pd.ErrorCode != tt.wantCode {
				t.Errorf("problem = (%d, %s), want (%d, %s)", pd.Status, pd.ErrorCode, tt.wantStatus, tt.wantCode)
			}
			if pd.Instance == nil || *pd.Instance != tt.path {
				t.Errorf("instance = %v, want %s", pd.Instance, tt.path)
			}
		})
	}
}

// TestRoutingRedirectsPassThrough checks that the mux's path-cleaning
// redirect for an unknown path, which also has no matched pattern, is not
// turned into an error.
func TestRoutingRedirectsPassThrough(t *testing.T) {
	var buf bytes.Buffer
	c := newTestConnector(t, &buf)

	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2//nothing", nil))

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTemporaryRedirect)
	}
	if loc := rec.Header().Get("Location"); loc != "/v2/nothing" {
		t.Errorf("Location = %q, want /v2/nothing", loc)
	}
}

// TestRoutingAsteriskTargetKeepsMuxReply checks that a "*" request target
// still gets the mux's own 400 rather than a redirect or routing error.
func TestRoutingAsteriskTargetKeepsMuxReply(t *testing.T) {
	var buf bytes.Buffer
	c := newTestConnector(t, &buf)

	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "*", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
