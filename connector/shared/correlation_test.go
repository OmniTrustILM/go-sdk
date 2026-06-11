package shared

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// runCorrelated sends one request through withCorrelationID and returns the
// ctx value observed by the inner handler plus the response recorder.
func runCorrelated(t *testing.T, alias string, mutate func(*http.Request)) (string, *httptest.ResponseRecorder) {
	t.Helper()
	var got string
	h := withCorrelationID(alias)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = CorrelationIDFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if mutate != nil {
		mutate(req)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return got, rr
}

func TestCorrelationInboundEchoed(t *testing.T) {
	got, rr := runCorrelated(t, "", func(r *http.Request) {
		r.Header.Set(CorrelationHeader, "client-corr-1")
	})
	if got != "client-corr-1" {
		t.Errorf("ctx correlation id = %q, want client-corr-1", got)
	}
	if rr.Header().Get(CorrelationHeader) != "client-corr-1" {
		t.Errorf("response %s = %q, want echo of inbound", CorrelationHeader, rr.Header().Get(CorrelationHeader))
	}
}

func TestCorrelationGeneratedWhenAbsent(t *testing.T) {
	got, rr := runCorrelated(t, "", nil)
	if got == "" {
		t.Fatal("no correlation id generated")
	}
	if rr.Header().Get(CorrelationHeader) != got {
		t.Errorf("response header %q != ctx value %q", rr.Header().Get(CorrelationHeader), got)
	}
}

func TestCorrelationRejectsOversized(t *testing.T) {
	long := strings.Repeat("a", maxCorrelationIDLength+1)
	got, _ := runCorrelated(t, "", func(r *http.Request) {
		r.Header.Set(CorrelationHeader, long)
	})
	if got == long {
		t.Error("oversized correlation id propagated; must be replaced")
	}
	if got == "" {
		t.Error("no replacement id generated")
	}
}

func TestCorrelationRejectsNonPrintable(t *testing.T) {
	got, _ := runCorrelated(t, "", func(r *http.Request) {
		r.Header.Set(CorrelationHeader, "bad\tvalue")
	})
	if strings.Contains(got, "\t") {
		t.Error("control character propagated into correlation id")
	}
	if got == "" {
		t.Error("no replacement id generated")
	}
}

func TestCorrelationAcceptsMaxLength(t *testing.T) {
	max := strings.Repeat("b", maxCorrelationIDLength)
	got, _ := runCorrelated(t, "", func(r *http.Request) {
		r.Header.Set(CorrelationHeader, max)
	})
	if got != max {
		t.Errorf("exactly-128-char id rejected; got %q", got)
	}
}

func TestCorrelationAliasHeaderFallback(t *testing.T) {
	got, rr := runCorrelated(t, "X-Request-Id", func(r *http.Request) {
		r.Header.Set("X-Request-Id", "legacy-7")
	})
	if got != "legacy-7" {
		t.Errorf("alias header not consulted; got %q", got)
	}
	// Echo always lands on the canonical header.
	if rr.Header().Get(CorrelationHeader) != "legacy-7" {
		t.Errorf("response %s = %q", CorrelationHeader, rr.Header().Get(CorrelationHeader))
	}
}

func TestCorrelationCanonicalWinsOverAlias(t *testing.T) {
	got, _ := runCorrelated(t, "X-Request-Id", func(r *http.Request) {
		r.Header.Set(CorrelationHeader, "canonical")
		r.Header.Set("X-Request-Id", "legacy")
	})
	if got != "canonical" {
		t.Errorf("got %q, want canonical header to win", got)
	}
}
