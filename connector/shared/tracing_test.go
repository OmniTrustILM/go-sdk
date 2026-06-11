package shared

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

// runTraced sends one request through withTracing and captures the span
// context observed by the inner handler plus the response.
func runTraced(t *testing.T, mutate func(*http.Request)) (trace.SpanContext, *httptest.ResponseRecorder) {
	t.Helper()
	var got trace.SpanContext
	h := withTracing()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = trace.SpanContextFromContext(r.Context())
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

func TestTracingHonorsInboundTraceparent(t *testing.T) {
	const inboundTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	const inboundSpan = "00f067aa0ba902b7"
	sc, rr := runTraced(t, func(r *http.Request) {
		r.Header.Set("traceparent", "00-"+inboundTrace+"-"+inboundSpan+"-01")
		r.Header.Set("tracestate", "vendor=value")
	})

	if !sc.IsValid() {
		t.Fatal("no span context established")
	}
	if sc.TraceID().String() != inboundTrace {
		t.Errorf("trace id = %s, want inbound %s", sc.TraceID(), inboundTrace)
	}
	if sc.SpanID().String() == inboundSpan {
		t.Error("span id equals inbound parent span id; want a fresh server span id")
	}
	if !sc.TraceFlags().IsSampled() {
		t.Error("sampled flag from inbound traceparent not preserved")
	}
	if got := sc.TraceState().Get("vendor"); got != "value" {
		t.Errorf("tracestate vendor = %q, want value", got)
	}
	// Neither header is propagated back to the client.
	if h := rr.Header().Get("traceparent"); h != "" {
		t.Errorf("traceparent echoed to response: %q", h)
	}
	if h := rr.Header().Get("tracestate"); h != "" {
		t.Errorf("tracestate echoed to response: %q", h)
	}
}

func TestTracingStartsNewTraceWhenAbsent(t *testing.T) {
	sc1, rr := runTraced(t, nil)
	if !sc1.IsValid() {
		t.Fatal("no span context established without inbound headers")
	}
	if !sc1.TraceFlags().IsSampled() {
		t.Error("self-started trace should set the sampled flag")
	}
	if h := rr.Header().Get("traceparent"); h != "" {
		t.Errorf("traceparent echoed to response: %q", h)
	}

	sc2, _ := runTraced(t, nil)
	if sc1.TraceID() == sc2.TraceID() {
		t.Error("two requests share a trace id; ids must be per-request")
	}
}

func TestTracingRejectsMalformedTraceparent(t *testing.T) {
	sc, _ := runTraced(t, func(r *http.Request) {
		r.Header.Set("traceparent", "garbage")
	})
	if !sc.IsValid() {
		t.Fatal("malformed traceparent must still yield a fresh valid span context")
	}
}
