package shared

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

// runTraced sends one request through withTracing and captures the trace
// info and otel span context observed by the inner handler, plus the
// response.
func runTraced(t *testing.T, mutate func(*http.Request)) (traceInfo, trace.SpanContext, *httptest.ResponseRecorder) {
	t.Helper()
	var ti traceInfo
	var sc trace.SpanContext
	h := withTracing()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ti, _ = r.Context().Value(ctxKeyTrace).(traceInfo)
		sc = trace.SpanContextFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if mutate != nil {
		mutate(req)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return ti, sc, rr
}

func TestTracingHonorsInboundTraceparent(t *testing.T) {
	const inboundTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	const inboundSpan = "00f067aa0ba902b7"
	ti, sc, rr := runTraced(t, func(r *http.Request) {
		r.Header.Set("traceparent", "00-"+inboundTrace+"-"+inboundSpan+"-01")
		r.Header.Set("tracestate", "vendor=value")
	})

	if ti.traceID != inboundTrace {
		t.Errorf("trace id = %s, want inbound %s", ti.traceID, inboundTrace)
	}
	if ti.spanID == inboundSpan || len(ti.spanID) != 16 {
		t.Errorf("span id = %s, want a fresh 16-hex server span id != inbound parent", ti.spanID)
	}
	if ti.flags != "01" {
		t.Errorf("flags = %s, want inbound sampled flag preserved", ti.flags)
	}
	if got := ti.state.Get("vendor"); got != "value" {
		t.Errorf("tracestate vendor = %q, want value", got)
	}
	// The otel span-context slot must stay untouched: a real TracerProvider
	// added via WithMiddleware extracts the genuine headers itself; a
	// synthesized span context here would fabricate phantom parents and
	// hijack ParentBased sampling (PR#22 review).
	if sc.IsValid() {
		t.Errorf("otel span context slot polluted with synthesized context: %v", sc)
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
	ti1, sc, rr := runTraced(t, nil)
	if len(ti1.traceID) != 32 || len(ti1.spanID) != 16 {
		t.Fatalf("no synthesized ids without inbound headers: %+v", ti1)
	}
	if ti1.flags != "01" {
		t.Errorf("self-started trace flags = %s, want 01", ti1.flags)
	}
	if sc.IsValid() {
		t.Error("otel span context slot polluted on self-started trace")
	}
	if h := rr.Header().Get("traceparent"); h != "" {
		t.Errorf("traceparent echoed to response: %q", h)
	}

	ti2, _, _ := runTraced(t, nil)
	if ti1.traceID == ti2.traceID {
		t.Error("two requests share a trace id; ids must be per-request")
	}
}

func TestTracingRejectsMalformedTraceparent(t *testing.T) {
	ti, _, _ := runTraced(t, func(r *http.Request) {
		r.Header.Set("traceparent", "garbage")
	})
	if len(ti.traceID) != 32 || len(ti.spanID) != 16 {
		t.Fatalf("malformed traceparent must still yield fresh ids: %+v", ti)
	}
}

// TestTraceFieldsPreferRealSpanContext pins the precedence contract: when a
// real OpenTelemetry span context is present (user middleware / otelhttp),
// its ids win over the middleware-synthesized ones, so log lines reference
// spans that actually exist in the tracing backend.
func TestTraceFieldsPreferRealSpanContext(t *testing.T) {
	ti := traceInfo{traceID: "11111111111111111111111111111111", spanID: "1111111111111111", flags: "01"}
	realTID, _ := trace.TraceIDFromHex("22222222222222222222222222222222")
	realSID, _ := trace.SpanIDFromHex("2222222222222222")
	real := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: realTID, SpanID: realSID, TraceFlags: trace.FlagsSampled,
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	ctx := req.Context()
	ctx = contextWithTraceInfo(ctx, ti)
	ctx = trace.ContextWithSpanContext(ctx, real)

	tid, sid, flags, ok := traceFieldsFromContext(ctx)
	if !ok || tid != "22222222222222222222222222222222" || sid != "2222222222222222" || flags != "01" {
		t.Errorf("got (%s, %s, %s, %v), want the real span context's ids", tid, sid, flags, ok)
	}

	// Without a real span context the synthesized ids serve as fallback.
	tid, sid, _, ok = traceFieldsFromContext(contextWithTraceInfo(req.Context(), ti))
	if !ok || tid != ti.traceID || sid != ti.spanID {
		t.Errorf("fallback got (%s, %s, %v), want synthesized ids", tid, sid, ok)
	}
}
