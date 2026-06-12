package shared

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// w3cPropagator extracts inbound W3C Trace Context (traceparent + tracestate)
// headers. Extraction only — per the ILM logging-and-tracing spec neither
// header is propagated back to the client, so the middleware never calls
// Inject on the response.
var w3cPropagator = propagation.TraceContext{}

// traceInfo carries the synthesized server-side trace identifiers for one
// request. It lives under a dedicated context key (ctxKeyTrace) consumed
// ONLY by the logging path — deliberately NOT under the OpenTelemetry span
// context slot. Storing a fabricated, never-exported span context in the
// otel slot would mislead real tracers a connector may add via
// WithMiddleware (e.g. otelhttp): exported spans would parent to a span id
// that exists nowhere, the sampled flag would hijack ParentBased sampling
// decisions, and log-to-trace lookups would chase ids absent from the
// backend. With the dedicated key, real tracers see exactly the inbound
// headers (or a clean root) and the log handler prefers their span context
// over these synthesized ids whenever one is present.
type traceInfo struct {
	traceID string
	spanID  string
	flags   string
	state   trace.TraceState
}

// contextWithTraceInfo stores the synthesized trace identifiers for the
// logging path.
func contextWithTraceInfo(ctx context.Context, ti traceInfo) context.Context {
	return context.WithValue(ctx, ctxKeyTrace, ti)
}

// traceFieldsFromContext resolves the trace identifiers to log for ctx.
// A real OpenTelemetry span context (started by user middleware or any otel
// instrumentation) takes precedence — its ids exist in the tracing backend,
// so log↔trace correlation works. The middleware-synthesized ids are the
// fallback that keeps every request traceable when no tracer is installed.
func traceFieldsFromContext(ctx context.Context) (traceID, spanID, flags string, ok bool) {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		return sc.TraceID().String(), sc.SpanID().String(), flagsHex(sc.TraceFlags()), true
	}
	if ti, found := ctx.Value(ctxKeyTrace).(traceInfo); found {
		return ti.traceID, ti.spanID, ti.flags, true
	}
	return "", "", "", false
}

// withTracing is the built-in tracing middleware. Positioned ahead of the
// logging middleware so the request-scoped logger and every downstream log
// record can derive trace_id / span_id / trace_flags for the request.
//
// Behavior per the ILM logging-and-tracing spec:
//
//   - Inbound traceparent is honored: the trace ID, trace flags and
//     tracestate are retained and a fresh span ID is generated, making the
//     logged identifiers the server-side child of the caller's span.
//   - With no (or invalid) inbound traceparent a new trace is started:
//     random trace ID + span ID with the sampled flag set.
//   - Neither traceparent nor tracestate is written to the response.
//
// The synthesized identifiers are intentionally NOT stored as an
// OpenTelemetry span context (see traceInfo) — the otel context slot is
// left untouched, so a real TracerProvider added via WithMiddleware
// extracts the genuine inbound headers itself, makes unpolluted sampling
// decisions, and exports clean trace trees, while record-level log calls
// carrying a real span context automatically log its ids instead of the
// synthesized ones.
func withTracing() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract into a scratch context only to parse the headers; the
			// request context's otel slot must stay untouched.
			scratch := w3cPropagator.Extract(context.Background(), propagation.HeaderCarrier(r.Header))
			parent := trace.SpanContextFromContext(scratch)

			ti := traceInfo{spanID: newSpanID()}
			if parent.IsValid() {
				ti.traceID = parent.TraceID().String()
				ti.flags = flagsHex(parent.TraceFlags())
				ti.state = parent.TraceState()
			} else {
				ti.traceID = newTraceID()
				ti.flags = "01"
			}

			next.ServeHTTP(w, r.WithContext(contextWithTraceInfo(r.Context(), ti)))
		})
	}
}

// newTraceID returns a random non-zero 16-byte W3C trace ID in lowercase hex.
func newTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is unrecoverable for ID quality; fall back to
		// a fixed marker rather than panicking in the request path.
		copy(b[:], []byte("sdkfallbacktrace"))
	}
	return hex.EncodeToString(b[:])
}

// newSpanID returns a random non-zero 8-byte W3C span ID in lowercase hex.
func newSpanID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		copy(b[:], []byte("sdkspans"))
	}
	return hex.EncodeToString(b[:])
}
