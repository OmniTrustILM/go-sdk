package shared

import (
	"crypto/rand"
	"net/http"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// w3cPropagator extracts inbound W3C Trace Context (traceparent + tracestate)
// headers. Extraction only — per the ILM logging-and-tracing spec neither
// header is propagated back to the client, so the middleware never calls
// Inject on the response.
var w3cPropagator = propagation.TraceContext{}

// withTracing is the built-in tracing middleware. Positioned ahead of the
// logging middleware so the request-scoped logger and every downstream log
// record can derive trace_id / span_id / trace_flags from the span context.
//
// Behavior per the ILM logging-and-tracing spec:
//
//   - Inbound traceparent is honored: the trace ID, trace flags and
//     tracestate are retained and a fresh span ID is generated, making the
//     SDK's span context the server-side child of the caller's span.
//   - With no (or invalid) inbound traceparent a new trace is started:
//     random trace ID + span ID with the sampled flag set.
//   - Neither traceparent nor tracestate is written to the response.
//
// The resulting span context is stored with the standard OpenTelemetry
// context API (trace.ContextWithSpanContext), so user middleware running
// later in the chain (e.g. otelhttp with a real TracerProvider) sees it as
// parent, and any code holding the request context can read it back with
// trace.SpanContextFromContext.
func withTracing() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := w3cPropagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			parent := trace.SpanContextFromContext(ctx)
			cfg := trace.SpanContextConfig{
				SpanID: newSpanID(),
			}
			if parent.IsValid() {
				cfg.TraceID = parent.TraceID()
				cfg.TraceFlags = parent.TraceFlags()
				cfg.TraceState = parent.TraceState()
			} else {
				cfg.TraceID = newTraceID()
				cfg.TraceFlags = trace.FlagsSampled
			}

			ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(cfg))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// newTraceID returns a random non-zero 16-byte W3C trace ID.
func newTraceID() trace.TraceID {
	var id trace.TraceID
	for !id.IsValid() {
		if _, err := rand.Read(id[:]); err != nil {
			// crypto/rand failure is unrecoverable for ID quality; fall back
			// to a fixed marker rather than panicking in the request path.
			copy(id[:], []byte("sdkfallbacktrace"))
			break
		}
	}
	return id
}

// newSpanID returns a random non-zero 8-byte W3C span ID.
func newSpanID() trace.SpanID {
	var id trace.SpanID
	for !id.IsValid() {
		if _, err := rand.Read(id[:]); err != nil {
			copy(id[:], []byte("sdkspans"))
			break
		}
	}
	return id
}
